package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/gjson"
)

func answered(ms int, at time.Time) proxyInfo { return proxyInfo{Type: "VLESS", Delay: ms, Tested: at} }

var silent = proxyInfo{Type: "VLESS"}

func TestOrderPoolPutsFastAndSteadyFirst(t *testing.T) {
	st := &serverStats{Servers: map[string]*serverStat{
		"a-AT": {Avg: 400, N: 9},
		"a-DE": {Avg: 70, N: 9},
		"a-FI": {Avg: 60, Miss: 0.5, N: 9}, // quickest when it answers, which is half the time
		"a-NL": {Avg: 90, N: 9},
		"a-SE": {Miss: 1}, // never answered: no rating at all
	}}
	pool := []string{"a-AT", "a-DE", "a-FI", "a-NEW", "a-NL", "a-SE"}
	got := orderPool(pool, st)
	want := []string{"a-DE", "a-NL", "a-FI", "a-AT", "a-NEW", "a-SE"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("порядок auto:\n есть %v\n жду  %v", got, want)
	}
	if pool[0] != "a-AT" {
		t.Error("orderPool испортил исходный список")
	}
	if got := orderPool(pool, &serverStats{}); !reflect.DeepEqual(got, pool) {
		t.Errorf("без статистики порядок должен остаться прежним: %v", got)
	}
}

func TestStatsFollowTheCoreChecks(t *testing.T) {
	st := &serverStats{Servers: map[string]*serverStat{}}
	pool := []string{"a-DE", "a-NL"}
	t0 := time.Unix(1_000_000, 0)

	// Both answered half a minute ago.
	px := map[string]proxyInfo{"a-DE": answered(100, t0), "a-NL": answered(200, t0)}
	if !st.observe(t0.Add(30*time.Second), pool, px, "") {
		t.Fatal("первые результаты не учтены")
	}
	// Looking again at the same results adds nothing.
	if st.observe(t0.Add(33*time.Second), pool, px, "") {
		t.Error("тот же результат посчитан дважды")
	}
	if s := st.Servers["a-DE"]; s.N != 1 || s.Avg != 100 {
		t.Errorf("a-DE после одного ответа: %+v", s)
	}

	// Next round: DE got slower, NL fell silent.
	t1 := t0.Add(time.Minute)
	px = map[string]proxyInfo{"a-DE": answered(200, t1), "a-NL": silent}
	st.observe(t1.Add(30*time.Second), pool, px, "")
	if s := st.Servers["a-DE"]; s.N != 2 || s.Avg <= 100 || s.Avg >= 200 {
		t.Errorf("a-DE после 100 и 200 мс: среднее %.0f, жду между ними", s.Avg)
	}
	nl := st.Servers["a-NL"]
	if nl.Miss <= 0 {
		t.Fatalf("a-NL промолчал, а промах не записан: %+v", nl)
	}
	// However often the tray looks, a round is one miss.
	miss := nl.Miss
	st.observe(t1.Add(33*time.Second), pool, px, "")
	if nl.Miss != miss {
		t.Errorf("один и тот же промах посчитан дважды: %.2f -> %.2f", miss, nl.Miss)
	}

	rDE, _ := st.rating("a-DE")
	rNL, _ := st.rating("a-NL")
	if rNL <= 200 {
		t.Errorf("оценка a-NL %.0f: промах должен был её ухудшить", rNL)
	}
	_ = rDE
}

// With nobody in the pool answering there is no telling a dead server from a
// dead network, or from checks that are simply paused.
func TestNoMissesWithoutEvidenceOfChecks(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	pool := []string{"a-DE", "a-NL"}
	cases := map[string]struct {
		px     map[string]proxyInfo
		probed string
	}{
		"вся сеть лежит":            {map[string]proxyInfo{"a-DE": silent, "a-NL": silent}, ""},
		"проверки на паузе":         {map[string]proxyInfo{"a-DE": answered(80, now.Add(-time.Hour)), "a-NL": silent}, ""},
		"круг проверок ещё идёт":    {map[string]proxyInfo{"a-DE": answered(80, now.Add(-2*time.Second)), "a-NL": silent}, ""},
		"отвечает только свой пинг": {map[string]proxyInfo{"a-DE": answered(80, now.Add(-30*time.Second)), "a-NL": silent}, "a-DE"},
	}
	for name, c := range cases {
		st := &serverStats{Servers: map[string]*serverStat{}}
		st.observe(now, pool, c.px, c.probed)
		if s := st.Servers["a-NL"]; s != nil && s.Miss > 0 {
			t.Errorf("%s: a-NL записан промах %.2f", name, s.Miss)
		}
	}
}

func TestStatsSaveLoadAndForget(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_000_000, 0)
	st := loadStats(dir) // no file yet
	st.Servers["a-DE"] = &serverStat{Avg: 70, N: 3, Seen: now}
	st.Servers["a-OLD"] = &serverStat{Avg: 70, N: 3, Seen: now.Add(-2 * statsKeep)}
	if err := st.save(dir, now); err != nil {
		t.Fatal(err)
	}
	got := loadStats(dir)
	if s := got.Servers["a-DE"]; s == nil || s.Avg != 70 || s.N != 3 {
		t.Errorf("a-DE после записи и чтения: %+v", s)
	}
	if _, ok := got.Servers["a-OLD"]; ok {
		t.Error("сервер, которого нет уже два месяца, не забыт")
	}
}

// The whole point, end to end: a refresh builds "auto" as a group that stays
// put, ordered by what the servers showed before.
func TestRefreshBuildsStickyAutoInRatedOrder(t *testing.T) {
	// A refresh has the core vet the new config. A stand-in that approves
	// everything is a shell script, which Windows cannot run as an .exe; there
	// TestUpdateSubscriptionPreservesEverythingElse covers the real thing.
	if runtime.GOOS == "windows" {
		t.Skip("нужен подставной sing-box, а это shell-скрипт")
	}
	links := []string{
		"vless://id@at.example.com:443?security=tls#Austria",
		"vless://id@de.example.com:443?security=tls#Germany",
		"vless://id@nl.example.com:443?security=tls#Netherlands",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Join(links, "\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["direct"], "default": "direct"},
    {"type": "direct", "tag": "direct"}
  ],
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:7890", "secret": ""}}
}`)
	write("subscription.txt", "x "+srv.URL+"\n")
	if err := os.WriteFile(coreExe(dir), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	refresh := func() gjson.Result {
		t.Helper()
		if err := updateSubscriptionFile(dir, t.Logf); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		return gjson.GetBytes(raw, `outbounds.#(type=="urltest")`)
	}
	members := func(g gjson.Result) []string {
		var out []string
		for _, m := range g.Get("outbounds").Array() {
			out = append(out, m.String())
		}
		return out
	}

	auto := refresh()
	first := members(auto)
	if len(first) != 3 {
		t.Fatalf("в auto %v, жду три сервера", first)
	}
	if got := auto.Get("tolerance").Int(); got != autoTolerance {
		t.Errorf("tolerance %d, жду %d", got, autoTolerance)
	}
	if got := auto.Get("interval").String(); got != autoInterval {
		t.Errorf("interval %q, жду %q", got, autoInterval)
	}
	// Sticky means no measurement can beat the current server: a check runs
	// for 15 s at most, so no delay is ever larger than that.
	if autoTolerance <= 15000 {
		t.Errorf("tolerance %d: сервер быстрее на эту величину вытеснит текущий", autoTolerance)
	}
	// uint16 in sing-box, and it is added to a delay of up to 32767 ms.
	if autoTolerance+32767 > 65535 {
		t.Errorf("tolerance %d переполнит uint16 при сложении с задержкой", autoTolerance)
	}

	// The last in line turns out to be the fastest; the first, the flakiest.
	st := loadStats(dir)
	st.Servers[first[2]] = &serverStat{Avg: 50, N: 10, Seen: time.Now()}
	st.Servers[first[1]] = &serverStat{Avg: 120, N: 10, Seen: time.Now()}
	st.Servers[first[0]] = &serverStat{Avg: 60, Miss: 0.9, N: 10, Seen: time.Now()}
	if err := st.save(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	want := []string{first[2], first[1], first[0]}
	if got := members(refresh()); !reflect.DeepEqual(got, want) {
		t.Errorf("порядок auto после замеров:\n есть %v\n жду  %v", got, want)
	}

	// The by-hand list keeps its alphabetical order: only "auto" is ranked.
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var manual []string
	for _, m := range gjson.GetBytes(raw, `outbounds.#(type=="selector").outbounds`).Array() {
		manual = append(manual, m.String())
	}
	if want := append([]string{autoTag}, first...); !reflect.DeepEqual(manual, want) {
		t.Errorf("список для ручного выбора:\n есть %v\n жду  %v", manual, want)
	}
}
