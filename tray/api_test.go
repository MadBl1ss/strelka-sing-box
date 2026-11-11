package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// What sing-box 1.14 answers on GET /proxies, trimmed: a selector on "auto",
// "auto" on a-DE, one server with a result, one without.
const proxiesReply = `{"proxies":{
  "GLOBAL":{"type":"Fallback","name":"GLOBAL","udp":true,"history":[],"all":["proxy","auto","a-DE","a-NL"],"now":"proxy"},
  "proxy":{"type":"Selector","name":"proxy","udp":true,"history":[{"time":"2026-11-11T10:00:00.5+03:00","delay":84}],"now":"auto","all":["auto","a-DE","a-NL"]},
  "auto":{"type":"URLTest","name":"auto","udp":true,"history":[{"time":"2026-11-11T10:00:00.5+03:00","delay":84}],"now":"a-DE","all":["a-DE","a-NL"]},
  "a-DE":{"type":"VLESS","name":"a-DE","udp":true,"history":[{"time":"2026-11-11T10:00:00.5+03:00","delay":84}]},
  "a-NL":{"type":"VLESS","name":"a-NL","udp":true,"history":[]},
  "direct":{"type":"Direct","name":"direct","udp":true,"history":[]}
}}`

func apiStub(t *testing.T, h http.HandlerFunc) *client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return newClient(&cfg{controller: strings.TrimPrefix(srv.URL, "http://"), secret: "s3cret"})
}

func TestProxiesReadsSelectionAndResults(t *testing.T) {
	cl := apiStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxies" || r.Header.Get("Authorization") != "Bearer s3cret" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, proxiesReply)
	})
	px, err := cl.proxies()
	if err != nil {
		t.Fatal(err)
	}
	if px["proxy"].Now != "auto" || !px["auto"].group() || px["a-DE"].group() {
		t.Errorf("группы разобраны неверно: proxy=%+v auto=%+v", px["proxy"], px["auto"])
	}
	if leaf := leafOf(px, px["proxy"].Now); leaf != "a-DE" {
		t.Errorf("сервер под auto: %q, жду a-DE", leaf)
	}
	if leafOf(px, "a-NL") != "a-NL" || leafOf(px, "нет такого") != "нет такого" {
		t.Error("обычный сервер должен быть сам себе листом")
	}
	de := px["a-DE"]
	if !de.alive() || de.Delay != 84 || de.Tested.IsZero() {
		t.Errorf("a-DE: %+v, жду ответ 84 мс", de)
	}
	if px["a-NL"].alive() {
		t.Errorf("a-NL без истории считается живым: %+v", px["a-NL"])
	}
}

// The probe must give a server longer than the 3 s that used to fail it, and
// stay inside what sing-box parses: the per-proxy timeout is an int16.
func TestProbeAndGroupTestRequests(t *testing.T) {
	var seen []string
	cl := apiStub(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"?timeout="+r.URL.Query().Get("timeout"))
		fmt.Fprint(w, `{"delay":120}`)
	})
	ms, err := cl.delay("a-DE")
	if err != nil || ms != 120 {
		t.Fatalf("delay: %d, %v", ms, err)
	}
	if err := cl.testGroup("proxy", checkTimeout); err != nil {
		t.Fatalf("testGroup: %v", err)
	}
	want := []string{"/proxies/a-DE/delay?timeout=5000", "/group/proxy/delay?timeout=10000"}
	if len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Errorf("запросы:\n есть %v\n жду  %v", seen, want)
	}
	if probeTimeout <= 3*time.Second || probeTimeout.Milliseconds() > 32767 {
		t.Errorf("probeTimeout %v: нужен больше 3 с и в пределах int16 мс", probeTimeout)
	}
}

func TestCheckSummary(t *testing.T) {
	start := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	servers := []server{{Tag: "auto"}, {Tag: "a-DE"}, {Tag: "a-NL"}, {Tag: "a-PL"}, {Tag: "a-SE"}}
	px := map[string]proxyInfo{
		"auto": {Type: "URLTest", Now: "a-DE", All: []string{"a-DE", "a-NL"}, Delay: 90, Tested: start.Add(time.Second)},
		"a-DE": {Delay: 90, Tested: start.Add(time.Second)},
		"a-NL": {Delay: 64, Tested: start.Add(2 * time.Second)},
		"a-PL": {},                                         // failed: the core dropped its result
		"a-SE": {Delay: 30, Tested: start.Add(-time.Hour)}, // not reached in time, old result
	}
	got := checkSummary(px, servers, start)
	if got != "Отвечают 2 из 4. Самый быстрый: a-NL — 64 мс." {
		t.Errorf("итог проверки: %q", got)
	}
	dead := map[string]proxyInfo{"a-DE": {}, "a-NL": {}}
	if got := checkSummary(dead, servers[1:3], start); !strings.Contains(got, "ни один из 2") {
		t.Errorf("никто не ответил: %q", got)
	}
}

func TestPingSuffix(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	checked := now.Add(-time.Minute)
	cases := []struct {
		name    string
		p       proxyInfo
		checked time.Time
		want    string
	}{
		{"свежий ответ", proxyInfo{Delay: 84, Tested: now.Add(-time.Minute)}, time.Time{}, "   84 мс"},
		{"ответ часовой давности", proxyInfo{Delay: 84, Tested: now.Add(-time.Hour)}, time.Time{}, ""},
		{"не проверялся", proxyInfo{}, time.Time{}, ""},
		{"не ответил на проверку", proxyInfo{}, checked, "   нет ответа"},
		{"группа", proxyInfo{All: []string{"a"}, Delay: 84, Tested: now}, checked, ""},
	}
	for _, c := range cases {
		if got := pingSuffix(now, c.p, c.checked); got != c.want {
			t.Errorf("%s: %q, жду %q", c.name, got, c.want)
		}
	}
}

func TestStatusLineByState(t *testing.T) {
	s := snapshot{now: "auto", leaf: "a-DE", auto: true, ping: 84, pingOK: true}
	for state, want := range map[string]string{
		stOK:       "Подключено — auto → a-DE — 84 мс",
		stStarting: "Проверяю auto → a-DE…",
		stWarn:     "Серверы не отвечают",
		stError:    "sing-box не отвечает",
		stOff:      "VPN выключен",
	} {
		s.state = state
		if got := statusLine(s); got != want {
			t.Errorf("%s: %q, жду %q", state, got, want)
		}
	}
	// Green held over a server whose last answer is gone: no stale number.
	s.state, s.pingOK = stOK, false
	if got := statusLine(s); got != "Подключено — auto → a-DE" {
		t.Errorf("без пинга: %q", got)
	}
	if got := statusLine(snapshot{state: stWarn, now: "a-DE", leaf: "a-DE"}); got != "a-DE не отвечает" {
		t.Errorf("ручной сервер: %q", got)
	}
}
