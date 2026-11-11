package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCore is a Clash API that answers from a table and remembers what it
// was asked, so a test can tell reading from testing.
type fakeCore struct {
	mu      sync.Mutex
	now     string          // what the selector points at
	leaf    string          // what "auto" points at
	delays  map[string]int  // servers with a result on record
	probe   map[string]bool // answer of /proxies/<tag>/delay
	asked   []string        // every test request, in order
	testedC chan string
}

func (f *fakeCore) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hist := func(tag string) string {
		if ms, ok := f.delays[tag]; ok {
			return fmt.Sprintf(`[{"time":%q,"delay":%d}]`, time.Now().Format(time.RFC3339Nano), ms)
		}
		return "[]"
	}
	switch {
	case r.URL.Path == "/proxies":
		fmt.Fprintf(w, `{"proxies":{
			"proxy":{"type":"Selector","now":%q,"all":["auto","a-DE","a-NL"],"history":[]},
			"auto":{"type":"URLTest","now":%q,"all":["a-DE","a-NL"],"history":%s},
			"a-DE":{"type":"VLESS","history":%s},
			"a-NL":{"type":"VLESS","history":%s}}}`,
			f.now, f.leaf, hist(f.leaf), hist("a-DE"), hist("a-NL"))
	case r.URL.Path == "/configs":
		fmt.Fprint(w, `{"mode":"Rule","mode-list":["Rule","Global"]}`)
	case r.URL.Path == "/connections":
		fmt.Fprint(w, `{"downloadTotal":1,"uploadTotal":1,"connections":[]}`)
	case strings.HasSuffix(r.URL.Path, "/delay"):
		f.asked = append(f.asked, r.URL.Path)
		if f.testedC != nil {
			f.testedC <- r.URL.Path
		}
		tag := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
		if strings.HasPrefix(r.URL.Path, "/proxies/") && !f.probe[tag] {
			http.Error(w, `{"message":"timeout"}`, http.StatusGatewayTimeout)
			return
		}
		fmt.Fprint(w, `{"delay":77}`)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCore) tests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

func pollApp(t *testing.T, f *fakeCore) *app {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	conf := &cfg{controller: strings.TrimPrefix(srv.URL, "http://"), selector: "proxy"}
	return &app{
		conf:   conf,
		cl:     newClient(conf),
		coreUp: func() (time.Time, bool) { return time.Now(), true },
	}
}

// The root of the flapping: a probe through the API is not a harmless look.
// When it fails, sing-box drops the server and "auto" jumps. So under "auto"
// the tray must only read.
func TestAutoIsReadNotProbed(t *testing.T) {
	f := &fakeCore{now: "auto", leaf: "a-DE", delays: map[string]int{"a-DE": 84, "a-NL": 120}}
	a := pollApp(t, f)
	for i := 0; i < 5; i++ {
		s := a.poll()
		a.snap = s
		if s.raw != rawOK || !s.auto || s.leaf != "a-DE" || s.ping != 84 {
			t.Fatalf("опрос %d: %+v", i, s)
		}
	}
	if got := f.tests(); len(got) != 0 {
		t.Errorf("под auto трей не должен ничего тестировать, а запросил %v", got)
	}
}

// When the server "auto" holds has no result, the tray gives it a moment and
// then asks the core to re-check the whole group - once, not on every poll.
func TestAutoWithoutAnswerAsksForOneRecheck(t *testing.T) {
	f := &fakeCore{now: "auto", leaf: "a-DE", delays: map[string]int{"a-NL": 120}, testedC: make(chan string, 8)}
	a := pollApp(t, f)

	if s := a.poll(); s.raw != rawBad {
		t.Fatalf("сервер без ответа: raw=%q, жду %q", s.raw, rawBad)
	}
	if got := f.tests(); len(got) != 0 {
		t.Fatalf("перепроверка запрошена сразу, без паузы: %v", got)
	}

	a.noAnswerSince = time.Now().Add(-recheckAfter - time.Second)
	a.poll()
	select {
	case path := <-f.testedC:
		if path != "/group/auto/delay" {
			t.Errorf("перепроверка пошла в %q, жду всю группу auto", path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("перепроверка не запрошена")
	}
	for a.rechecking.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	a.poll()
	a.poll()
	if got := f.tests(); len(got) != 1 {
		t.Errorf("перепроверок %d (%v), жду одну на %v", len(got), got, recheckEvery)
	}

	// The core moved to a live server: all is well and the clock is reset.
	f.mu.Lock()
	f.leaf = "a-NL"
	f.mu.Unlock()
	if s := a.poll(); s.raw != rawOK || s.leaf != "a-NL" || !a.noAnswerSince.IsZero() {
		t.Errorf("после перехода на a-NL: %+v, noAnswerSince=%v", s, a.noAnswerSince)
	}
}

// A server picked by hand is nobody's to check but the tray's, and not on
// every three-second poll.
func TestHandPickedServerIsProbedAtItsOwnPace(t *testing.T) {
	f := &fakeCore{now: "a-NL", leaf: "a-DE", probe: map[string]bool{"a-NL": true}}
	a := pollApp(t, f)

	s := a.poll()
	a.snap = s
	if s.raw != rawOK || s.auto || !s.probed || s.ping != 77 {
		t.Fatalf("первый опрос: %+v", s)
	}
	s = a.poll()
	a.snap = s
	if s.raw != rawOK || s.probed {
		t.Errorf("второй опрос через мгновение: %+v, пинга быть не должно", s)
	}
	if got := f.tests(); len(got) != 1 || got[0] != "/proxies/a-NL/delay" {
		t.Errorf("запросы: %v, жду один пинг a-NL", got)
	}

	// After a miss the next probe comes sooner than the usual pace.
	f.mu.Lock()
	f.probe["a-NL"] = false
	f.mu.Unlock()
	a.lastPing = time.Now().Add(-pingEvery)
	s = a.poll()
	a.snap = s
	a.health.observe(time.Now(), s, false)
	if s.raw != rawBad || !s.probed {
		t.Fatalf("промах: %+v", s)
	}
	a.lastPing = time.Now().Add(-retryEvery)
	if s = a.poll(); !s.probed {
		t.Errorf("после промаха повтор должен идти через %v, а не через %v", retryEvery, pingEvery)
	}
}

func TestPollSeesCoreGoneOrMute(t *testing.T) {
	f := &fakeCore{now: "auto", leaf: "a-DE", delays: map[string]int{"a-DE": 84}}
	a := pollApp(t, f)

	a.coreUp = func() (time.Time, bool) { return time.Time{}, false }
	if s := a.poll(); s.raw != rawOff {
		t.Errorf("процесса нет: raw=%q", s.raw)
	}
	a.coreUp = func() (time.Time, bool) { return time.Now(), true }
	a.cl = newClient(&cfg{controller: "127.0.0.1:1"}) // nothing listens there
	if s := a.poll(); s.raw != rawError {
		t.Errorf("API молчит: raw=%q", s.raw)
	}
}
