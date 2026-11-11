package main

import (
	"testing"
	"time"
)

// feed runs polls through health three seconds apart, the way the tray does,
// and returns the settled state after each.
func feed(h *health, at *time.Time, polls ...snapshot) []string {
	var out []string
	for _, s := range polls {
		out = append(out, h.observe(*at, s, false))
		*at = at.Add(pollEvery)
	}
	return out
}

func manual(raw string, probed bool) snapshot {
	return snapshot{raw: raw, leaf: "a-DE", now: "a-DE", probed: probed, pingOK: raw == rawOK}
}

func auto(raw, leaf string) snapshot {
	return snapshot{raw: raw, leaf: leaf, now: "auto", auto: true, pingOK: raw == rawOK}
}

func last(states []string) string { return states[len(states)-1] }

// The complaint that started this: one missed ping turned the shield yellow
// and the next good one turned it back, with a notification each way.
func TestOneMissedProbeChangesNothing(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, manual(rawOK, true))
	for i := 0; i < 20; i++ {
		got := feed(h, &at, manual(rawBad, true), manual(rawOK, true))
		if got[0] != stOK || got[1] != stOK {
			t.Fatalf("круг %d: один промах дал %v, щит должен оставаться зелёным", i, got)
		}
	}
}

func TestThreeMissedProbesInARowAreAnOutage(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, manual(rawOK, true))
	got := feed(h, &at,
		manual(rawBad, true),
		manual(rawBad, false), // a poll between probes repeats the old answer
		manual(rawBad, true),
		manual(rawBad, false),
		manual(rawBad, true), // the third miss, 12 s in: not long enough yet
		manual(rawBad, false),
	)
	want := []string{stOK, stOK, stOK, stOK, stOK, stWarn}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("после %d опросов: %q, жду %q (все: %v)", i+1, got[i], want[i], got)
		}
	}
	if got := feed(h, &at, manual(rawOK, true)); got[0] != stOK {
		t.Errorf("первый же ответ должен вернуть зелёный, а там %q", got[0])
	}
}

// Waking from sleep: the network is not back yet and every probe is refused
// at once. Whatever was counted before the lid closed must not add up.
func TestSleepStartsTheCountOver(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, manual(rawOK, true), manual(rawBad, true), manual(rawBad, true))
	at = at.Add(8 * time.Hour)
	got := feed(h, &at, manual(rawBad, true), manual(rawBad, true), manual(rawOK, true))
	for i, st := range got {
		if st != stOK {
			t.Errorf("опрос %d после сна: %q, сеть ещё только поднималась", i+1, st)
		}
	}
}

// "auto" is not probed by the tray; it counts as down only after the core
// has had time to move to another server and did not.
func TestAutoWaitsForTheCoreToMoveOn(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, auto(rawOK, "a-DE"))

	var polls []snapshot
	for i := 0; i < int(holdBad/pollEvery); i++ {
		polls = append(polls, auto(rawBad, "a-DE"))
	}
	for i, st := range feed(h, &at, polls...) {
		if st != stOK {
			t.Fatalf("опрос %d: %q раньше, чем прошло %v", i+1, st, holdBad)
		}
	}
	if got := feed(h, &at, auto(rawBad, "a-DE")); got[0] != stWarn {
		t.Errorf("через %v без ответа должно быть %q, а там %q", holdBad, stWarn, got[0])
	}
}

func TestAutoMovingToAnotherServerStaysGreen(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	got := feed(h, &at,
		auto(rawOK, "a-DE"),
		auto(rawBad, "a-DE"),
		auto(rawBad, "a-DE"),
		auto(rawOK, "b-NL"), // the core moved on
	)
	for i, st := range got {
		if st != stOK {
			t.Errorf("опрос %d: %q, а VPN всё это время работал", i+1, st)
		}
	}
}

// A hand-picked server must not inherit the green shield of the previous
// one: until its first probe nothing is known about it.
func TestSwitchingByHandStartsOver(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, manual(rawOK, true))

	dead := snapshot{raw: rawBad, leaf: "b-NL", now: "b-NL", probed: true}
	got := feed(h, &at, dead, dead, dead, dead, dead, dead)
	want := []string{stStarting, stStarting, stStarting, stStarting, stStarting, stWarn}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("опрос %d: %q, жду %q", i+1, got[i], want[i])
		}
	}

	h, at = &health{}, time.Unix(0, 0)
	feed(h, &at, manual(rawOK, true))
	live := snapshot{raw: rawOK, leaf: "b-NL", now: "b-NL", probed: true, pingOK: true}
	if got := feed(h, &at, live); got[0] != stOK {
		t.Errorf("живой сервер после переключения: %q, жду %q", got[0], stOK)
	}
}

// A restart seen from outside: the process vanishes, comes back mute, then
// answers. Nobody asked for it, so none of that may reach the user as "off".
func TestBriefRestartIsRiddenOut(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	got := feed(h, &at,
		auto(rawOK, "a-DE"),
		snapshot{raw: rawOff},
		snapshot{raw: rawError},
		snapshot{raw: rawError},
		auto(rawBad, "a-DE"),
		auto(rawOK, "a-DE"),
	)
	for i, st := range got {
		if st != stOK {
			t.Errorf("опрос %d: %q, перезапуск за пару секунд не должен быть виден", i+1, st)
		}
	}
}

func TestGoneForGoodIsOff(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	got := feed(h, &at, auto(rawOK, "a-DE"), snapshot{raw: rawOff}, snapshot{raw: rawOff}, snapshot{raw: rawOff})
	if got[1] != stOK {
		t.Errorf("первый опрос без процесса: %q, рано", got[1])
	}
	if last(got) != stOff {
		t.Errorf("процесса нет уже %v: %q, жду %q", 2*pollEvery, last(got), stOff)
	}
}

func TestMuteCoreIsAnError(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, auto(rawOK, "a-DE"))
	var polls []snapshot
	for i := 0; i < int(holdError/pollEvery)+2; i++ {
		polls = append(polls, snapshot{raw: rawError})
	}
	got := feed(h, &at, polls...)
	if got[0] != stOK || last(got) != stError {
		t.Errorf("молчащий API: сначала %q, в конце %q; жду %q и %q", got[0], last(got), stOK, stError)
	}
}

// Starting the tray, or the VPN, goes off -> starting -> ok and never shows
// the red or yellow "problem" states on the way.
func TestStartupPassesThroughStarting(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	got := feed(h, &at,
		snapshot{raw: rawOff},
		snapshot{raw: rawError},
		auto(rawBad, "a-DE"),
		auto(rawOK, "a-DE"),
	)
	want := []string{stOff, stStarting, stStarting, stOK}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("опрос %d: %q, жду %q (все: %v)", i+1, got[i], want[i], got)
		}
	}
}

// When the user clicked "restart", waiting things out would leave the shield
// green over a VPN that is being torn down.
func TestExpectedStopShowsAtOnce(t *testing.T) {
	h, at := &health{}, time.Unix(0, 0)
	feed(h, &at, auto(rawOK, "a-DE"))
	if st := h.observe(at, snapshot{raw: rawOff}, true); st != stOff {
		t.Errorf("ожидаемая остановка: %q, жду %q сразу", st, stOff)
	}
	at = at.Add(pollEvery)
	if st := h.observe(at, snapshot{raw: rawError}, true); st != stStarting {
		t.Errorf("ядро поднимается: %q, жду %q", st, stStarting)
	}
	at = at.Add(pollEvery)
	if st := h.observe(at, auto(rawOK, "a-DE"), true); st != stOK {
		t.Errorf("ядро ответило: %q, жду %q", st, stOK)
	}
}

func TestIconForEveryState(t *testing.T) {
	for _, st := range []string{"", stOff, stError, stOK, stWarn, stStarting} {
		if _, ok := icons[iconFor(st)]; !ok {
			t.Errorf("для состояния %q нет иконки (%q)", st, iconFor(st))
		}
	}
}
