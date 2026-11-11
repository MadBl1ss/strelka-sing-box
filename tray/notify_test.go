package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func autoSnap(leaf string, ping int) snapshot {
	return snapshot{now: "auto", leaf: leaf, auto: true, ping: ping, pingOK: ping > 0}
}

func title(t *toast) string {
	if t == nil {
		return ""
	}
	return t.title
}

func TestProblemsLevelIsQuietWhileThingsWork(t *testing.T) {
	var n announcer
	now := time.Unix(0, 0)
	for _, tr := range []transition{
		{prev: "", cur: stOff},
		{prev: stOff, cur: stStarting},
		{prev: stStarting, cur: stOK, snap: autoSnap("a-DE", 80)},
		{prev: stOK, cur: stStarting, snap: autoSnap("a-DE", 80)},
		{prev: stOK, cur: stOff, expected: true},
	} {
		if got := n.decide(now, notifyProblems, tr); got != nil {
			t.Errorf("%s -> %s: уведомление %q, а должно быть тихо", tr.prev, tr.cur, got.title)
		}
	}
}

func TestProblemIsReportedOnceAndSoIsItsEnd(t *testing.T) {
	var n announcer
	now := time.Unix(0, 0)

	down := n.decide(now, notifyProblems, transition{prev: stOK, cur: stWarn, snap: autoSnap("a-DE", 0)})
	if title(down) != "Серверы не отвечают" {
		t.Fatalf("падение auto: %q", title(down))
	}
	up := n.decide(now.Add(time.Minute), notifyProblems, transition{prev: stWarn, cur: stOK, snap: autoSnap("b-NL", 90)})
	if title(up) != "VPN снова работает" || !strings.Contains(up.body, "b-NL") || !strings.Contains(up.body, "90") {
		t.Fatalf("восстановление: %+v", up)
	}

	// It falls over again a minute later: that one is not news, and neither
	// is its end, since nobody was told it began.
	again := n.decide(now.Add(2*time.Minute), notifyProblems, transition{prev: stOK, cur: stWarn, snap: autoSnap("b-NL", 0)})
	back := n.decide(now.Add(3*time.Minute), notifyProblems, transition{prev: stWarn, cur: stOK, snap: autoSnap("b-NL", 90)})
	if again != nil || back != nil {
		t.Errorf("повтор в пределах %v: %q и %q, должно быть тихо", problemGap, title(again), title(back))
	}

	later := n.decide(now.Add(problemGap+time.Minute), notifyProblems, transition{prev: stOK, cur: stError})
	if title(later) != "Проблема с VPN" {
		t.Errorf("новая проблема спустя %v: %q", problemGap, title(later))
	}
}

func TestHandPickedServerIsNamed(t *testing.T) {
	var n announcer
	s := snapshot{now: "a-DE", leaf: "a-DE"}
	got := n.decide(time.Unix(0, 0), notifyProblems, transition{prev: stStarting, cur: stWarn, snap: s})
	if title(got) != "Сервер не отвечает" || !strings.Contains(got.body, "a-DE") {
		t.Errorf("выбранный вручную сервер: %+v", got)
	}
}

func TestUnexpectedStopIsAProblemExpectedIsNot(t *testing.T) {
	var n announcer
	now := time.Unix(0, 0)
	if got := n.decide(now, notifyProblems, transition{prev: stOK, cur: stOff}); title(got) != "VPN выключился" {
		t.Errorf("VPN упал сам: %q", title(got))
	}
	n = announcer{}
	if got := n.decide(now, notifyProblems, transition{prev: stOK, cur: stOff, expected: true}); got != nil {
		t.Errorf("остановка по кнопке: %q, должно быть тихо", got.title)
	}
	n = announcer{}
	if got := n.decide(now, notifyAll, transition{prev: stOK, cur: stOff, expected: true}); title(got) != "VPN выключен" {
		t.Errorf("остановка по кнопке, уровень «обо всём»: %q", title(got))
	}
}

// A start the user asked for is answered at any level but "none".
func TestAskedStartIsAnswered(t *testing.T) {
	var n announcer
	tr := transition{prev: stStarting, cur: stOK, snap: autoSnap("a-DE", 70), asked: true}
	if got := n.decide(time.Unix(0, 0), notifyProblems, tr); title(got) != "VPN подключен" {
		t.Errorf("запуск по кнопке: %q", title(got))
	}
	if got := n.decide(time.Unix(0, 0), notifyNone, tr); got != nil {
		t.Errorf("уведомления выключены, а пришло %q", got.title)
	}
}

func TestNoneLevelSaysNothingAndLeavesNoDebt(t *testing.T) {
	var n announcer
	now := time.Unix(0, 0)
	if got := n.decide(now, notifyNone, transition{prev: stOK, cur: stWarn, snap: autoSnap("a-DE", 0)}); got != nil {
		t.Fatalf("уровень «выключены»: %q", got.title)
	}
	// Notifications come back on while the problem is still there, then it
	// ends: there is nothing to report the end of.
	if got := n.decide(now.Add(time.Minute), notifyProblems, transition{prev: stWarn, cur: stOK, snap: autoSnap("a-DE", 80)}); got != nil {
		t.Errorf("конец проблемы, о которой не сообщали: %q", got.title)
	}
}

func TestAllLevelReportsConnecting(t *testing.T) {
	var n announcer
	now := time.Unix(0, 0)
	if got := n.decide(now, notifyAll, transition{prev: "", cur: stOK, snap: autoSnap("a-DE", 70)}); got != nil {
		t.Errorf("трей только запустился, VPN уже работал: %q", got.title)
	}
	if got := n.decide(now, notifyAll, transition{prev: stStarting, cur: stOK, snap: autoSnap("a-DE", 70)}); title(got) != "VPN подключен" {
		t.Errorf("подключение: %q", title(got))
	}
}

func TestSettingsRoundTripAndDefault(t *testing.T) {
	dir := t.TempDir()
	if got := loadSettings(dir).Notify; got != notifyProblems {
		t.Errorf("без файла: %q, жду %q", got, notifyProblems)
	}
	if err := saveSettings(dir, settings{Notify: notifyNone}); err != nil {
		t.Fatal(err)
	}
	if got := loadSettings(dir).Notify; got != notifyNone {
		t.Errorf("после сохранения: %q", got)
	}
	if err := os.WriteFile(settingsPath(dir), []byte(`{"notify":"loud"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadSettings(dir).Notify; got != notifyProblems {
		t.Errorf("мусор в файле: %q, жду %q", got, notifyProblems)
	}
}
