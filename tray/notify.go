package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Status notifications come in three levels. Answers to something the user
// just clicked ("подписка обновлена", "не переключилось") are not status and
// are always shown.
const (
	notifyAll      = "all"      // every change of state
	notifyProblems = "problems" // only a confirmed problem and its end
	notifyNone     = "none"
)

// problemGap keeps a connection that keeps falling over from reporting each
// fall: after one problem notice the next is at least this far away.
const problemGap = 5 * time.Minute

type toast struct{ title, body string }

// announcer decides which changes of state deserve a notification.
type announcer struct {
	alerted     bool      // a problem was reported and has not ended yet
	lastProblem time.Time // when that report went out
}

// transition is one change of the settled state, with what is known around it.
type transition struct {
	prev, cur string
	snap      snapshot
	expected  bool // the user asked for this stop or restart
	asked     bool // the user asked for a start and is waiting to hear back
}

func (n *announcer) decide(now time.Time, level string, t transition) *toast {
	if t.prev == t.cur || level == notifyNone {
		// Still track the episode, so switching notifications back on does
		// not report the end of a problem nobody was told about.
		if t.cur == stOK || t.cur == stOff {
			n.alerted = false
		}
		return nil
	}
	s := t.snap
	switch t.cur {
	case stOK:
		was := n.alerted
		n.alerted = false
		line := serverName(s)
		if s.pingOK {
			line = fmt.Sprintf("Сервер %s, пинг %d мс", serverName(s), s.ping)
		}
		switch {
		case was:
			return &toast{"VPN снова работает", line}
		case t.asked || (level == notifyAll && t.prev != ""):
			return &toast{"VPN подключен", line}
		}
	case stWarn:
		if s.auto {
			return n.problem(now, "Серверы не отвечают",
				"Ни один сервер из auto не дал ответа. Проверь интернет; если он есть — обнови подписку.")
		}
		return n.problem(now, "Сервер не отвечает",
			serverName(s)+" молчит. Выбери auto или другой сервер в меню.")
	case stError:
		return n.problem(now, "Проблема с VPN", "sing-box запущен, но не отвечает.")
	case stOff:
		if t.prev == "" {
			return nil // the tray just started and the VPN is simply off
		}
		if t.expected {
			n.alerted = false
			if level == notifyAll {
				return &toast{"VPN выключен", "sing-box остановлен."}
			}
			return nil
		}
		return n.problem(now, "VPN выключился", "sing-box перестал работать. Запусти VPN из меню у щита.")
	}
	return nil
}

func (n *announcer) problem(now time.Time, title, body string) *toast {
	if !n.lastProblem.IsZero() && now.Sub(n.lastProblem) < problemGap {
		return nil
	}
	n.alerted, n.lastProblem = true, now
	return &toast{title, body}
}

// ---- settings ------------------------------------------------------------

type settings struct {
	Notify string `json:"notify"`
}

func settingsPath(dir string) string { return filepath.Join(dir, "tray-settings.json") }

func loadSettings(dir string) settings {
	s := settings{Notify: notifyProblems}
	if b, err := os.ReadFile(settingsPath(dir)); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	switch s.Notify {
	case notifyAll, notifyProblems, notifyNone:
	default:
		s.Notify = notifyProblems
	}
	return s
}

func saveSettings(dir string, s settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath(dir), b, 0o644)
}
