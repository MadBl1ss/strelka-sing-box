package main

import "time"

// A single poll is a poor witness: one slow handshake, a core that is still
// booting, a process snapshot taken mid-restart. Acting on each of them is
// what made the icon and the notifications flap. health turns the stream of
// raw polls into a settled state that only moves when the evidence holds.

// What one poll saw.
const (
	rawOff   = "off"   // no core process
	rawError = "error" // the process is there, its API is silent
	rawOK    = "ok"    // the server in use answers
	rawBad   = "bad"   // it does not
)

// What the tray shows.
const (
	stOff      = "off"
	stError    = "error"
	stOK       = "ok"
	stWarn     = "warn"     // the server (or all of "auto") is confirmed silent
	stStarting = "starting" // the core is up, its first answer is still out
)

const (
	// The process must be missing on two polls in a row.
	holdOff = 4 * time.Second
	// A booting core takes a few seconds to open its API.
	holdError = 20 * time.Second
	// "auto" without an answer: the core gets a full round of checks (and the
	// re-check the tray asks for) to move to a live server before this counts.
	holdBad = 45 * time.Second
	// A hand-picked server is tested by the tray itself: this many failed
	// probes in a row mean it is down - provided they span this long, so that
	// three quick refusals while Wi-Fi reconnects do not count.
	failsBad  = 3
	holdProbe = 15 * time.Second
	// A gap this long between polls means the machine slept. What was being
	// waited out before is stale; the count starts over.
	sleepGap = 30 * time.Second
)

type health struct {
	state string    // settled state; "" until the first poll
	cand  string    // the raw state being waited out
	since time.Time // when cand was first seen
	fails int       // failed probes in a row
	leaf  string    // the server the evidence is about
	seen  time.Time // the previous poll
}

// observe feeds one poll in and returns the settled state. expected means the
// user has just asked for a stop or a restart: then there is nothing to wait
// out, the VPN going away is exactly what should be shown.
func (h *health) observe(now time.Time, s snapshot, expected bool) string {
	up := s.raw == rawOK || s.raw == rawBad
	if !h.seen.IsZero() && now.Sub(h.seen) > sleepGap {
		h.cand, h.fails = "", 0
	}
	h.seen = now

	// A hand-picked server is a new subject: nothing known about the old one
	// carries over, and the icon must not vouch for it before its first probe.
	if up && !s.auto && h.leaf != "" && s.leaf != h.leaf {
		h.fails = 0
		if h.state == stOK || h.state == stWarn {
			h.state = stStarting
		}
	}
	if up {
		h.leaf = s.leaf
	}

	if s.raw != h.cand {
		h.cand, h.since = s.raw, now
	}
	held := now.Sub(h.since)

	switch s.raw {
	case rawOK:
		h.fails = 0
		h.state = stOK
	case rawBad:
		if s.probed {
			h.fails++
		}
		confirmed := h.fails >= failsBad && held >= holdProbe
		if s.auto {
			confirmed = held >= holdBad
		}
		if confirmed {
			h.state = stWarn
		} else {
			h.wait(expected)
		}
	case rawError:
		if held >= holdError {
			h.state = stError
		} else {
			h.wait(expected)
		}
	default: // rawOff
		if h.state == "" || expected || held >= holdOff {
			h.state = stOff
			h.fails, h.leaf = 0, ""
		} else {
			h.wait(expected)
		}
	}
	return h.state
}

// wait decides what to show while bad news is still unconfirmed. A working
// VPN keeps its green shield; a core that just appeared, or just found its
// voice again, is "starting" rather than whatever it was before.
func (h *health) wait(expected bool) {
	switch {
	case h.state == "" || h.state == stOff:
		h.state = stStarting
	case h.state == stError && h.cand == rawBad:
		h.state = stStarting
	case expected:
		h.state = stStarting
	}
}

// iconFor maps a settled state to one of the four shields.
func iconFor(state string) string {
	switch state {
	case stOK, stWarn, stError:
		return state
	case stStarting:
		return stWarn
	}
	return stOff
}
