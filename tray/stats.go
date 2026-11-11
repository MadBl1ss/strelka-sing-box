package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// "auto" holds on to its server for as long as that server answers, and when
// it has to leave, it takes the first live one in list order. So the order of
// the list is the order of preference - and it should not be the alphabet.
//
// The tray keeps a running picture of every server from the checks the core
// makes anyway: how fast it usually answers and how often it does not. The
// next time the server list is rebuilt, "auto" is sorted by that.

const (
	statsFile = "server-stats.json"
	// How much one new sample moves the running averages.
	statsWeight = 0.2
	// A server that misses every check is rated this many times slower.
	missPenalty = 3.0
	// A miss only counts while checks are demonstrably running: somebody
	// else in the pool answered this recently.
	statsFresh  = 3 * time.Minute
	statsSettle = 20 * time.Second
	// One miss per server per this long, however often the tray looks.
	missEvery = time.Minute
	// Servers gone from every subscription for this long are forgotten.
	statsKeep = 30 * 24 * time.Hour
)

type serverStat struct {
	Avg    float64   `json:"avg"`  // typical delay, ms
	Miss   float64   `json:"miss"` // share of checks without an answer, 0..1
	N      int       `json:"n"`    // answers seen
	Seen   time.Time `json:"seen"` // the last answer
	MissAt time.Time `json:"miss_at,omitzero"`
}

type serverStats struct {
	Servers map[string]*serverStat `json:"servers"`
}

func statsPath(dir string) string { return filepath.Join(dir, statsFile) }

func loadStats(dir string) *serverStats {
	st := &serverStats{}
	if b, err := os.ReadFile(statsPath(dir)); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.Servers == nil {
		st.Servers = map[string]*serverStat{}
	}
	return st
}

func (st *serverStats) save(dir string, now time.Time) error {
	for tag, s := range st.Servers {
		last := s.Seen
		if s.MissAt.After(last) {
			last = s.MissAt
		}
		if now.Sub(last) > statsKeep {
			delete(st.Servers, tag)
		}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statsPath(dir), b, 0o644)
}

// observe folds the core's latest results for the "auto" pool into the
// picture. probed is the server the tray tests by itself, if any: its results
// say nothing about whether the pool is being checked. It reports whether
// anything changed.
func (st *serverStats) observe(now time.Time, pool []string, px map[string]proxyInfo, probed string) bool {
	// A round of checks takes up to 15 s. Until one has had time to finish, a
	// server without a result is merely not reached yet.
	checking := false
	for _, tag := range pool {
		if tag == probed {
			continue
		}
		if p := px[tag]; p.alive() {
			if age := now.Sub(p.Tested); age >= statsSettle && age < statsFresh {
				checking = true
				break
			}
		}
	}
	changed := false
	for _, tag := range pool {
		p, known := px[tag]
		if !known {
			continue
		}
		s := st.Servers[tag]
		switch {
		case p.alive():
			if s != nil && !p.Tested.After(s.Seen) {
				continue // the same result as last time
			}
			if s == nil {
				s = &serverStat{Avg: float64(p.Delay)}
				st.Servers[tag] = s
			} else {
				s.Avg += statsWeight * (float64(p.Delay) - s.Avg)
				s.Miss -= statsWeight * s.Miss
			}
			s.N++
			s.Seen = p.Tested
			changed = true
		case checking:
			if s == nil {
				s = &serverStat{}
				st.Servers[tag] = s
			}
			if now.Sub(s.MissAt) < missEvery {
				continue
			}
			s.Miss += statsWeight * (1 - s.Miss)
			s.MissAt = now
			changed = true
		}
	}
	return changed
}

// rating is what the order is built on: lower is better. A server that never
// answered has none.
func (st *serverStats) rating(tag string) (float64, bool) {
	s := st.Servers[tag]
	if s == nil || s.N == 0 {
		return 0, false
	}
	return s.Avg * (1 + missPenalty*s.Miss), true
}

// orderPool sorts the "auto" pool best first. Servers nobody has measured
// yet keep their place in line behind the measured ones.
func orderPool(pool []string, st *serverStats) []string {
	out := append([]string(nil), pool...)
	if st == nil {
		return out
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := st.rating(out[i])
		rj, okj := st.rating(out[j])
		if oki != okj {
			return oki
		}
		return oki && ri < rj
	})
	return out
}
