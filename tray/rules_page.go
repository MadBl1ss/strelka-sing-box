package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// The rules page is served by the tray itself on a random loopback port and
// only answers with the per-run token, so no web page can reach it by
// guessing the port (and a rebinding attack fails the Host check).

//go:embed rules.html
var rulesHTML string

type rulesServer struct {
	a     *app
	mu    sync.Mutex // serialises edits of the rule files
	token string
	addr  string
}

func (a *app) openRules() {
	changed, err := ensureRules(a.dir, func(f string, v ...any) { log.Printf(f, v...) })
	if err != nil {
		a.notify("Правила", "Не удалось подготовить файлы правил: "+err.Error())
		return
	}
	if changed {
		a.notify("Правила", "Правила вынесены в отдельные файлы. Перезапусти VPN один раз — дальше изменения применяются сразу.")
	}

	a.rulesOnce.Do(func() {
		s, err := startRulesServer(a)
		if err != nil {
			log.Printf("rules page: %v", err)
			return
		}
		a.rules = s
	})
	if a.rules == nil {
		a.notify("Правила", "Не удалось открыть страницу правил, подробности в sing-box-tray.log")
		return
	}
	_ = openURL(fmt.Sprintf("http://%s/?t=%s", a.rules.addr, a.rules.token))
}

func startRulesServer(a *app) (*rulesServer, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &rulesServer{a: a, token: hex.EncodeToString(b), addr: ln.Addr().String()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("POST /api/rule", s.edit)
	mux.HandleFunc("GET /api/connections", s.connections)
	srv := &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Printf("rules page stopped: %v", err)
		}
	}()
	log.Printf("rules page on %s", s.addr)
	return s, nil
}

func (s *rulesServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Token")
		if tok == "" {
			tok = r.URL.Query().Get("t")
		}
		if r.Host != s.addr || subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *rulesServer) page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(rulesHTML, "__TOKEN__", s.token, 1)))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type statePayload struct {
	Rules   ruleState `json:"rules"`
	System  []string  `json:"system"`  // rules that stay in config.json
	Live    bool      `json:"live"`    // the running core already reads the files
	Running bool      `json:"running"` // sing-box answers at all
	Added   string    `json:"added,omitempty"`
}

func (s *rulesServer) buildState() (statePayload, error) {
	var p statePayload
	rs, err := loadRules(s.a.dir)
	if err != nil {
		return p, err
	}
	p.Rules = rs
	p.System = systemRules(filepath.Join(s.a.dir, "config.json"))

	var r struct {
		Rules []struct {
			Payload string `json:"payload"`
		} `json:"rules"`
	}
	if err := s.a.cl.do("GET", "/rules", nil, &r, 0); err == nil {
		p.Running = true
		for _, x := range r.Rules {
			if strings.Contains(x.Payload, "rule_set="+ruleSetVPN) {
				p.Live = true
			}
		}
	}
	return p, nil
}

func (s *rulesServer) state(w http.ResponseWriter, _ *http.Request) {
	p, err := s.buildState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *rulesServer) edit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Op    string `json:"op"`   // add | remove
		List  string `json:"list"` // vpn | direct
		Kind  string `json:"kind"` // auto | app | domain | keyword | ip
		Value string `json:"value"`
	}
	fail := func(err error) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		fail(err)
		return
	}
	if req.List != ruleSetVPN && req.List != ruleSetDir {
		fail(fmt.Errorf("неизвестный список %q", req.List))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := loadRules(s.a.dir)
	if err != nil {
		fail(err)
		return
	}
	added := ""
	switch req.Op {
	case "add":
		kind, v, err := normalizeRule(req.Kind, req.Value)
		if err != nil {
			fail(err)
			return
		}
		rs.addRule(req.List, kind, v)
		added = v
		log.Printf("rules: %s %s %q", req.List, kind, v)
	case "remove":
		if rs.list(req.List).field(req.Kind) == nil {
			fail(fmt.Errorf("неизвестный тип %q", req.Kind))
			return
		}
		rs.removeRule(req.List, req.Kind, req.Value)
		log.Printf("rules: removed %s %s %q", req.List, req.Kind, req.Value)
	default:
		fail(fmt.Errorf("неизвестная операция %q", req.Op))
		return
	}
	if err := saveRules(s.a.dir, rs); err != nil {
		fail(err)
		return
	}
	p, err := s.buildState()
	if err != nil {
		fail(err)
		return
	}
	p.Added = added
	writeJSON(w, http.StatusOK, p)
}

// connView is one live connection, trimmed to what the page shows.
type connView struct {
	App    string   `json:"app"`
	Path   string   `json:"path"`
	Host   string   `json:"host"`
	IP     string   `json:"ip"`
	Port   string   `json:"port"`
	Net    string   `json:"net"`
	Chains []string `json:"chains"`
	Rule   string   `json:"rule"`
	Up     uint64   `json:"up"`
	Down   uint64   `json:"down"`
	Start  string   `json:"start"`
}

func (s *rulesServer) connections(w http.ResponseWriter, _ *http.Request) {
	var r struct {
		Connections []struct {
			Chains   []string `json:"chains"`
			Rule     string   `json:"rule"`
			Upload   uint64   `json:"upload"`
			Download uint64   `json:"download"`
			Start    string   `json:"start"`
			Metadata struct {
				Host        string `json:"host"`
				DstIP       string `json:"destinationIP"`
				DstPort     string `json:"destinationPort"`
				Network     string `json:"network"`
				ProcessPath string `json:"processPath"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := s.a.cl.do("GET", "/connections", nil, &r, 0); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"running": false, "connections": []connView{}})
		return
	}
	out := make([]connView, 0, len(r.Connections))
	for _, c := range r.Connections {
		m := c.Metadata
		app := ""
		if m.ProcessPath != "" {
			app = filepath.Base(m.ProcessPath)
		}
		out = append(out, connView{
			App: app, Path: m.ProcessPath, Host: m.Host, IP: m.DstIP, Port: m.DstPort,
			Net: m.Network, Chains: c.Chains, Rule: c.Rule, Up: c.Upload, Down: c.Download, Start: c.Start,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"running": true, "connections": out})
}

// systemRules describes the route rules that stay in config.json, so the page
// can show the whole picture even though it edits only the files.
func systemRules(cfgPath string) []string {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil
	}
	var out []string
	gjson.GetBytes(raw, "route.rules").ForEach(func(_, r gjson.Result) bool {
		if r.Get("rule_set").Exists() {
			return true
		}
		action := r.Get("action").String()
		if action == "" || action == "route" {
			action = "→ " + r.Get("outbound").String()
		}
		var cond []string
		r.ForEach(func(k, v gjson.Result) bool {
			switch k.String() {
			case "action", "outbound":
			default:
				cond = append(cond, k.String()+"="+strings.Join(asStrings(v), ", "))
			}
			return true
		})
		if len(cond) == 0 {
			cond = []string{"всё"}
		}
		out = append(out, strings.Join(cond, "; ")+"  "+action)
		return true
	})
	if f := gjson.GetBytes(raw, "route.final").String(); f != "" {
		out = append(out, "остальное  → "+f)
	}
	return out
}
