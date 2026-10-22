package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Two routing modes, switched at runtime through the Clash API:
//
//	Rule    (default) only rules\vpn.json goes through the VPN, the rest direct;
//	Global  everything goes through the VPN except rules\direct.json, LAN
//	        addresses and xray.exe's own connections.
//
// The rules carry "clash_mode", so a switch is one PATCH /configs: no restart
// and no admin. sing-box keeps the chosen mode in cache.db across restarts.
//
// In Global, DNS goes through the VPN as well, or the ISP's resolver would
// still see (and could spoof) every lookup. The VPN servers' own names are
// the exception: xray.exe resolves them through Windows, and a lookup that
// had to travel through a tunnel running over xray would never complete.
// Those names live in rules\servers-dns.json, rewritten on every refresh.

const (
	modeRule      = "Rule"
	modeGlobal    = "Global"
	serversDNSTag = "servers-dns"
)

// modesMigrated reports whether config.json already has the mode rules.
func modesMigrated(cfg []byte) bool {
	found := false
	gjson.GetBytes(cfg, "route.rules").ForEach(func(_, r gjson.Result) bool {
		if r.Get("clash_mode").Exists() {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasRuleSet tells whether a rule references the given rule-set tag.
func hasRuleSet(r gjson.Result, tag string) bool {
	return slices.Contains(asStrings(r.Get("rule_set")), tag)
}

// ensureModes adds the mode rules to config.json once. Like ensureRules, the
// result must pass "sing-box check" or the old config stays. Returns whether
// config.json changed, which means the running core needs a restart.
func ensureModes(dir string, logf func(string, ...any)) (bool, error) {
	cfgPath := filepath.Join(dir, "config.json")
	cur, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, err
	}
	if !rulesMigrated(cur) {
		return false, fmt.Errorf("сначала нужны файлы правил (rules\\*.json)")
	}
	if modesMigrated(cur) {
		if _, err := os.Stat(ruleFile(dir, serversDNSTag)); os.IsNotExist(err) &&
			gjson.GetBytes(cur, `route.rule_set.#(tag=="`+serversDNSTag+`")`).Exists() {
			return false, writeServersDNS(dir, cur)
		}
		return false, nil
	}

	proxyDNS := dnsServerVia(cur, proxyOutTag)
	localDNS := gjson.GetBytes(cur, "dns.final").String()
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }

	// Route: LAN stays local in any mode (no VPN server can reach it); in
	// Global everything that rules\direct.json did not claim goes to proxy.
	var route []json.RawMessage
	privateAt, globalAt := -1, -1
	gjson.GetBytes(cur, "route.rules").ForEach(func(_, r gjson.Result) bool {
		if privateAt < 0 && r.Get("rule_set").Exists() {
			privateAt = len(route)
		}
		route = append(route, raw(r.Raw))
		if hasRuleSet(r, ruleSetDir) {
			globalAt = len(route)
		}
		return true
	})
	if privateAt < 0 {
		privateAt = len(route)
	}
	if globalAt < 0 {
		globalAt = len(route)
	}
	globalRule := raw(`{"clash_mode":"` + modeGlobal + `","outbound":"` + proxyOutTag + `"}`)
	route = slices.Insert(route, globalAt, globalRule)
	route = slices.Insert(route, privateAt, raw(`{"ip_is_private":true,"outbound":"`+directOutTag+`"}`))

	// DNS: the servers' names first, through the local resolver; then, after
	// the direct list, everything through the VPN resolver in Global.
	var dns []json.RawMessage
	dnsGlobalAt := -1
	gjson.GetBytes(cur, "dns.rules").ForEach(func(_, r gjson.Result) bool {
		dns = append(dns, raw(r.Raw))
		if hasRuleSet(r, ruleSetDir+"-dns") {
			dnsGlobalAt = len(dns)
		}
		return true
	})
	if dnsGlobalAt < 0 {
		dnsGlobalAt = 0
	}
	sets := []json.RawMessage{}
	gjson.GetBytes(cur, "route.rule_set").ForEach(func(_, v gjson.Result) bool {
		sets = append(sets, raw(v.Raw))
		return true
	})
	if proxyDNS != "" && localDNS != "" {
		dns = slices.Insert(dns, dnsGlobalAt, raw(`{"clash_mode":"`+modeGlobal+`","server":"`+proxyDNS+`"}`))
		dns = slices.Insert(dns, 0, raw(`{"rule_set":"`+serversDNSTag+`","server":"`+localDNS+`"}`))
		sets = append(sets, raw(`{"type":"local","tag":"`+serversDNSTag+`","path":"`+rulesDir+`/`+serversDNSTag+`.json"}`))
	}

	out := cur
	for _, set := range []struct {
		path string
		v    any
	}{{"route.rules", route}, {"dns.rules", dns}, {"route.rule_set", sets}} {
		b, err := json.Marshal(set.v)
		if err != nil {
			return false, err
		}
		if out, err = sjson.SetRawBytes(out, set.path, b); err != nil {
			return false, err
		}
	}

	// The check needs the file the new config names.
	if err := writeServersDNS(dir, cur); err != nil {
		return false, err
	}
	tmp := cfgPath + ".modes.tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return false, err
	}
	if err := runQuiet(coreExe(dir), []string{"check", "-c", tmp}, dir); err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("конфиг с режимами не прошёл проверку: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.before-modes.json"), cur, 0o644); err != nil {
		logf("не удалось сохранить бэкап: %v", err)
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		os.Remove(tmp)
		return false, err
	}
	_ = runQuiet(coreExe(dir), []string{"format", "-c", cfgPath, "-w"}, dir)
	logf("добавлены режимы «по списку» и «весь трафик»")
	return true, nil
}

// serverHosts lists the domain names of every VPN server: sing-box's own
// outbounds plus the ones behind xray (in config.json those are 127.0.0.1).
func serverHosts(dir string, cfg []byte) []string {
	var hosts []string
	add := func(h string) {
		h = strings.ToLower(h)
		if h != "" && net.ParseIP(h) == nil && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	gjson.GetBytes(cfg, "outbounds.#.server").ForEach(func(_, h gjson.Result) bool {
		add(h.String())
		return true
	})
	for _, addr := range xrayAddrs(dir) {
		add(addr)
	}
	slices.Sort(hosts)
	return hosts
}

// writeServersDNS rewrites rules\servers-dns.json from a config. Written in
// place and only when it changed, like the other rule-set files, so sing-box
// picks it up without a restart.
func writeServersDNS(dir string, cfg []byte) error {
	if err := os.MkdirAll(filepath.Join(dir, rulesDir), 0o755); err != nil {
		return err
	}
	var rules []headless
	if hosts := serverHosts(dir, cfg); len(hosts) > 0 {
		rules = []headless{{Domain: hosts}}
	}
	return writeRuleSet(ruleFile(dir, serversDNSTag), rules)
}

func modeTitle(m string) string {
	if strings.EqualFold(m, modeGlobal) {
		return "весь трафик через VPN"
	}
	return "через VPN только список"
}
