package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Split routing lives in local rule-set files rather than in config.json:
// sing-box (1.10+) re-reads a local rule-set as soon as the file changes, so
// the rules page can add an app or a site without a restart and without
// admin rights. config.json only points at the files.
//
//	rules/direct.json      route: these go direct (checked first, so they win)
//	rules/vpn.json         route: these go through the "proxy" selector
//	rules/direct-dns.json  DNS: the domains of direct.json, resolved locally
//	rules/vpn-dns.json     DNS: the domains of vpn.json, resolved through the VPN
//
// The *-dns files carry domains only. An ip_cidr inside a rule-set that a DNS
// rule references turns that rule into a response filter, which would send
// every lookup through the VPN resolver first.

const (
	rulesDir     = "rules"
	ruleSetVPN   = "vpn"
	ruleSetDir   = "direct"
	ruleSetVer   = 3
	proxyOutTag  = "proxy"
	directOutTag = "direct"
)

// ruleList is one direction's rules as the page shows them.
type ruleList struct {
	Apps     []string `json:"apps"`     // process_name
	Domains  []string `json:"domains"`  // domain_suffix
	Keywords []string `json:"keywords"` // domain_keyword
	IPs      []string `json:"ips"`      // ip_cidr
}

type ruleState struct {
	VPN    ruleList `json:"vpn"`
	Direct ruleList `json:"direct"`
}

func (s *ruleState) list(name string) *ruleList {
	if name == ruleSetVPN {
		return &s.VPN
	}
	return &s.Direct
}

func (l *ruleList) field(kind string) *[]string {
	switch kind {
	case "app":
		return &l.Apps
	case "domain":
		return &l.Domains
	case "keyword":
		return &l.Keywords
	case "ip":
		return &l.IPs
	}
	return nil
}

func ruleFile(dir, tag string) string {
	return filepath.Join(dir, rulesDir, tag+".json")
}

// headless mirrors the rule-set source format for the fields the page edits.
type headless struct {
	ProcessName   []string `json:"process_name,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
}

type ruleSetFile struct {
	Version int        `json:"version"`
	Rules   []headless `json:"rules"`
}

func readRuleList(path string) (ruleList, error) {
	var l ruleList
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	var f ruleSetFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return l, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	for _, r := range f.Rules {
		l.Apps = append(l.Apps, r.ProcessName...)
		l.Domains = append(l.Domains, r.DomainSuffix...)
		l.Domains = append(l.Domains, r.Domain...)
		l.Keywords = append(l.Keywords, r.DomainKeyword...)
		l.IPs = append(l.IPs, r.IPCIDR...)
	}
	l.tidy()
	return l, nil
}

func loadRules(dir string) (ruleState, error) {
	var s ruleState
	var err error
	if s.VPN, err = readRuleList(ruleFile(dir, ruleSetVPN)); err != nil {
		return s, err
	}
	s.Direct, err = readRuleList(ruleFile(dir, ruleSetDir))
	return s, err
}

// tidy sorts and dedupes every field. Apps keep their case: process_name is
// an exact match, so "Discord.exe" and "discord.exe" are different entries.
func (l *ruleList) tidy() {
	for _, p := range []*[]string{&l.Apps, &l.Domains, &l.Keywords, &l.IPs} {
		v := slices.DeleteFunc(*p, func(s string) bool { return s == "" })
		slices.SortFunc(v, func(a, b string) int {
			if c := strings.Compare(strings.ToLower(a), strings.ToLower(b)); c != 0 {
				return c
			}
			return strings.Compare(a, b)
		})
		*p = slices.Compact(v)
		if *p == nil {
			*p = []string{}
		}
	}
}

// Headless rules must not mix process_name with domains: inside one rule
// different kinds of condition are ANDed. Separate rules in a set are ORed.
func (l ruleList) routeRules() []headless {
	var out []headless
	if len(l.Apps) > 0 {
		out = append(out, headless{ProcessName: l.Apps})
	}
	if len(l.Domains)+len(l.Keywords) > 0 {
		out = append(out, headless{DomainSuffix: l.Domains, DomainKeyword: l.Keywords})
	}
	if len(l.IPs) > 0 {
		out = append(out, headless{IPCIDR: l.IPs})
	}
	return out
}

func (l ruleList) dnsRules() []headless {
	if len(l.Domains)+len(l.Keywords) == 0 {
		return nil
	}
	return []headless{{DomainSuffix: l.Domains, DomainKeyword: l.Keywords}}
}

func writeRuleSet(path string, rules []headless) error {
	if rules == nil {
		rules = []headless{}
	}
	b, err := json.MarshalIndent(ruleSetFile{Version: ruleSetVer, Rules: rules}, "", "  ")
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(b) {
		return nil // untouched file: no reload in sing-box
	}
	// Written in place, not via rename: sing-box watches the file itself.
	return os.WriteFile(path, b, 0o644)
}

func saveRules(dir string, s ruleState) error {
	if err := os.MkdirAll(filepath.Join(dir, rulesDir), 0o755); err != nil {
		return err
	}
	s.VPN.tidy()
	s.Direct.tidy()
	files := []struct {
		tag   string
		rules []headless
	}{
		{ruleSetDir, s.Direct.routeRules()},
		{ruleSetDir + "-dns", s.Direct.dnsRules()},
		{ruleSetVPN, s.VPN.routeRules()},
		{ruleSetVPN + "-dns", s.VPN.dnsRules()},
	}
	for _, f := range files {
		if err := writeRuleSet(ruleFile(dir, f.tag), f.rules); err != nil {
			return err
		}
	}
	return nil
}

// ---- editing -----------------------------------------------------------

// normalizeRule turns what the user typed or clicked into a rule value.
// kind "auto" guesses: a path or *.exe is an app, an address is an IP,
// anything else a domain.
func normalizeRule(kind, value string) (string, string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", "", fmt.Errorf("пустое значение")
	}
	if kind == "auto" {
		lv := strings.ToLower(v)
		switch {
		case strings.HasSuffix(lv, ".exe") || strings.ContainsAny(v, `\`):
			kind = "app"
		case isIPOrCIDR(v):
			kind = "ip"
		default:
			kind = "domain"
		}
	}

	switch kind {
	case "app":
		if i := strings.LastIndexAny(v, `\/`); i >= 0 {
			v = v[i+1:]
		}
		if !strings.Contains(v, ".") {
			v += ".exe"
		}
		if strings.ContainsAny(v, `:*?"<>|`) {
			return "", "", fmt.Errorf("%q не похоже на имя программы", v)
		}
	case "domain":
		v = cleanDomain(v)
		if v == "" || strings.ContainsAny(v, " /\\:*") || !strings.Contains(v, ".") {
			return "", "", fmt.Errorf("%q не похоже на домен", value)
		}
	case "keyword":
		v = strings.ToLower(v)
		if strings.ContainsAny(v, " /\\") {
			return "", "", fmt.Errorf("ключевое слово без пробелов и слэшей")
		}
	case "ip":
		p, err := parsePrefix(v)
		if err != nil {
			return "", "", fmt.Errorf("%q не похоже на IP или подсеть", v)
		}
		v = p.String()
	default:
		return "", "", fmt.Errorf("неизвестный тип %q", kind)
	}
	return kind, v, nil
}

// cleanDomain accepts a pasted URL or "*.example.com" as well as a bare name.
func cleanDomain(v string) string {
	v = strings.ToLower(v)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	v = strings.TrimPrefix(v, "*")
	v = strings.Trim(v, ".")
	// A suffix rule for the bare site covers www. and every other subdomain.
	if rest, ok := strings.CutPrefix(v, "www."); ok && strings.Contains(rest, ".") {
		v = rest
	}
	return v
}

func isIPOrCIDR(v string) bool {
	_, err := parsePrefix(v)
	return err == nil
}

func parsePrefix(v string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// addRule puts a value into one direction and takes it out of the other, so
// "move to VPN" and "add to VPN" are the same click.
func (s *ruleState) addRule(list, kind, value string) {
	other := ruleSetDir
	if list == ruleSetDir {
		other = ruleSetVPN
	}
	s.removeRule(other, kind, value)
	f := s.list(list).field(kind)
	*f = append(*f, value)
	s.list(list).tidy()
}

func (s *ruleState) removeRule(list, kind, value string) {
	f := s.list(list).field(kind)
	*f = slices.DeleteFunc(*f, func(x string) bool { return x == value })
}

// ---- one-time move out of config.json ------------------------------------

// rulesMigrated reports whether config.json already routes through the
// rule-set files.
func rulesMigrated(cfg []byte) bool {
	found := false
	gjson.GetBytes(cfg, "route.rule_set").ForEach(func(_, v gjson.Result) bool {
		if v.Get("tag").String() == ruleSetVPN {
			found = true
			return false
		}
		return true
	})
	return found
}

// movableRoute says whether a route rule is a plain "these apps/sites go
// there" list that belongs in a rule-set. Anything with other conditions
// (inbound, source, protocol...) stays in config.json, and so does the
// xray.exe exemption: it keeps the sidecar from looping into the tunnel and
// must not be one click away from deletion.
func movableRoute(r gjson.Result) (dest string, ok bool) {
	if a := r.Get("action").String(); a != "" && a != "route" {
		return "", false
	}
	out := r.Get("outbound").String()
	if out != proxyOutTag && out != directOutTag {
		return "", false
	}
	allowed := map[string]bool{"process_name": true, "domain_suffix": true, "domain": true,
		"domain_keyword": true, "ip_cidr": true, "outbound": true, "action": true}
	good := true
	r.ForEach(func(k, v gjson.Result) bool {
		if !allowed[k.String()] {
			good = false
			return false
		}
		if k.String() == "process_name" {
			for _, p := range asStrings(v) {
				if strings.EqualFold(p, xrayImage) {
					good = false
				}
			}
		}
		return good
	})
	if !good {
		return "", false
	}
	if out == proxyOutTag {
		return ruleSetVPN, true
	}
	return ruleSetDir, true
}

func movableDNS(r gjson.Result) bool {
	if a := r.Get("action").String(); a != "" && a != "route" {
		return false
	}
	allowed := map[string]bool{"domain_suffix": true, "domain": true, "domain_keyword": true,
		"server": true, "action": true}
	good := r.Get("server").Exists()
	r.ForEach(func(k, _ gjson.Result) bool {
		good = good && allowed[k.String()]
		return good
	})
	return good
}

// asStrings reads a field that sing-box allows as either "x" or ["x", "y"].
func asStrings(v gjson.Result) []string {
	if !v.Exists() {
		return nil
	}
	if !v.IsArray() {
		return []string{v.String()}
	}
	var out []string
	for _, x := range v.Array() {
		out = append(out, x.String())
	}
	return out
}

func (l *ruleList) absorb(r gjson.Result) {
	l.Apps = append(l.Apps, asStrings(r.Get("process_name"))...)
	l.Domains = append(l.Domains, asStrings(r.Get("domain_suffix"))...)
	l.Domains = append(l.Domains, asStrings(r.Get("domain"))...)
	l.Keywords = append(l.Keywords, asStrings(r.Get("domain_keyword"))...)
	l.IPs = append(l.IPs, asStrings(r.Get("ip_cidr"))...)
}

// migrateRules moves the plain app/site lists out of config.json into the
// rule-set files and returns the new config. It adds to whatever the files
// already hold, and returns cfg unchanged when there is nothing to do.
func migrateRules(dir string, cfg []byte) ([]byte, bool, error) {
	if rulesMigrated(cfg) {
		return cfg, false, nil
	}
	state, err := loadRules(dir)
	if err != nil {
		return nil, false, err
	}

	// Route rules: drop the movable ones, remember where the first one sat.
	var routeOut []json.RawMessage
	insertAt := -1
	gjson.GetBytes(cfg, "route.rules").ForEach(func(_, r gjson.Result) bool {
		if dest, ok := movableRoute(r); ok {
			state.list(dest).absorb(r)
			if insertAt < 0 {
				insertAt = len(routeOut)
			}
			return true
		}
		routeOut = append(routeOut, json.RawMessage(r.Raw))
		return true
	})
	if insertAt < 0 {
		insertAt = len(routeOut)
	}
	refs := []json.RawMessage{
		json.RawMessage(`{"rule_set":"` + ruleSetDir + `","outbound":"` + directOutTag + `"}`),
		json.RawMessage(`{"rule_set":"` + ruleSetVPN + `","outbound":"` + proxyOutTag + `"}`),
	}
	routeOut = slices.Insert(routeOut, insertAt, refs...)

	// DNS rules: a domain list sent to some resolver. The one aimed at the
	// resolver that goes through the VPN is folded into the VPN list, which
	// already holds the same domains for routing.
	vpnDNS := dnsServerVia(cfg, proxyOutTag)
	localDNS := gjson.GetBytes(cfg, "dns.final").String()
	var dnsOut []json.RawMessage
	dnsAt := -1
	gjson.GetBytes(cfg, "dns.rules").ForEach(func(_, r gjson.Result) bool {
		if vpnDNS != "" && movableDNS(r) && r.Get("server").String() == vpnDNS {
			state.VPN.absorb(r)
			if dnsAt < 0 {
				dnsAt = len(dnsOut)
			}
			return true
		}
		dnsOut = append(dnsOut, json.RawMessage(r.Raw))
		return true
	})
	if dnsAt < 0 {
		dnsAt = len(dnsOut)
	}
	var dnsRefs []json.RawMessage
	if localDNS != "" {
		dnsRefs = append(dnsRefs, json.RawMessage(`{"rule_set":"`+ruleSetDir+`-dns","server":"`+localDNS+`"}`))
	}
	if vpnDNS != "" {
		dnsRefs = append(dnsRefs, json.RawMessage(`{"rule_set":"`+ruleSetVPN+`-dns","server":"`+vpnDNS+`"}`))
	}
	dnsOut = slices.Insert(dnsOut, dnsAt, dnsRefs...)

	// Rule-set definitions, keeping any the config already had.
	var sets []json.RawMessage
	gjson.GetBytes(cfg, "route.rule_set").ForEach(func(_, v gjson.Result) bool {
		sets = append(sets, json.RawMessage(v.Raw))
		return true
	})
	for _, tag := range []string{ruleSetDir, ruleSetDir + "-dns", ruleSetVPN, ruleSetVPN + "-dns"} {
		sets = append(sets, json.RawMessage(fmt.Sprintf(
			`{"type":"local","tag":%q,"format":"source","path":%q}`, tag, rulesDir+"/"+tag+".json")))
	}

	out := cfg
	for _, set := range []struct {
		path string
		v    []json.RawMessage
	}{{"route.rules", routeOut}, {"dns.rules", dnsOut}, {"route.rule_set", sets}} {
		b, err := json.Marshal(set.v)
		if err != nil {
			return nil, false, err
		}
		if out, err = sjson.SetRawBytes(out, set.path, b); err != nil {
			return nil, false, err
		}
	}
	if err := saveRules(dir, state); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// dnsServerVia finds the DNS server whose detour is the given outbound.
func dnsServerVia(cfg []byte, outbound string) string {
	tag := ""
	gjson.GetBytes(cfg, "dns.servers").ForEach(func(_, v gjson.Result) bool {
		if v.Get("detour").String() == outbound {
			tag = v.Get("tag").String()
			return false
		}
		return true
	})
	return tag
}

// ensureRules makes sure config.json uses the rule-set files and that every
// file it names exists (a missing one stops sing-box from starting). The new
// config must pass "sing-box check" or the old one stays. Returns whether
// config.json changed, which means the running core needs a restart.
func ensureRules(dir string, logf func(string, ...any)) (bool, error) {
	cfgPath := filepath.Join(dir, "config.json")
	cur, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, err
	}
	if rulesMigrated(cur) {
		for _, tag := range []string{ruleSetDir, ruleSetDir + "-dns", ruleSetVPN, ruleSetVPN + "-dns"} {
			if _, err := os.Stat(ruleFile(dir, tag)); os.IsNotExist(err) {
				s, err := loadRules(dir)
				if err != nil {
					return false, err
				}
				return false, saveRules(dir, s)
			}
		}
		return false, nil
	}

	out, changed, err := migrateRules(dir, cur)
	if err != nil || !changed {
		return false, err
	}
	tmp := cfgPath + ".rules.tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return false, err
	}
	if err := runQuiet(coreExe(dir), []string{"check", "-c", tmp}, dir); err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("конфиг с файлами правил не прошёл проверку: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.before-rules.json"), cur, 0o644); err != nil {
		logf("не удалось сохранить бэкап: %v", err)
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		os.Remove(tmp)
		return false, err
	}
	_ = runQuiet(coreExe(dir), []string{"format", "-c", cfgPath, "-w"}, dir)
	logf("правила вынесены из config.json в папку %s", rulesDir)
	return true, nil
}
