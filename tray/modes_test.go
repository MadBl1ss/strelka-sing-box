package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tidwall/gjson"
)

// Adds the mode rules to a throwaway copy of the live config and checks
// where they landed. ensureModes itself runs "sing-box check" on the result.
func TestEnsureModesMigratesLiveConfig(t *testing.T) {
	src := resolveDir()
	tmp := t.TempDir()
	for _, n := range []string{"config.json", "xray.json"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Skipf("нет %s: %v", n, err)
		}
		os.WriteFile(filepath.Join(tmp, n), b, 0o644)
	}
	if err := os.Link(filepath.Join(src, "sing-box.exe"), filepath.Join(tmp, "sing-box.exe")); err != nil {
		t.Skipf("не удалось слинковать sing-box.exe: %v", err)
	}
	rs, err := loadRules(src)
	if err != nil {
		t.Skip(err)
	}
	if err := saveRules(tmp, rs); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(filepath.Join(tmp, "config.json"))
	if modesMigrated(cfg) {
		t.Skip("живой конфиг уже с режимами")
	}

	logf := func(f string, v ...any) { t.Logf(f, v...) }
	changed, err := ensureModes(tmp, logf)
	if err != nil || !changed {
		t.Fatalf("ensureModes: changed=%v err=%v", changed, err)
	}
	out, _ := os.ReadFile(filepath.Join(tmp, "config.json"))

	// Route: LAN before every list, Global right after the direct list.
	rules := gjson.GetBytes(out, "route.rules").Array()
	private, direct, global, vpn := -1, -1, -1, -1
	for i, r := range rules {
		switch {
		case r.Get("ip_is_private").Bool():
			private = i
		case hasRuleSet(r, ruleSetDir):
			direct = i
		case r.Get("clash_mode").String() == modeGlobal:
			global = i
		case hasRuleSet(r, ruleSetVPN):
			vpn = i
		}
	}
	if !(private >= 0 && private < direct && direct+1 == global && global < vpn) {
		t.Fatalf("порядок правил: private=%d direct=%d global=%d vpn=%d", private, direct, global, vpn)
	}
	if rules[global].Get("outbound").String() != proxyOutTag {
		t.Fatalf("Global ведёт не в proxy: %s", rules[global].Raw)
	}

	// DNS: server names first via the local resolver, Global after direct-dns.
	dns := gjson.GetBytes(out, "dns.rules").Array()
	if !hasRuleSet(dns[0], serversDNSTag) || dns[0].Get("server").String() != gjson.GetBytes(out, "dns.final").String() {
		t.Fatalf("первое DNS-правило не servers-dns→local: %s", dns[0].Raw)
	}
	gi := -1
	for i, r := range dns {
		if r.Get("clash_mode").String() == modeGlobal {
			gi = i
		}
	}
	if gi < 1 || !hasRuleSet(dns[gi-1], ruleSetDir+"-dns") ||
		dns[gi].Get("server").String() != dnsServerVia(out, proxyOutTag) {
		t.Fatalf("DNS Global не сразу после direct-dns или не через VPN-резолвер (%d)", gi)
	}

	// Every server name is in the file, and no IP slipped in.
	set, err := os.ReadFile(ruleFile(tmp, serversDNSTag))
	if err != nil {
		t.Fatal(err)
	}
	names := gjson.GetBytes(set, "rules.0.domain").Array()
	if len(names) == 0 {
		t.Fatal("servers-dns.json пуст")
	}
	for _, n := range names {
		if net.ParseIP(n.String()) != nil {
			t.Fatalf("IP в списке доменов: %s", n)
		}
	}
	for _, addr := range xrayAddrs(tmp) {
		if net.ParseIP(addr) == nil && !gjson.GetBytes(set, `rules.0.domain.#(=="`+addr+`")`).Exists() {
			t.Fatalf("сервер xray %s не попал в servers-dns", addr)
		}
	}
	t.Logf("в servers-dns %d имён", len(names))

	// Second run: nothing to do.
	if changed, err := ensureModes(tmp, logf); err != nil || changed {
		t.Fatalf("повторный запуск: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "config.before-modes.json")); err != nil {
		t.Fatal("нет бэкапа config.before-modes.json")
	}
}
