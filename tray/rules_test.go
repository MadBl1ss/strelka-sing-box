package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Moves the rules of a throwaway copy of the live config into rule-set files
// and checks that the core accepts the result, that nothing is lost, and that
// the rules which must stay in config.json do stay there.
func TestEnsureRulesMigratesLiveConfig(t *testing.T) {
	src := resolveDir()
	orig, err := os.ReadFile(filepath.Join(src, "config.json"))
	if err != nil {
		t.Skipf("нет config.json: %v", err)
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "config.json"), orig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(src, "sing-box.exe"), filepath.Join(tmp, "sing-box.exe")); err != nil {
		t.Skipf("не удалось слинковать sing-box.exe: %v", err)
	}

	already := rulesMigrated(orig)
	logf := func(f string, v ...any) { t.Logf(f, v...) }
	changed, err := ensureRules(tmp, logf)
	if err != nil {
		t.Fatal(err)
	}
	if changed == already {
		t.Fatalf("changed=%v при уже вынесенных правилах=%v", changed, already)
	}
	out, _ := os.ReadFile(filepath.Join(tmp, "config.json"))
	if !rulesMigrated(out) {
		t.Fatal("в config.json нет rule_set vpn")
	}
	if err := runQuiet(coreExe(tmp), []string{"check", "-c", "config.json"}, tmp); err != nil {
		t.Fatalf("sing-box check: %v", err)
	}

	// Second run is a no-op.
	if changed, err := ensureRules(tmp, logf); err != nil || changed {
		t.Fatalf("повторный запуск: changed=%v err=%v", changed, err)
	}

	route := gjson.GetBytes(out, "route.rules").String()
	for _, keep := range []string{`"xray.exe"`, `"wsl-in"`, `"hijack-dns"`} {
		if !strings.Contains(route, keep) {
			t.Errorf("правило с %s пропало из route.rules", keep)
		}
	}
	for _, gone := range []string{"discord.com", "steamwebhelper.exe"} {
		if strings.Contains(route, gone) || strings.Contains(gjson.GetBytes(out, "dns.rules").String(), gone) {
			t.Errorf("%s остался в config.json", gone)
		}
	}
	// direct must be checked before vpn, or steam.exe would lose to a domain.
	di, vi := -1, -1
	for i, r := range gjson.GetBytes(out, "route.rules").Array() {
		switch r.Get("rule_set").String() {
		case ruleSetDir:
			di = i
		case ruleSetVPN:
			vi = i
		}
	}
	if di < 0 || vi < 0 || di > vi {
		t.Errorf("порядок rule_set в route.rules неверный: %s", route)
	}

	if already {
		return
	}
	rs, err := loadRules(tmp)
	if err != nil {
		t.Fatal(err)
	}
	gjson.GetBytes(orig, "route.rules").ForEach(func(_, r gjson.Result) bool {
		dest, ok := movableRoute(r)
		if !ok {
			return true
		}
		l := rs.list(dest)
		for _, p := range asStrings(r.Get("process_name")) {
			if !slices.Contains(l.Apps, p) {
				t.Errorf("%s: потерялось приложение %s", dest, p)
			}
		}
		for _, d := range asStrings(r.Get("domain_suffix")) {
			if !slices.Contains(l.Domains, d) {
				t.Errorf("%s: потерялся домен %s", dest, d)
			}
		}
		for _, ip := range asStrings(r.Get("ip_cidr")) {
			if !slices.Contains(l.IPs, ip) {
				t.Errorf("%s: потерялась подсеть %s", dest, ip)
			}
		}
		return true
	})

	// The DNS file must never carry IPs (see the note at the top of rules.go).
	dns, _ := os.ReadFile(ruleFile(tmp, ruleSetVPN+"-dns"))
	if strings.Contains(string(dns), "ip_cidr") || strings.Contains(string(dns), "process_name") {
		t.Errorf("vpn-dns.json содержит не только домены: %s", dns)
	}
}

func TestNormalizeRule(t *testing.T) {
	cases := []struct{ kind, in, wantKind, want string }{
		{"auto", "steam.exe", "app", "steam.exe"},
		{"auto", `C:\Program Files (x86)\Steam\steam.exe`, "app", "steam.exe"},
		{"auto", "https://Store.SteamPowered.com/app/570/", "domain", "store.steampowered.com"},
		{"auto", "*.youtube.com", "domain", "youtube.com"},
		{"auto", "https://www.Example.org/some/path", "domain", "example.org"},
		{"domain", "www.com", "domain", "www.com"},
		{"auto", ".googlevideo.com", "domain", "googlevideo.com"},
		{"auto", "91.108.4.1", "ip", "91.108.4.1/32"},
		{"auto", "91.108.4.7/22", "ip", "91.108.4.0/22"},
		{"auto", "2001:db8::1", "ip", "2001:db8::1/128"},
		{"app", "Discord", "app", "Discord.exe"},
		{"keyword", "Telegram", "keyword", "telegram"},
	}
	for _, c := range cases {
		k, v, err := normalizeRule(c.kind, c.in)
		if err != nil || k != c.wantKind || v != c.want {
			t.Errorf("normalizeRule(%q, %q) = %q, %q, %v; want %q, %q", c.kind, c.in, k, v, err, c.wantKind, c.want)
		}
	}
	for _, bad := range []struct{ kind, in string }{
		{"auto", ""}, {"domain", "localhost"}, {"ip", "300.1.1.1"}, {"app", "a:b.exe"}, {"nope", "x"},
	} {
		if _, _, err := normalizeRule(bad.kind, bad.in); err == nil {
			t.Errorf("normalizeRule(%q, %q) должен был отказать", bad.kind, bad.in)
		}
	}
}

func TestRulesRoundTripAndMove(t *testing.T) {
	dir := t.TempDir()
	var s ruleState
	s.addRule(ruleSetVPN, "app", "steamwebhelper.exe")
	s.addRule(ruleSetVPN, "domain", "steamcommunity.com")
	s.addRule(ruleSetVPN, "ip", "91.108.0.0/16")
	s.addRule(ruleSetDir, "app", "steam.exe")
	// Adding to the other side moves it.
	s.addRule(ruleSetDir, "domain", "steamcommunity.com")
	if slices.Contains(s.VPN.Domains, "steamcommunity.com") || !slices.Contains(s.Direct.Domains, "steamcommunity.com") {
		t.Fatalf("домен не переехал: %+v", s)
	}
	s.addRule(ruleSetVPN, "domain", "steamcommunity.com")

	if err := saveRules(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.VPN.Apps, []string{"steamwebhelper.exe"}) ||
		!slices.Equal(got.VPN.Domains, []string{"steamcommunity.com"}) ||
		!slices.Equal(got.VPN.IPs, []string{"91.108.0.0/16"}) ||
		!slices.Equal(got.Direct.Apps, []string{"steam.exe"}) ||
		len(got.Direct.Domains) != 0 {
		t.Fatalf("после сохранения и чтения: %+v", got)
	}

	// Apps and domains must be separate headless rules: in one rule sing-box
	// ANDs them, so nothing would ever match.
	raw, _ := os.ReadFile(ruleFile(dir, ruleSetVPN))
	for _, r := range gjson.GetBytes(raw, "rules").Array() {
		if r.Get("process_name").Exists() && r.Get("domain_suffix").Exists() {
			t.Fatalf("process_name и domain_suffix в одном правиле: %s", raw)
		}
	}

	got.removeRule(ruleSetVPN, "app", "steamwebhelper.exe")
	if len(got.VPN.Apps) != 0 {
		t.Fatalf("не удалилось: %+v", got.VPN.Apps)
	}
}
