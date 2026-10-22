package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tidwall/gjson"
)

// Runs the real subscription refresh against a throwaway copy of the live
// config and checks two things: the core accepts the result, and every
// section other than "outbounds" comes out byte-identical.
func TestUpdateSubscriptionPreservesEverythingElse(t *testing.T) {
	src := resolveDir()
	orig, err := os.ReadFile(filepath.Join(src, "config.json"))
	if err != nil {
		t.Skipf("нет config.json: %v", err)
	}

	tmp := t.TempDir()
	// hwid.txt too: without it the copy would mint a new device id and take
	// another slot on every device-limited panel.
	for _, n := range []string{"config.json", "subscription.txt", "hwid.txt"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Skipf("нет %s: %v", n, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The updater runs the sing-box.exe next to the config.
	// Hardlink rather than copy: it is 80 MB.
	if err := os.Link(filepath.Join(src, "sing-box.exe"), filepath.Join(tmp, "sing-box.exe")); err != nil {
		t.Skipf("не удалось слинковать sing-box.exe: %v", err)
	}
	withXray := os.Link(filepath.Join(src, xrayImage), filepath.Join(tmp, xrayImage)) == nil
	// The config names rules\*.json; "sing-box check" fails without them.
	if rs, err := loadRules(src); err == nil {
		if err := saveRules(tmp, rs); err != nil {
			t.Fatal(err)
		}
	}

	var lines []string
	if err := updateSubscriptionFile(tmp, func(f string, a ...any) {
		lines = append(lines, f)
		t.Logf(f, a...)
	}); err != nil {
		t.Fatalf("обновление упало: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(tmp, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Sections the updater must never touch.
	for _, sec := range []string{"log", "dns", "inbounds", "route", "experimental"} {
		before := gjson.GetBytes(orig, sec).String()
		after := gjson.GetBytes(got, sec).String()
		if before != after {
			t.Errorf("секция %q изменилась!\nбыло : %.400s\nстало: %.400s", sec, before, after)
		}
	}

	outs := gjson.GetBytes(got, "outbounds").Array()
	if len(outs) < 3 {
		t.Fatalf("в outbounds всего %d элементов", len(outs))
	}
	if outs[0].Get("type").String() != "selector" {
		t.Errorf("первым должен идти selector, а там %q", outs[0].Get("type").String())
	}
	if outs[len(outs)-1].Get("type").String() != "direct" {
		t.Errorf("последним должен идти direct, а там %q", outs[len(outs)-1].Get("type").String())
	}

	def := outs[0].Get("default").String()
	inList := false
	for _, tag := range outs[0].Get("outbounds").Array() {
		if tag.String() == def {
			inList = true
		}
	}
	if !inList {
		t.Errorf("default=%q отсутствует в списке селектора", def)
	}

	prevDef := gjson.GetBytes(orig, `outbounds.#(type=="selector").default`).String()
	t.Logf("серверов: %d, default было %q стало %q", len(outs)-3, prevDef, def)

	auto := outs[1]
	if auto.Get("type").String() != "urltest" || auto.Get("tag").String() != autoTag {
		t.Fatalf("вторым должен идти urltest %q, а там %.200s", autoTag, auto.String())
	}
	if outs[0].Get("outbounds.0").String() != autoTag {
		t.Errorf("%q должен стоять первым в селекторе", autoTag)
	}

	servers := map[string]bool{}
	for i, o := range outs[2 : len(outs)-1] {
		servers[o.Get("tag").String()] = true
		// Each protocol has its own credential field; an Xray server keeps
		// its credentials in xray.json.
		cred := o.Get("uuid").String() + o.Get("password").String()
		if o.Get("tag").String() == "" || o.Get("server").String() == "" || (cred == "" && o.Get("type").String() != "socks") {
			t.Errorf("сервер #%d неполный: %.200s", i, o.String())
		}
	}
	for _, tag := range auto.Get("outbounds").Array() {
		if !servers[tag.String()] {
			t.Errorf("в auto есть %q, которого нет среди серверов", tag.String())
		}
	}
	t.Logf("в auto: %d из %d", len(auto.Get("outbounds").Array()), len(servers))

	// Every socks outbound must land on the Xray inbound of the same server.
	xraw, err := os.ReadFile(filepath.Join(tmp, "xray.json"))
	if !withXray {
		if err == nil {
			t.Error("xray.exe нет, а xray.json появился")
		}
		return
	}
	if err != nil {
		t.Fatalf("xray.exe есть, а xray.json не создан: %v", err)
	}
	socks := 0
	for _, o := range outs {
		if o.Get("type").String() != "socks" {
			continue
		}
		socks++
		tag := o.Get("tag").String()
		in := gjson.GetBytes(xraw, `inbounds.#(tag=="in-`+tag+`")`)
		if !in.Exists() || in.Get("port").Int() != o.Get("server_port").Int() {
			t.Errorf("%s: порт в config.json %d, в xray.json %s", tag, o.Get("server_port").Int(), in.Get("port").Raw)
		}
		if !gjson.GetBytes(xraw, `outbounds.#(tag=="`+tag+`")`).Exists() {
			t.Errorf("%s: нет outbound в xray.json", tag)
		}
	}
	if n := len(gjson.GetBytes(xraw, "inbounds").Array()); n != socks {
		t.Errorf("socks-выходов %d, а входов xray %d", socks, n)
	}
	t.Logf("через xray: %d", socks)

	if _, err := os.Stat(filepath.Join(tmp, "config.bak.json")); err != nil {
		t.Errorf("бэкап не создан: %v", err)
	}
}
