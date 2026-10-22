package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// The shared template: a selector that can only go direct, no servers.
const templateCfg = `{
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["direct"], "default": "direct"},
    {"type": "direct", "tag": "direct"}
  ],
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:7890", "secret": ""}}
}`

func TestCountProxies(t *testing.T) {
	if n := countProxies([]byte(templateCfg)); n != 0 {
		t.Fatalf("template: %d servers, want 0", n)
	}
	full := `{"outbounds": [
		{"type": "selector", "tag": "proxy"}, {"type": "urltest", "tag": "auto"},
		{"type": "vless", "tag": "FI"}, {"type": "socks", "tag": "DE"},
		{"type": "direct", "tag": "direct"}]}`
	if n := countProxies([]byte(full)); n != 2 {
		t.Fatalf("got %d servers, want 2", n)
	}
}

func TestEnsureSecretOnlyFillsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(templateCfg), 0o644)
	logf := func(string, ...any) {}

	if err := ensureSecret(p, logf); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	s := gjson.GetBytes(raw, "experimental.clash_api.secret").String()
	if len(s) != 24 {
		t.Fatalf("secret %q, want 24 hex chars", s)
	}
	if err := ensureSecret(p, logf); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(p)
	if string(again) != string(raw) {
		t.Fatal("a set secret must stay as it is")
	}
}

func TestTaskXMLEscapes(t *testing.T) {
	x := taskXML(`PC\Вася & Co`, `C:\VPN <1>\sing-box-tray.exe`, `C:\VPN <1>`, true)
	for _, want := range []string{
		`<UserId>PC\Вася &amp; Co</UserId>`,
		`<Command>C:\VPN &lt;1&gt;\sing-box-tray.exe</Command>`,
		`<RunLevel>HighestAvailable</RunLevel>`,
		`<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("no %s in the task XML", want)
		}
	}
	if b := utf16LE("ab"); len(b) != 6 || b[0] != 0xFF || b[1] != 0xFE || b[2] != 'a' {
		t.Errorf("utf16LE: % x", b)
	}
}

// Registers a real task through Task Scheduler and removes it again. It
// touches the machine, so it only runs on request:
//
//	set SINGBOX_TASK_TEST=1 && go test -run TestTaskRegisters
//
// LeastPrivilege lets it run without admin; the elevated variant differs in
// that one element only.
func TestTaskRegisters(t *testing.T) {
	if os.Getenv("SINGBOX_TASK_TEST") == "" {
		t.Skip("SINGBOX_TASK_TEST не задан")
	}
	const name = "sing-box tray test task"
	dir := t.TempDir()
	exe := filepath.Join(dir, "sing-box-tray.exe")
	if err := createTask(name, taskXML(currentAccount(), exe, dir, false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer schtasks("/Delete", "/TN", name, "/F")
	if err := schtasks("/Query", "/TN", name); err != nil {
		t.Fatalf("query: %v", err)
	}
	if err := schtasks("/Delete", "/TN", name, "/F"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if schtasks("/Query", "/TN", name) == nil {
		t.Fatal("the task is still there after delete")
	}
}
