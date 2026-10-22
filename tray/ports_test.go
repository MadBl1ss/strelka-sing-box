//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tidwall/gjson"
)

// fixPorts has to move a listener off a port Windows will not let sing-box
// bind. Occupying a port for real is the honest way to simulate that: a
// reserved range and a busy socket both fail the same bind test.
func TestFixPortsMovesBlockedPorts(t *testing.T) {
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	busyPort := blocked.Addr().(*net.TCPAddr).Port

	// Also block the first two fallbacks so the picker has to walk the list.
	var held []net.Listener
	for _, p := range portCandidates[:2] {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			held = append(held, l)
		}
	}
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()

	cfg := fmt.Sprintf(`{
  "log": {"level": "warn"},
  "inbounds": [
    {"type": "tun", "tag": "tun-in"},
    {"type": "mixed", "tag": "wsl-in", "listen_port": %d}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"},
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d", "secret": "x"}}
}`, busyPort, busyPort)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := fixPorts(path, func(f string, a ...any) { t.Logf(f, a...) }); err != nil {
		t.Fatalf("fixPorts: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	ctrl := gjson.GetBytes(got, "experimental.clash_api.external_controller").String()
	_, newCtrlPort, err := net.SplitHostPort(ctrl)
	if err != nil {
		t.Fatalf("контроллер испорчен: %q", ctrl)
	}
	if newCtrlPort == fmt.Sprint(busyPort) {
		t.Errorf("порт панели остался занятым: %s", ctrl)
	}

	wsl := gjson.GetBytes(got, `inbounds.#(tag=="wsl-in").listen_port`).Int()
	if wsl == int64(busyPort) {
		t.Errorf("порт wsl-in остался занятым: %d", wsl)
	}
	if wsl == 0 {
		t.Error("listen_port у wsl-in потерялся")
	}
	if fmt.Sprint(wsl) == newCtrlPort {
		t.Errorf("панели и wsl-in выдан один и тот же порт %d", wsl)
	}

	// The tun inbound has no listen_port and must come through untouched.
	if gjson.GetBytes(got, `inbounds.#(tag=="tun-in").type`).String() != "tun" {
		t.Error("tun-in повреждён")
	}
	if gjson.GetBytes(got, "log.level").String() != "warn" {
		t.Error("остальные секции задеты")
	}
	t.Logf("занятый %d -> панель %s, wsl-in %d", busyPort, newCtrlPort, wsl)
}
