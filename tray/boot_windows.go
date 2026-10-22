package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/sys/windows"
)

// Port of autostart.ps1: the elevated half that actually brings the tunnel
// up. Run by the logon task as "sing-box-tray.exe -boot"; it does its work
// and exits, leaving sing-box running. No PowerShell involved.

const bootLogName = "autostart.log"

var portCandidates = []int{7890, 7891, 7892, 3128, 8118, 18080, 20172, 28080, 38080, 48080}

// bootLogger appends to autostart.log, the one log of the elevated side.
func bootLogger(dir string) (logf func(string, ...any), done func()) {
	logPath := filepath.Join(dir, bootLogName)
	if st, err := os.Stat(logPath); err == nil && st.Size() > 200_000 {
		os.Remove(logPath)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	logf = func(format string, a ...any) {
		line := time.Now().Format("2006-01-02 15:04:05") + "  " + fmt.Sprintf(format, a...) + "\r\n"
		if f != nil {
			f.WriteString(line)
		}
	}
	return logf, func() {
		if err == nil {
			f.Close()
		}
	}
}

// runBoot brings the tunnel up. With setup (first run of a fresh copy) it
// also registers the logon task for account, unless one already exists.
func runBoot(dir string, setup bool, account string) int {
	logf, done := bootLogger(dir)
	defer done()
	logf("--- boot ---")

	// Order matters: clear leftovers BEFORE probing ports, or an orphaned
	// core makes its own port look occupied and the config gets rewritten.
	if n := killAll(coreImage) + killAll(xrayImage); n > 0 {
		logf("снял %d зависших процессов sing-box/xray", n)
		time.Sleep(2 * time.Second)
	}

	// Split-routing lists live in rules\*.json. Before the refresh: its
	// "sing-box check" fails on a config that names a missing rule file, and
	// an old config still has the lists inline.
	if _, err := ensureRules(dir, logf); err != nil {
		logf("файлы правил: %v", err)
	}
	if _, err := ensureModes(dir, logf); err != nil {
		logf("режимы: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := ensureSecret(cfgPath, logf); err != nil {
		logf("секрет веб-панели: %v", err)
	}

	// The network is often not up yet right after logon, hence the retries.
	updated := false
	for i := 1; i <= 3; i++ {
		if err := updateSubscriptionFile(dir, logf); err != nil {
			logf("попытка %d не удалась: %v", i, err)
			time.Sleep(10 * time.Second)
			continue
		}
		updated = true
		break
	}
	logf("подписка обработана: %v", updated)

	// A template with no servers would come up "connected" through direct
	// and unblock nothing. Better to stay off and say why.
	if raw, err := os.ReadFile(cfgPath); err == nil && countProxies(raw) == 0 {
		logf("в config.json нет ни одного сервера — проверь ссылку в subscription.txt")
		return 1
	}

	if err := fixPorts(cfgPath, logf); err != nil {
		logf("проверка портов не удалась: %v", err)
	}

	// Xray first, so its ports are open by the time sing-box tests servers.
	// If it fails, only the servers behind it go dark: not a boot failure.
	xrayErr := filepath.Join(dir, "xray-error.log")
	xrayUp := false
	if _, err := os.Stat(filepath.Join(dir, "xray.json")); err == nil && xrayPresent(dir) {
		if err := fixXrayPorts(dir, logf); err != nil {
			logf("проверка портов xray не удалась: %v", err)
		}
		os.Remove(filepath.Join(dir, "xray.log"))
		if pid, err := startDetached(dir, xrayExe(dir), []string{"run", "-c", "xray.json"}, xrayErr); err != nil {
			logf("не удалось запустить xray: %v", err)
		} else {
			logf("xray запущен, pid=%d", pid)
			xrayUp = true
		}
	}

	sbLog := filepath.Join(dir, "sing-box.log")
	errLog := filepath.Join(dir, "sing-box-error.log")
	os.Remove(sbLog)
	os.Remove(errLog)

	proc, err := startDetached(dir, coreExe(dir), []string{"run", "-c", "config.json"}, errLog)
	if err != nil {
		logf("не удалось запустить sing-box: %v", err)
		return 1
	}
	time.Sleep(4 * time.Second)

	if _, _, alive := findProcess(xrayImage); xrayUp && !alive {
		logf("xray сразу завершился, серверы через него не работают. Причина:")
		if b, err := os.ReadFile(xrayErr); err == nil {
			for _, ln := range lastLines(string(b), 5) {
				logf("    %s", ln)
			}
		}
	}
	if _, _, alive := findProcess(coreImage); !alive {
		logf("sing-box сразу завершился, причина:")
		if b, err := os.ReadFile(errLog); err == nil {
			for _, ln := range lastLines(string(b), 5) {
				logf("    %s", ln)
			}
		}
		return 1
	}
	logf("sing-box работает, pid=%d", proc)

	// Only now: a task that brings up a config with no working servers
	// would just repeat the failure at every logon.
	if setup && !logonTaskExists() {
		exe, err := os.Executable()
		if err == nil {
			err = registerLogonTask(exe, dir, account)
		}
		if err != nil {
			logf("автозапуск VPN не настроен: %v", err)
		} else {
			logf("автозапуск VPN настроен для %s", account)
		}
	}
	return 0
}

// ensureSecret gives a fresh copy its own Clash API secret. The shared
// template ships without one so that no two friends end up with the same.
func ensureSecret(cfgPath string, logf func(string, ...any)) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	api := gjson.GetBytes(raw, "experimental.clash_api")
	if !api.Exists() || api.Get("secret").String() != "" {
		return nil
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	out, err := sjson.SetBytes(raw, "experimental.clash_api.secret", hex.EncodeToString(buf))
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, out, 0o644); err != nil {
		return err
	}
	logf("создан секрет веб-панели")
	return nil
}

// fixPorts re-checks every port the config wants to listen on. Windows
// reserves whole TCP ranges for Hyper-V/WinNAT and they move between
// reboots, so a port that worked yesterday can be forbidden today.
func fixPorts(cfgPath string, logf func(string, ...any)) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	dirty := false
	taken := map[int]bool{}

	ctrl := gjson.GetBytes(raw, "experimental.clash_api.external_controller").String()
	if host, portStr, err := net.SplitHostPort(ctrl); err == nil {
		if p, err := parsePort(portStr); err == nil {
			taken[p] = true
			if !portUsable(p) {
				if np := pickPort(taken); np > 0 {
					logf("порт панели %d занят Windows -> %d", p, np)
					raw, _ = sjson.SetBytes(raw, "experimental.clash_api.external_controller",
						net.JoinHostPort(host, fmt.Sprint(np)))
					taken[np] = true
					dirty = true
				}
			}
		}
	}

	gjson.GetBytes(raw, "inbounds").ForEach(func(k, v gjson.Result) bool {
		lp := v.Get("listen_port")
		if !lp.Exists() {
			return true
		}
		p := int(lp.Int())
		taken[p] = true
		if portUsable(p) {
			return true
		}
		if np := pickPort(taken); np > 0 {
			logf("порт %s %d занят Windows -> %d", v.Get("tag").String(), p, np)
			raw, _ = sjson.SetBytes(raw, fmt.Sprintf("inbounds.%d.listen_port", k.Int()), np)
			taken[np] = true
			dirty = true
		}
		return true
	})

	if dirty {
		return os.WriteFile(cfgPath, raw, 0o644)
	}
	return nil
}

// portUsable just tries to bind. That single test covers both "already in
// use" and "inside a Windows reserved range" - the latter fails the bind
// with a permissions error - so no netsh parsing is needed.
func portUsable(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func pickPort(taken map[int]bool) int {
	for _, c := range portCandidates {
		if !taken[c] && portUsable(c) {
			return c
		}
	}
	return 0
}

func parsePort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	return p, err
}

// fixXrayPorts does for xray.json what fixPorts does for config.json. Each
// Xray port is also the server_port of the socks outbound with the same tag
// in config.json, so the two files move together.
func fixXrayPorts(dir string, logf func(string, ...any)) error {
	xPath := filepath.Join(dir, "xray.json")
	cPath := filepath.Join(dir, "config.json")
	xraw, err := os.ReadFile(xPath)
	if err != nil {
		return err
	}
	craw, err := os.ReadFile(cPath)
	if err != nil {
		return err
	}

	taken := listenPorts(craw)
	gjson.GetBytes(xraw, "inbounds.#.port").ForEach(func(_, p gjson.Result) bool {
		taken[int(p.Int())] = true
		return true
	})
	outIdx := map[string]int{}
	gjson.GetBytes(craw, "outbounds").ForEach(func(k, v gjson.Result) bool {
		outIdx[v.Get("tag").String()] = int(k.Int())
		return true
	})

	next := xrayBasePort
	moved := 0
	gjson.GetBytes(xraw, "inbounds").ForEach(func(k, v gjson.Result) bool {
		p := int(v.Get("port").Int())
		if portUsable(p) {
			return true
		}
		for taken[next] || !portUsable(next) {
			next++
			if next > 65000 {
				return false
			}
		}
		tag := strings.TrimPrefix(v.Get("tag").String(), "in-")
		xraw, _ = sjson.SetBytes(xraw, fmt.Sprintf("inbounds.%d.port", k.Int()), next)
		if i, ok := outIdx[tag]; ok {
			craw, _ = sjson.SetBytes(craw, fmt.Sprintf("outbounds.%d.server_port", i), next)
		}
		taken[next] = true
		moved++
		return true
	})
	if moved == 0 {
		return nil
	}
	logf("порты xray заняты Windows: перенёс %d", moved)
	if err := os.WriteFile(xPath, xraw, 0o644); err != nil {
		return err
	}
	return os.WriteFile(cPath, craw, 0o644)
}

// startDetached launches a core (sing-box or xray) detached, with stderr
// captured to a file: early fatals (port bind, TUN creation) never reach
// the configured log.
func startDetached(dir, exe string, args []string, errLog string) (int, error) {
	ef, err := os.Create(errLog)
	if err != nil {
		return 0, err
	}
	defer ef.Close()

	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	cmd.Stderr = ef
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// Release the handle so this process can exit without reaping the child.
	cmd.Process.Release()
	return pid, nil
}

func killAll(image string) int {
	n := 0
	for {
		pid, _, found := findProcess(image)
		if !found {
			return n
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
		if err != nil {
			return n
		}
		windows.TerminateProcess(h, 1)
		windows.CloseHandle(h)
		n++
		if n > 32 { // paranoia: never spin forever
			return n
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func lastLines(s string, n int) []string {
	var out []string
	for _, ln := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}
