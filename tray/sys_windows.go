package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValue = "sing-box tray"

const (
	coreImage         = "sing-box.exe"
	elevHint          = "Потребуются права администратора"
	autostartLabel    = "Показывать иконку при входе в Windows"
	vpnAutostartLabel = "Включать VPN при входе в Windows"
)

// ---- platform glue used by the portable code ----------------------------

func trayLogPath(dir string) string { return filepath.Join(dir, "sing-box-tray.log") }

func coreExe(dir string) string { return filepath.Join(dir, coreImage) }

func hideWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

// iconBytes: the Win32 tray wants an ICO, not a bare PNG.
func iconBytes(pngData []byte, size int) []byte { return icoWrap(pngData, size) }

func (a *app) restartCore() {
	// Same binary, boot mode: kill stale, refresh the subscription, re-check
	// Windows reserved ports, start detached. Needs admin for the TUN.
	if err := elevate(a.exePath, a.bootArgs(), a.dir); err != nil {
		a.notify("Перезапуск", "Не вышло: "+err.Error())
		return
	}
	a.notify("Перезапуск", "Поднимаю туннель заново...")
}

func (a *app) stopCore() {
	if err := elevate("taskkill.exe", "/F /IM "+coreImage+" /IM "+xrayImage, a.dir); err != nil {
		a.notify("Остановка", "Не вышло: "+err.Error())
		return
	}
	a.notify("Остановка", "Выключаю VPN...")
}

func (a *app) showLog() {
	p := a.logPath
	if st, err := os.Stat(a.errPath); err == nil && st.Size() > 0 {
		p = a.errPath
	}
	_ = openFile(p)
}

func (a *app) openBench() { _ = openURL(filepath.Join(a.dir, "test-servers.bat")) }

// instanceMutex is held for the lifetime of the process; closing it would
// let a second icon start.
var instanceMutex windows.Handle

// singleInstance returns false if another copy already holds the mutex,
// which stops a second icon appearing when the .exe is launched twice.
//
// The already-exists condition has to be read from CreateMutex's own error:
// a separate GetLastError call is unreliable in Go, because the runtime can
// clobber the thread's last error before it is read.
//
// Local\ rather than Global\ so that two signed-in users each get an icon.
func singleInstance() bool {
	name, err := windows.UTF16PtrFromString(`Local\sing-box-vpn-tray`)
	if err != nil {
		return true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if h == 0 {
		return true // cannot tell - better to run than to refuse
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return false
	}
	instanceMutex = h
	return true
}

// findProcess looks for a running image by name and reports when it started,
// which is what separates "VPN is off" from "VPN is up but not answering".
func findProcess(image string) (pid uint32, started time.Time, found bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, time.Time{}, false
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if !strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), image) {
			continue
		}
		pid = e.ProcessID
		found = true
		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
			var c, x, k, u windows.Filetime
			if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
				started = time.Unix(0, c.Nanoseconds())
			}
			windows.CloseHandle(h)
		}
		return pid, started, true
	}
	return 0, time.Time{}, false
}

// elevate re-launches a command through the shell with the "runas" verb,
// which is what raises the UAC prompt. Used only for start/stop/restart -
// everything else the tray does needs no privileges at all.
func elevate(exe, args, cwd string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	f, _ := windows.UTF16PtrFromString(exe)
	var a, d *uint16
	if args != "" {
		a, _ = windows.UTF16PtrFromString(args)
	}
	if cwd != "" {
		d, _ = windows.UTF16PtrFromString(cwd)
	}
	return windows.ShellExecute(0, verb, f, a, d, windows.SW_HIDE)
}

// runHidden runs a command to completion with no console window. Used for
// the things that need no elevation, so nothing flashes on screen.
func runHidden(exe string, args []string, cwd string) error {
	cmd := exec.Command(exe, args...)
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func openURL(u string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	f, _ := windows.UTF16PtrFromString(u)
	return windows.ShellExecute(0, verb, f, nil, nil, windows.SW_SHOWNORMAL)
}

func openFile(path string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	f, _ := windows.UTF16PtrFromString("notepad.exe")
	a, _ := windows.UTF16PtrFromString(`"` + path + `"`)
	return windows.ShellExecute(0, verb, f, a, nil, windows.SW_SHOWNORMAL)
}

// ---- clipboard ---------------------------------------------------------

// setClipboard shells out to the clip.exe that ships with Windows rather
// than driving GlobalAlloc/OpenClipboard by hand: the manual route needs a
// uintptr-to-unsafe.Pointer conversion that go vet flags, and the only
// thing ever copied here is an ASCII hex secret.
func setClipboard(text string) error {
	cmd := exec.Command("clip.exe")
	cmd.Stdin = strings.NewReader(text)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// ---- run at logon ------------------------------------------------------
// A Run key beats a .lnk here: no COM, no shortcut file to go stale if the
// folder moves, and it is trivial to read back for the menu check mark.

func startupEnabled(exe string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runValue)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.Trim(v, `"`), exe)
}

func setStartup(exe string, on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue(runValue)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	return k.SetStringValue(runValue, `"`+exe+`"`)
}
