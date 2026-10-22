package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
)

// First run and the logon task.
//
// A freshly unpacked folder has a template config.json with no servers. The
// tray then walks the user through setup by itself: with no link it opens
// subscription.txt in Notepad and waits for it to be saved; with a link it
// asks for admin once and runs "-boot -setup", which fetches the servers,
// brings the tunnel up and registers the logon task. So a friend only has to
// paste a link and start the .exe.

const taskName = "sing-box VPN autostart"

// setupRetryGap keeps a burst of Ctrl+S in Notepad from raising one UAC
// prompt per save.
const (
	setupWait     = 90 * time.Second
	setupRetryGap = 15 * time.Second
)

type firstRun struct {
	active bool
	asked  bool      // subscription.txt was opened in Notepad
	subMod time.Time // subscription.txt as of the last attempt
	tried  time.Time // when the last attempt started; zero before the first
	warned bool      // the "no servers came back" notice was shown
}

// firstRunStep runs on every tick while the config has no servers.
func (a *app) firstRunStep() {
	f := &a.setup
	if a.conf.proxies > 0 {
		f.active = false
		log.Print("first run: servers are in, setup done")
		return
	}

	subPath := filepath.Join(a.dir, "subscription.txt")
	var mod time.Time
	link := false
	if st, err := os.Stat(subPath); err == nil {
		mod = st.ModTime()
		if b, err := os.ReadFile(subPath); err == nil {
			link = len(parseSubscriptions(string(b))) > 0
		}
	}

	if !link {
		if !f.asked {
			f.asked = true
			a.notify("Нужна ссылка на подписку",
				"Вставь её в открывшийся subscription.txt и сохрани (Ctrl+S) — VPN включится сам.")
			_ = openFile(subPath)
		}
		return
	}

	if !f.tried.IsZero() {
		if mod.Equal(f.subMod) {
			if !f.warned && time.Since(f.tried) > setupWait {
				f.warned = true
				a.notify("Серверы не получены",
					"По ссылке из subscription.txt ничего не скачалось. Проверь ссылку и сохрани файл — попробую снова.")
			}
			return
		}
		if time.Since(f.tried) < setupRetryGap {
			return
		}
	}
	f.tried, f.subMod, f.warned = time.Now(), mod, false

	if !startupEnabled(a.exePath) {
		if err := setStartup(a.exePath, true); err == nil {
			a.miAuto.Check()
		}
	}
	log.Print("first run: link found, starting -boot -setup")
	if err := elevate(a.exePath, a.bootArgs(), a.dir); err != nil {
		a.notify("Нужны права администратора",
			"Без них VPN не включится. Нажми «Запустить VPN» в меню у щита и согласись.")
		return
	}
	a.notify("Первый запуск", "Скачиваю серверы и подключаюсь, это займёт до минуты.")
}

// bootArgs is what restartCore elevates. Until the first setup has gone
// through, every start also registers the logon task.
func (a *app) bootArgs() string {
	if !a.setup.active {
		return "-boot"
	}
	return "-boot -setup -user " + quoteArg(currentAccount())
}

func (a *app) toggleVPNAutostart() {
	want := !a.miVPNAuto.Checked()
	mode := "off"
	if want {
		mode = "on"
	}
	if err := elevate(a.exePath, "-autostart "+mode+" -user "+quoteArg(currentAccount()), a.dir); err != nil {
		a.notify("Автозапуск VPN", "Не вышло: "+err.Error())
		return
	}
	// elevate does not wait for the elevated process, so watch the result.
	go func() {
		for i := 0; i < 20; i++ {
			time.Sleep(time.Second)
			if logonTaskExists() != want {
				continue
			}
			if want {
				a.miVPNAuto.Check()
				a.notify("Автозапуск VPN", "Включён: VPN будет подниматься сам при входе в Windows.")
			} else {
				a.miVPNAuto.Uncheck()
				a.notify("Автозапуск VPN", "Выключен.")
			}
			return
		}
		a.notify("Автозапуск VPN", "Не получилось, подробности в autostart.log")
	}()
}

// runAutostart is the elevated half of the menu toggle ("-autostart on|off").
func runAutostart(dir, mode, account string) int {
	logf, done := bootLogger(dir)
	defer done()
	exe, err := os.Executable()
	if err != nil {
		logf("автозапуск: %v", err)
		return 1
	}
	switch mode {
	case "on":
		err = registerLogonTask(exe, dir, account)
	case "off":
		err = removeLogonTask()
	default:
		err = fmt.Errorf("неизвестный режим %q, нужно on или off", mode)
	}
	if err != nil {
		logf("автозапуск %s: %v", mode, err)
		return 1
	}
	logf("автозапуск VPN: %s", mode)
	return 0
}

// ---- the scheduled task --------------------------------------------------

// logonTaskExists needs no admin: reading a task in the root folder is open
// to its owner.
func logonTaskExists() bool {
	return schtasks("/Query", "/TN", taskName) == nil
}

func removeLogonTask() error {
	if !logonTaskExists() {
		return nil
	}
	return schtasks("/Delete", "/TN", taskName, "/F")
}

// registerLogonTask goes through an XML definition because plain schtasks
// flags cannot clear "start only on AC power": on a laptop the VPN would
// silently not start on battery.
func registerLogonTask(exe, dir, account string) error {
	return createTask(taskName, taskXML(account, exe, dir, true))
}

func createTask(name, def string) error {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("sing-box-task-%d.xml", os.Getpid()))
	if err := os.WriteFile(tmp, utf16LE(def), 0o644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	return schtasks("/Create", "/TN", name, "/XML", tmp, "/F")
}

// taskXML: run "<exe> -boot" 20 s after this account logs on (the network
// is rarely up the instant the desktop appears), elevated, with no time
// limit and regardless of battery. highest=false exists for the test, which
// cannot register an elevated task without admin.
func taskXML(account, exe, dir string, highest bool) string {
	level := "LeastPrivilege"
	if highest {
		level = "HighestAvailable"
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Поднимает VPN (sing-box) при входе в Windows</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlText(account) + `</UserId>
      <Delay>PT20S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlText(account) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>` + level + `</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlText(exe) + `</Command>
      <Arguments>-boot</Arguments>
      <WorkingDirectory>` + xmlText(dir) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
}

func schtasks(args ...string) error {
	cmd := exec.Command("schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// currentAccount is "DOMAIN\user". It is passed to the elevated process on
// purpose: when a standard user elevates with someone else's admin password,
// the elevated side runs as that admin, and the task must still be bound to
// the person actually sitting at the machine.
func currentAccount() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
}

func quoteArg(s string) string { return `"` + s + `"` }

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// utf16LE is what Task Scheduler reliably accepts for an XML that declares
// encoding="UTF-16": little-endian with a BOM.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2+2*len(u))
	out[0], out[1] = 0xFF, 0xFE
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2+2*i:], c)
	}
	return out
}
