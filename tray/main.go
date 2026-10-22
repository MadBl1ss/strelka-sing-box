// vpn-tray is a status indicator for sing-box.
//
// It deliberately does not own the core: sing-box is started by the logon
// task and keeps running when this icon is closed. Everything here goes
// through the Clash API on loopback, so the tray itself needs no privileges.
// Only start/stop/restart elevate, and only when clicked.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/gen2brain/beeep"
)

const (
	pollEvery = 3 * time.Second
	pingEvery = 15 * time.Second
)

var (
	selfTest   = flag.Bool("selftest", false, "poll once, print what the tray would show, exit")
	bootMode   = flag.Bool("boot", false, "bring the tunnel up and exit; run elevated by the logon task")
	updateOnly = flag.Bool("update", false, "refresh the server list from subscription.txt and exit")
	dirFlag    = flag.String("dir", "", "folder holding config.json (default: found automatically)")
	setupFlag  = flag.Bool("setup", false, "with -boot: first run, also register the logon task")
	autoFlag   = flag.String("autostart", "", "on|off: register or remove the logon task and exit; needs admin")
	userFlag   = flag.String("user", "", "account the logon task is for (default: the current one)")
)

// resolveDir finds the folder holding config.json. The binary normally sits
// next to it, but during development it is built into tray\.
func resolveDir() string {
	if *dirFlag != "" {
		return *dirFlag
	}
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		return dir
	}
	if wd, err := os.Getwd(); err == nil {
		for _, c := range []string{wd, filepath.Dir(wd)} {
			if _, err := os.Stat(filepath.Join(c, "config.json")); err == nil {
				return c
			}
		}
	}
	return dir
}

type app struct {
	dir     string
	exePath string
	cfgPath string
	logPath string
	errPath string

	conf   *cfg
	cl     *client
	cfgMod time.Time // config.json as last loaded
	setup  firstRun

	mu        sync.RWMutex
	snap      snapshot
	prevState string
	lastPing  time.Time

	miStatus  *systray.MenuItem
	miTraffic *systray.MenuItem
	miConns   *systray.MenuItem
	miUptime  *systray.MenuItem
	miPower   *systray.MenuItem
	miAuto    *systray.MenuItem
	miVPNAuto *systray.MenuItem
	miRule    *systray.MenuItem
	miGlobal  *systray.MenuItem
	miSrv     *systray.MenuItem
	miNoSrv   *systray.MenuItem
	srvItems  map[string]*systray.MenuItem

	// last values pushed into the menu, so ticks that change nothing are free
	txtStatus   string
	txtTraffic  string
	txtConns    string
	txtUptime   string
	txtPower    string
	checkedTag  string
	checkedMode string
	rowsShown   bool

	// pendingMode is applied once a restarted core knows it (see setMode).
	pendingMode string

	rulesOnce sync.Once
	rules     *rulesServer
}

func main() {
	flag.Parse()

	// Boot mode is the elevated half: no icon, no config parsing up front,
	// because part of its job is to repair the config.
	if *bootMode {
		os.Exit(runBoot(resolveDir(), *setupFlag, account()))
	}
	if *autoFlag != "" {
		os.Exit(runAutostart(resolveDir(), *autoFlag, account()))
	}

	// Refresh only: no icon, no elevation. Handy from a script, and it makes
	// the first-run path testable without bringing the tunnel up.
	if *updateOnly {
		if err := updateSubscriptionFile(resolveDir(), func(f string, v ...any) {
			fmt.Printf(f+"\n", v...)
		}); err != nil {
			fmt.Println("ошибка:", err)
			os.Exit(1)
		}
		return
	}

	a := &app{}
	if err := a.init(); err != nil {
		fatal(err)
	}
	if *selfTest {
		a.runSelfTest()
		return
	}
	if !singleInstance() {
		return // another icon is already up
	}
	systray.Run(a.onReady, func() {})
}

// account is the logon task's owner: the -user the tray passed along, or
// whoever runs this.
func account() string {
	if *userFlag != "" {
		return *userFlag
	}
	return currentAccount()
}

func (a *app) init() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	a.exePath = exe
	a.dir = resolveDir()
	a.cfgPath = filepath.Join(a.dir, "config.json")
	a.logPath = filepath.Join(a.dir, "sing-box.log")
	a.errPath = filepath.Join(a.dir, "sing-box-error.log")

	if !*selfTest {
		if f, err := os.OpenFile(trayLogPath(a.dir),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			log.SetOutput(f)
		}
	}
	log.SetFlags(log.Ltime)

	if st, err := os.Stat(a.cfgPath); err == nil {
		a.cfgMod = st.ModTime()
	}
	conf, err := loadConfig(a.cfgPath)
	if err != nil {
		return fmt.Errorf("%s: %w", a.cfgPath, err)
	}
	a.conf = conf
	a.cl = newClient(conf)
	a.srvItems = map[string]*systray.MenuItem{}
	a.setup.active = conf.proxies == 0
	return nil
}

// reloadConfig picks config.json up again when something else rewrote it:
// the boot (new servers, a moved port, a fresh secret), the updater, the
// server test. A half-written file fails to parse and is retried next tick.
func (a *app) reloadConfig() {
	st, err := os.Stat(a.cfgPath)
	if err != nil || st.ModTime().Equal(a.cfgMod) {
		return
	}
	conf, err := loadConfig(a.cfgPath)
	if err != nil {
		log.Printf("reload config: %v", err)
		return
	}
	a.cfgMod = st.ModTime()
	a.conf = conf
	a.cl = newClient(conf)
	a.syncServers()
}

// syncServers makes the server submenu match a.conf. systray cannot delete
// items, so a server that left the list is hidden, and shown again if it
// comes back.
func (a *app) syncServers() {
	want := map[string]bool{}
	for _, s := range a.conf.servers {
		want[s.Tag] = true
		label := s.Tag
		if s.Addr != "" {
			label += "   " + s.Addr
		}
		if it, ok := a.srvItems[s.Tag]; ok {
			it.SetTitle(label)
			it.Show()
			continue
		}
		it := a.miSrv.AddSubMenuItemCheckbox(label, s.Addr, false)
		a.srvItems[s.Tag] = it
		tag := s.Tag
		on(it, func() { a.switchServer(tag) })
	}
	for tag, it := range a.srvItems {
		if !want[tag] {
			it.Hide()
		}
	}
	if len(a.conf.servers) == 0 {
		a.miNoSrv.Show()
	} else {
		a.miNoSrv.Hide()
	}
	a.checkedTag = "" // the next tick re-applies the check mark
}

func fatal(err error) {
	log.Printf("fatal: %v", err)
	_ = beeep.Notify("sing-box tray", "Не удалось запустить: "+err.Error(), "")
	os.Exit(1)
}

// ---- polling -----------------------------------------------------------

func (a *app) poll() snapshot {
	var s snapshot

	_, started, found := findProcess(coreImage)
	if !found {
		s.state = "off"
		s.now = "-"
		return s
	}
	s.since, s.sinceSet = started, !started.IsZero()

	now, _, err := a.cl.selected(a.conf.selector)
	if err != nil {
		// Process is up but the API is silent: still booting, or it bound a
		// port it was not allowed to and is on its way out.
		s.state = "error"
		s.now = "?"
		return s
	}
	s.now = now
	s.leaf = a.cl.leaf(now)
	if m, list, err := a.cl.mode(); err == nil {
		s.mode, s.modes = m, list
	}

	if d, u, total, via, err := a.cl.traffic(); err == nil {
		s.down, s.up, s.conns, s.viaVPN = d, u, total, via
	}

	a.mu.RLock()
	prev := a.snap
	last := a.lastPing
	a.mu.RUnlock()

	if time.Since(last) >= pingEvery || prev.leaf != s.leaf {
		a.mu.Lock()
		a.lastPing = time.Now()
		a.mu.Unlock()
		if ms, err := a.cl.delay(s.leaf); err == nil {
			s.ping, s.pingOK = ms, true
		}
	} else {
		s.ping, s.pingOK = prev.ping, prev.pingOK
	}

	if s.pingOK {
		s.state = "ok"
	} else {
		s.state = "warn"
	}
	return s
}

// ---- formatting (shared by the menu and the self-test) -----------------

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f МБ", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f КБ", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d Б", b)
}

// serverName is the selection as the user sees it: "auto → lider-DE" when a
// group picked the server, the bare tag otherwise.
func serverName(s snapshot) string {
	if s.leaf != "" && s.leaf != s.now {
		return s.now + " → " + s.leaf
	}
	return s.now
}

func statusLine(s snapshot) string {
	switch s.state {
	case "ok":
		line := fmt.Sprintf("Подключено — %s — %d мс", serverName(s), s.ping)
		if strings.EqualFold(s.mode, modeGlobal) {
			line += " — весь трафик"
		}
		return line
	case "warn":
		return fmt.Sprintf("%s не отвечает", serverName(s))
	case "error":
		return "sing-box не отвечает"
	}
	return "VPN выключен"
}

func trafficLine(s snapshot) string {
	return fmt.Sprintf("%s вниз / %s вверх", fmtBytes(s.down), fmtBytes(s.up))
}

func connsLine(s snapshot) string {
	return fmt.Sprintf("%d соединений, %d через VPN", s.conns, s.viaVPN)
}

func uptimeLine(s snapshot) string {
	if !s.sinceSet {
		return "работает —"
	}
	d := time.Since(s.since).Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	return fmt.Sprintf("работает %02d:%02d:%02d", h, m, sec)
}

func tooltip(s snapshot) string {
	t := "sing-box — " + statusLine(s)
	if s.state == "ok" {
		t += fmt.Sprintf("\n%s вниз, %d через VPN", fmtBytes(s.down), s.viaVPN)
	}
	// NOTIFYICONDATA caps the tip; stay well under it.
	if len([]rune(t)) > 110 {
		t = string([]rune(t)[:110])
	}
	return t
}

// ---- tray --------------------------------------------------------------

func (a *app) onReady() {
	systray.SetIcon(icons["off"])
	systray.SetTitle("sing-box")
	systray.SetTooltip("sing-box — запуск...")

	a.miStatus = systray.AddMenuItem("Проверяю...", "")
	a.miStatus.Disable()
	a.miTraffic = systray.AddMenuItem("", "")
	a.miTraffic.Disable()
	a.miConns = systray.AddMenuItem("", "")
	a.miConns.Disable()
	a.miUptime = systray.AddMenuItem("", "")
	a.miUptime.Disable()

	systray.AddSeparator()

	a.miSrv = systray.AddMenuItem("Сервер", "Выбрать сервер")
	a.miNoSrv = a.miSrv.AddSubMenuItem("пока пусто: нужна ссылка в subscription.txt", "")
	a.miNoSrv.Disable()
	a.syncServers()

	a.miRule = systray.AddMenuItemCheckbox("Через VPN только программы и сайты из списка", "", true)
	a.miGlobal = systray.AddMenuItemCheckbox("Через VPN весь трафик", "Кроме списка «напрямую» и локальной сети", false)
	on(a.miRule, func() { a.setMode(modeRule) })
	on(a.miGlobal, func() { a.setMode(modeGlobal) })

	miTest := systray.AddMenuItem("Тест серверов (пинг и скорость)", "")
	miUpd := systray.AddMenuItem("Обновить подписку", "")
	systray.AddSeparator()
	miRules := systray.AddMenuItem("Правила маршрутизации…", "Какие программы и сайты идут через VPN")
	miPanel := systray.AddMenuItem("Открыть веб-панель", "")
	miLog := systray.AddMenuItem("Показать лог", "")
	systray.AddSeparator()
	miRestart := systray.AddMenuItem("Перезапустить VPN", elevHint)
	a.miPower = systray.AddMenuItem("Остановить VPN", elevHint)
	systray.AddSeparator()
	a.miVPNAuto = systray.AddMenuItemCheckbox(vpnAutostartLabel, elevHint, logonTaskExists())
	a.miAuto = systray.AddMenuItemCheckbox(autostartLabel, "", startupEnabled(a.exePath))
	systray.AddSeparator()
	miQuit := systray.AddMenuItem("Закрыть иконку (VPN останется работать)", "")

	on(miTest, a.openBench)
	on(miUpd, a.updateSubscription)
	on(miRules, a.openRules)
	on(miPanel, a.openPanel)
	on(miLog, a.showLog)
	on(miRestart, a.restartCore)
	on(a.miPower, func() {
		a.mu.RLock()
		off := a.snap.state == "off"
		a.mu.RUnlock()
		if off {
			a.restartCore()
		} else {
			a.stopCore()
		}
	})
	on(a.miVPNAuto, a.toggleVPNAutostart)
	on(a.miAuto, func() {
		want := !a.miAuto.Checked()
		if err := setStartup(a.exePath, want); err != nil {
			a.notify("Автозапуск", "Не вышло: "+err.Error())
			return
		}
		if want {
			a.miAuto.Check()
			a.notify("Автозапуск иконки", "Включён.")
		} else {
			a.miAuto.Uncheck()
			a.notify("Автозапуск иконки", "Выключен.")
		}
	})
	on(miQuit, func() { systray.Quit() })

	systray.SetOnTapped(a.openPanel)

	log.Print("--- tray started ---")
	go a.loop()
}

// setTitle pushes text to a menu item only when it differs from what is
// already there.
func setTitle(it *systray.MenuItem, cur *string, text string) {
	if *cur == text {
		return
	}
	*cur = text
	it.SetTitle(text)
}

// on wires a menu item to an action. One goroutine per item is the shape
// systray expects; they live as long as the tray does.
func on(item *systray.MenuItem, f func()) {
	go func() {
		for range item.ClickedCh {
			f()
		}
	}()
}

func (a *app) loop() {
	a.tick()
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for range t.C {
		a.tick()
	}
}

func (a *app) tick() {
	a.reloadConfig()
	s := a.poll()

	a.mu.Lock()
	prev := a.prevState
	a.snap = s
	a.prevState = s.state
	a.mu.Unlock()

	// Only on change: every SetIcon rebuilds an HICON, and this runs every
	// few seconds for as long as the machine is on.
	if s.state != prev {
		systray.SetIcon(icons[s.state])
	}
	systray.SetTooltip(tooltip(s))

	// Every one of these is a Win32 menu call, and tick runs forever - so
	// touch a menu item only when its text or state actually differs.
	setTitle(a.miStatus, &a.txtStatus, statusLine(s))

	show := s.state == "ok" || s.state == "warn"
	if show != a.rowsShown {
		a.rowsShown = show
		for _, it := range []*systray.MenuItem{a.miTraffic, a.miConns, a.miUptime} {
			if show {
				it.Show()
			} else {
				it.Hide()
			}
		}
	}
	if show {
		setTitle(a.miTraffic, &a.txtTraffic, trafficLine(s))
		setTitle(a.miConns, &a.txtConns, connsLine(s))
		setTitle(a.miUptime, &a.txtUptime, uptimeLine(s))
	}

	if s.now != a.checkedTag {
		a.checkedTag = s.now
		for tag, it := range a.srvItems {
			if tag == s.now {
				it.Check()
			} else {
				it.Uncheck()
			}
		}
	}

	power := "Остановить VPN"
	if s.state == "off" {
		power = "Запустить VPN"
	}
	setTitle(a.miPower, &a.txtPower, power)

	if s.mode != "" && s.mode != a.checkedMode {
		a.checkedMode = s.mode
		if strings.EqualFold(s.mode, modeGlobal) {
			a.miGlobal.Check()
			a.miRule.Uncheck()
		} else {
			a.miRule.Check()
			a.miGlobal.Uncheck()
		}
	}
	a.applyPendingMode(s)

	if prev != "" && prev != s.state {
		switch s.state {
		case "ok":
			a.notify("VPN подключен", fmt.Sprintf("Сервер %s, пинг %d мс", serverName(s), s.ping))
		case "warn":
			a.notify("Сервер не отвечает", serverName(s)+" не даёт пинг. Смени сервер через меню.")
		case "off":
			a.notify("VPN выключен", "sing-box не запущен.")
		case "error":
			a.notify("Проблема с VPN", "sing-box запущен, но не отвечает.")
		}
	}
	if prev != s.state {
		log.Printf("state: %s -> %s", prev, s.state)
	}

	if a.setup.active {
		a.firstRunStep()
	}
}

func (a *app) notify(title, body string) {
	if err := beeep.Notify(title, body, ""); err != nil {
		log.Printf("notify: %v", err)
	}
}

// ---- actions -----------------------------------------------------------

func (a *app) switchServer(tag string) {
	if err := a.cl.switchTo(a.conf.selector, tag); err != nil {
		a.notify("Не переключилось", err.Error())
		return
	}
	// The API switch is runtime only and sing-box 1.14 has no store_selected,
	// so pin it on disk as well or a restart would revert the choice.
	if err := pinDefault(a.cfgPath, a.conf, tag); err != nil {
		log.Printf("pin default: %v", err)
	}
	a.mu.Lock()
	a.lastPing = time.Time{}
	a.mu.Unlock()
	log.Printf("switched to %s", tag)
	a.tick()
}

func (a *app) openPanel() {
	if a.conf.secret != "" {
		if err := setClipboard(a.conf.secret); err == nil {
			a.notify("Веб-панель", "Секрет скопирован в буфер — вставь в поле Secret.")
		}
	}
	_ = openURL("http://" + a.conf.controller + "/ui/")
}

// setMode switches between "only the list" and "everything" on the running
// core: no restart, no admin. A core started from a config that predates the
// modes does not know them; then the config gets them, the core restarts and
// applyPendingMode finishes the switch.
func (a *app) setMode(m string) {
	a.mu.RLock()
	s := a.snap
	a.mu.RUnlock()
	a.checkedMode = "" // undo the click's own toggle on the next tick

	if s.state == "off" {
		a.notify("Режим", "Сначала включи VPN: режим переключается на работающем VPN.")
		return
	}
	if !containsFold(s.modes, m) {
		if _, err := ensureModes(a.dir, func(f string, v ...any) { log.Printf(f, v...) }); err != nil {
			a.notify("Режим", "Не вышло: "+err.Error())
			return
		}
		a.mu.Lock()
		a.pendingMode = m
		a.mu.Unlock()
		a.notify("Режим", "Нужен один перезапуск VPN, дальше режимы переключаются мгновенно.")
		a.restartCore()
		return
	}
	if err := a.cl.setMode(m); err != nil {
		a.notify("Режим", "Не переключилось: "+err.Error())
		return
	}
	if err := a.cl.closeAll(); err != nil {
		log.Printf("close connections: %v", err)
	}
	log.Printf("mode -> %s", m)
	a.notify("Режим", "Теперь "+modeTitle(m)+".")
	a.tick()
}

func (a *app) applyPendingMode(s snapshot) {
	a.mu.Lock()
	m := a.pendingMode
	if m == "" || !containsFold(s.modes, m) {
		a.mu.Unlock()
		return
	}
	a.pendingMode = ""
	a.mu.Unlock()
	if strings.EqualFold(s.mode, m) {
		return
	}
	if err := a.cl.setMode(m); err != nil {
		log.Printf("pending mode %s: %v", m, err)
		return
	}
	log.Printf("mode -> %s (after restart)", m)
	a.notify("Режим", "Теперь "+modeTitle(m)+".")
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// restartCore, stopCore, showLog and openBench live in sys_windows.go.

func (a *app) updateSubscription() {
	var last string
	err := updateSubscriptionFile(a.dir, func(format string, v ...any) {
		last = fmt.Sprintf(format, v...)
		log.Print(last)
	})
	if err != nil {
		a.notify("Подписка", "Не обновилась: "+err.Error())
		return
	}
	// The menu follows on the next tick (reloadConfig); the running core
	// keeps its old list until it restarts.
	if _, _, running := findProcess(coreImage); running {
		last += ". Чтобы применить — «Перезапустить VPN»"
	}
	a.notify("Подписка", last)
}

// ---- self-test ---------------------------------------------------------

func (a *app) runSelfTest() {
	fmt.Printf("config     : %s\n", a.cfgPath)
	fmt.Printf("controller : http://%s\n", a.conf.controller)
	fmt.Printf("selector   : %q (outbounds[%d]), default=%s\n",
		a.conf.selector, a.conf.selectorIdx, a.conf.defaultTag)
	fmt.Printf("servers    : %d (настоящих %d)\n", len(a.conf.servers), a.conf.proxies)
	fmt.Printf("first run  : %v\n", a.setup.active)
	fmt.Printf("wsl port   : %d\n", a.conf.wslPort)

	for _, n := range []string{"ok", "warn", "error", "off"} {
		fmt.Printf("icon %-5s : %d байт ico\n", n, len(icons[n]))
	}

	s := a.poll()
	a.snap = s
	fmt.Println()
	fmt.Printf("state      : %s\n", s.state)
	fmt.Printf("mode       : %s %v\n", s.mode, s.modes)
	fmt.Printf("tooltip    : %q (%d рун)\n", tooltip(s), len([]rune(tooltip(s))))
	fmt.Println()
	fmt.Println("меню:")
	fmt.Printf("   %s\n", statusLine(s))
	if s.state == "ok" || s.state == "warn" {
		fmt.Printf("   %s\n", trafficLine(s))
		fmt.Printf("   %s\n", connsLine(s))
		fmt.Printf("   %s\n", uptimeLine(s))
	}
	fmt.Println("   ---")
	fmt.Println("   Сервер")
	for _, sv := range a.conf.servers {
		mark := " "
		if sv.Tag == s.now {
			mark = "*"
		}
		fmt.Printf("      %s %-6s %s\n", mark, sv.Tag, sv.Addr)
	}
	fmt.Println("   Тест серверов / Обновить подписку")
	fmt.Println("   ---")
	fmt.Println("   Правила маршрутизации… / Открыть веб-панель / Показать лог")
	fmt.Println("   ---")
	power := "Остановить VPN"
	if s.state == "off" {
		power = "Запустить VPN"
	}
	fmt.Printf("   Перезапустить VPN / %s\n", power)
	fmt.Println("   ---")
	fmt.Printf("   Автозапуск VPN: %v\n", logonTaskExists())
	fmt.Printf("   Автозапуск иконки: %v\n", startupEnabled(a.exePath))
	fmt.Println("   Закрыть иконку")
}
