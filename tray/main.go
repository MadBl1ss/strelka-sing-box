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
	"sync/atomic"
	"time"

	"fyne.io/systray"
	"github.com/gen2brain/beeep"
)

const (
	pollEvery = 3 * time.Second
	// A hand-picked server is probed this often, and sooner after a miss so
	// that three in a row do not take a minute to collect.
	pingEvery  = 15 * time.Second
	retryEvery = 5 * time.Second

	// When the server "auto" sits on has no answer on record, the tray asks
	// the core to re-check the pool instead of waiting for its next round.
	recheckAfter = 10 * time.Second
	recheckEvery = time.Minute
	checkTimeout = 10 * time.Second

	// A start the user asked for gets this long before it is called failed:
	// it may have to download the subscription first.
	startWait = 2 * time.Minute
	// A stop the user asked for is "expected" for this long.
	stopWait = 2 * time.Minute

	statsEvery     = 30 * time.Second
	statsSaveEvery = 5 * time.Minute
	// A ping older than this is not shown next to a server.
	pingShown = 15 * time.Minute

	checkLabel = "Проверить все серверы (пинг)"
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
	coreUp func() (started time.Time, found bool) // is the core process there
	cfgMod time.Time                              // config.json as last loaded
	setup  firstRun

	mu       sync.RWMutex
	snap     snapshot
	lastPing time.Time

	// tick runs from the timer and from menu clicks; tickMu makes it one at
	// a time. Everything below it belongs to whoever holds it.
	tickMu        sync.Mutex
	health        health
	ann           announcer
	noAnswerSince time.Time // "auto": since when its server has no result
	lastRecheck   time.Time
	rechecking    atomic.Bool
	stats         *serverStats
	statsAt       time.Time
	statsSaved    time.Time
	statsDirty    bool

	// What the user asked for and has not seen happen yet, and how much they
	// want to hear about it. Set from menu clicks, read by tick.
	wantMu     sync.Mutex
	expectStop time.Time // a stop is expected until then
	startBy    time.Time // a start is awaited until then
	wentDown   bool      // ...and the VPN has been seen down since it was asked
	settings   settings
	toastIcon  string // the shield as a file, for notifications

	checking  atomic.Bool // a "check all servers" is running
	checkedAt time.Time   // when the last one finished

	miStatus  *systray.MenuItem
	miTraffic *systray.MenuItem
	miConns   *systray.MenuItem
	miUptime  *systray.MenuItem
	miPower   *systray.MenuItem
	miAuto    *systray.MenuItem
	miCheck   *systray.MenuItem
	miNotify  map[string]*systray.MenuItem
	miVPNAuto *systray.MenuItem
	miRule    *systray.MenuItem
	miGlobal  *systray.MenuItem
	miSrv     *systray.MenuItem
	miNoSrv   *systray.MenuItem
	srvItems  map[string]*systray.MenuItem
	srvBase   map[string]string // a server's menu label without its ping
	srvLabel  map[string]string // the label as last pushed to the menu

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
	a.coreUp = func() (time.Time, bool) {
		_, started, found := findProcess(coreImage)
		return started, found
	}
	a.srvItems = map[string]*systray.MenuItem{}
	a.srvBase = map[string]string{}
	a.srvLabel = map[string]string{}
	a.miNotify = map[string]*systray.MenuItem{}
	a.settings = loadSettings(a.dir)
	a.stats = loadStats(a.dir)
	beeep.AppName = "Стрелка"
	// One file for the life of the tray: handing the bytes over would write a
	// temp file per notification and delete it while Windows may still be
	// loading it.
	if p := filepath.Join(os.TempDir(), "strelka-shield.png"); os.WriteFile(p, toastIcon, 0o644) == nil {
		a.toastIcon = p
	}
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
		a.srvBase[s.Tag] = label
		a.srvLabel[s.Tag] = label
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

// poll looks at the core once. It reports what it saw (snapshot.raw) and
// leaves the verdict to health.
func (a *app) poll() snapshot {
	var s snapshot

	started, found := a.coreUp()
	if !found {
		s.raw = rawOff
		s.now = "-"
		return s
	}
	s.since, s.sinceSet = started, !started.IsZero()

	px, err := a.cl.proxies()
	if err != nil || px[a.conf.selector].Now == "" {
		// Process is up but the API is silent: still booting, or it bound a
		// port it was not allowed to and is on its way out.
		s.raw = rawError
		s.now = "?"
		return s
	}
	s.proxies = px
	s.now = px[a.conf.selector].Now
	s.leaf = leafOf(px, s.now)
	s.auto = px[s.now].group()
	if m, list, err := a.cl.mode(); err == nil {
		s.mode, s.modes = m, list
	}

	if d, u, total, via, err := a.cl.traffic(); err == nil {
		s.down, s.up, s.conns, s.viaVPN = d, u, total, via
	}

	if s.auto {
		a.watchAuto(&s)
	} else {
		a.probe(&s)
	}
	if s.pingOK {
		s.raw = rawOK
	} else {
		s.raw = rawBad
	}
	return s
}

// watchAuto reads how the server "auto" sits on did in the core's own
// checks. It tests nothing itself: a failed test through the API makes the
// core drop the server on the spot, and one slow answer is no reason to move.
func (a *app) watchAuto(s *snapshot) {
	if p := s.proxies[s.leaf]; p.alive() {
		s.ping, s.pingOK = p.Delay, true
		a.noAnswerSince = time.Time{}
		return
	}
	// No result on record: the server failed its last check, or a connection
	// through it. The core looks again on its next round; asking now gets the
	// VPN onto a live server (or confirms this one) sooner.
	now := time.Now()
	if a.noAnswerSince.IsZero() {
		a.noAnswerSince = now
	}
	if now.Sub(a.noAnswerSince) < recheckAfter || now.Sub(a.lastRecheck) < recheckEvery {
		return
	}
	if !a.rechecking.CompareAndSwap(false, true) {
		return
	}
	a.lastRecheck = now
	cl, group := a.cl, s.now
	log.Printf("%s: %s has no answer on record, asking the core to re-check", group, s.leaf)
	go func() {
		defer a.rechecking.Store(false)
		if err := cl.testGroup(group, checkTimeout); err != nil {
			log.Printf("re-check %s: %v", group, err)
		}
	}()
}

// probe tests a server the user picked by hand. Nobody else does: the core
// only checks the members of "auto" while "auto" is in use.
func (a *app) probe(s *snapshot) {
	a.mu.RLock()
	prev := a.snap
	last := a.lastPing
	a.mu.RUnlock()

	every := pingEvery
	if a.health.fails > 0 {
		every = retryEvery
	}
	if time.Since(last) < every && prev.leaf == s.leaf && !prev.auto {
		s.ping, s.pingOK = prev.ping, prev.pingOK
		return
	}
	a.mu.Lock()
	a.lastPing = time.Now()
	a.mu.Unlock()
	s.probed = true
	if ms, err := a.cl.delay(s.leaf); err == nil {
		s.ping, s.pingOK = ms, true
	}
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
	case stOK:
		line := "Подключено — " + serverName(s)
		if s.pingOK {
			line += fmt.Sprintf(" — %d мс", s.ping)
		}
		if strings.EqualFold(s.mode, modeGlobal) {
			line += " — весь трафик"
		}
		return line
	case stStarting:
		if s.leaf != "" {
			return "Проверяю " + serverName(s) + "…"
		}
		return "Запускается…"
	case stWarn:
		if s.auto {
			return "Серверы не отвечают"
		}
		return fmt.Sprintf("%s не отвечает", serverName(s))
	case stError:
		return "sing-box не отвечает"
	}
	return "VPN выключен"
}

// apiUp says whether this poll reached the core, so the traffic rows mean
// something.
func apiUp(s snapshot) bool { return s.raw == rawOK || s.raw == rawBad }

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
	if s.state == stOK {
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

	a.miCheck = systray.AddMenuItem(checkLabel, "Несколько секунд, VPN при этом работает")
	miTest := systray.AddMenuItem("Полный тест (пинг и скорость)", "В отдельном окне, занимает пару минут")
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
	miNotify := systray.AddMenuItem("Уведомления", "О чём сообщать всплывающим окном")
	for _, l := range []struct{ level, title, hint string }{
		{notifyAll, "Обо всём", "Подключение, отключение, смена сервера"},
		{notifyProblems, "Только о проблемах", "VPN упал или серверы молчат дольше полминуты"},
		{notifyNone, "Выключены", "Состояние видно по цвету щита"},
	} {
		it := miNotify.AddSubMenuItemCheckbox(l.title, l.hint, a.settings.Notify == l.level)
		a.miNotify[l.level] = it
		level := l.level
		on(it, func() { a.setNotify(level) })
	}
	systray.AddSeparator()
	miQuit := systray.AddMenuItem("Закрыть иконку (VPN останется работать)", "")

	on(a.miCheck, a.checkAll)
	on(miTest, a.openBench)
	on(miUpd, a.updateSubscription)
	on(miRules, a.openRules)
	on(miPanel, a.openPanel)
	on(miLog, a.showLog)
	on(miRestart, a.restartCore)
	on(a.miPower, func() {
		a.mu.RLock()
		off := a.snap.state == stOff
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
	on(miQuit, func() {
		a.tickMu.Lock()
		a.saveStats(time.Now(), true)
		a.tickMu.Unlock()
		systray.Quit()
	})

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
	a.tickMu.Lock()
	defer a.tickMu.Unlock()

	a.reloadConfig()
	s := a.poll()
	now := time.Now()
	a.wantMu.Lock()
	expected := now.Before(a.expectStop)
	a.wantMu.Unlock()
	prev := a.health.state
	s.state = a.health.observe(now, s, expected)

	a.mu.Lock()
	old := a.snap
	a.snap = s
	a.mu.Unlock()

	// Only on change: every SetIcon rebuilds an HICON, and this runs every
	// few seconds for as long as the machine is on.
	if iconFor(s.state) != iconFor(prev) || prev == "" {
		systray.SetIcon(icons[iconFor(s.state)])
	}
	systray.SetTooltip(tooltip(s))

	// Every one of these is a Win32 menu call, and tick runs forever - so
	// touch a menu item only when its text or state actually differs.
	setTitle(a.miStatus, &a.txtStatus, statusLine(s))

	show := apiUp(s)
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
	a.showPings(now, s)

	power := "Остановить VPN"
	if s.state == stOff {
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

	a.announce(now, prev, old, s)
	a.keepStats(now, s)

	if a.setup.active {
		a.firstRunStep()
	}
}

// announce turns a change of the settled state into a log line and, when it
// is worth interrupting someone, a notification.
func (a *app) announce(now time.Time, prev string, old, s snapshot) {
	a.wantMu.Lock()
	level := a.settings.Notify
	expected := now.Before(a.expectStop)
	// A restart is only done once the VPN has gone down and come back: right
	// after the click it is still up, and that is not the answer.
	waiting := !a.startBy.IsZero()
	if waiting && s.state != stOK {
		a.wentDown = true
	}
	asked := waiting && a.wentDown
	late := waiting && now.After(a.startBy)
	if (asked && s.state == stOK) || late || (!waiting && s.state == stOff) {
		a.startBy, a.expectStop, a.wentDown = time.Time{}, time.Time{}, false
	}
	a.wantMu.Unlock()

	if prev != s.state {
		log.Printf("state: %s -> %s", prev, s.state)
		t := transition{prev: prev, cur: s.state, snap: s, expected: expected, asked: asked}
		if msg := a.ann.decide(now, level, t); msg != nil {
			a.notify(msg.title, msg.body)
		}
	}
	if late && s.state != stOK && level != notifyNone {
		a.notify("VPN не запустился", "Прошло две минуты, а он так и не поднялся. Загляни в «Показать лог».")
	}

	// "auto" moving to another server is its job, not news - unless asked.
	if s.auto && old.auto && s.now == old.now && old.leaf != "" && s.leaf != old.leaf {
		log.Printf("%s: %s -> %s", s.now, old.leaf, s.leaf)
		if level == notifyAll && s.state == stOK {
			a.notify("Сервер сменился", fmt.Sprintf("%s: %s → %s", s.now, old.leaf, s.leaf))
		}
	}
}

// keepStats feeds the core's check results into the per-server picture that
// orders "auto" (see stats.go), and writes it out now and then.
func (a *app) keepStats(now time.Time, s snapshot) {
	if s.proxies == nil || now.Sub(a.statsAt) < statsEvery {
		return
	}
	a.statsAt = now
	probed := ""
	if !s.auto {
		probed = s.leaf
	}
	if a.stats.observe(now, a.conf.pool, s.proxies, probed) {
		a.statsDirty = true
	}
	a.saveStats(now, false)
}

func (a *app) saveStats(now time.Time, force bool) {
	if !a.statsDirty || (!force && now.Sub(a.statsSaved) < statsSaveEvery) {
		return
	}
	a.statsSaved, a.statsDirty = now, false
	if err := a.stats.save(a.dir, now); err != nil {
		log.Printf("server stats: %v", err)
	}
}

// pingSuffix is what a server's menu line says about its last check.
func pingSuffix(now time.Time, p proxyInfo, checked time.Time) string {
	switch {
	case p.group():
		return ""
	case p.alive() && now.Sub(p.Tested) < pingShown:
		return fmt.Sprintf("   %d мс", p.Delay)
	case !p.alive() && !checked.IsZero() && now.Sub(checked) < pingShown:
		return "   нет ответа"
	}
	return ""
}

// showPings puts each server's last result next to its name.
func (a *app) showPings(now time.Time, s snapshot) {
	a.mu.RLock()
	checked := a.checkedAt
	a.mu.RUnlock()
	for tag, it := range a.srvItems {
		base, ok := a.srvBase[tag]
		if !ok {
			continue
		}
		label := base
		if p, known := s.proxies[tag]; known {
			label += pingSuffix(now, p, checked)
		}
		if a.srvLabel[tag] != label {
			a.srvLabel[tag] = label
			it.SetTitle(label)
		}
	}
}

func (a *app) notify(title, body string) {
	if err := beeep.Notify(title, body, a.toastIcon); err != nil {
		log.Printf("notify: %v", err)
	}
}

// awaitStart and awaitStop record what the user just asked the VPN to do, so
// that the change that follows is not reported as a surprise.
func (a *app) awaitStart() {
	now := time.Now()
	a.wantMu.Lock()
	a.expectStop, a.startBy, a.wentDown = now.Add(stopWait), now.Add(startWait), false
	a.wantMu.Unlock()
}

func (a *app) awaitStop() {
	a.wantMu.Lock()
	a.expectStop, a.startBy, a.wentDown = time.Now().Add(stopWait), time.Time{}, false
	a.wantMu.Unlock()
}

func (a *app) setNotify(level string) {
	a.wantMu.Lock()
	a.settings.Notify = level
	err := saveSettings(a.dir, a.settings)
	a.wantMu.Unlock()
	if err != nil {
		log.Printf("settings: %v", err)
	}
	for l, it := range a.miNotify {
		if l == level {
			it.Check()
		} else {
			it.Uncheck()
		}
	}
}

// checkAll has the running core test every server at once and shows the
// result in the server list. Unlike the full test it starts nothing and takes
// seconds; it measures the delay only, not the speed.
func (a *app) checkAll() {
	a.mu.RLock()
	s := a.snap
	a.mu.RUnlock()
	if !apiUp(s) {
		a.notify("Проверка серверов", "Сначала включи VPN: серверы проверяет он.")
		return
	}
	if !a.checking.CompareAndSwap(false, true) {
		return
	}
	defer a.checking.Store(false)

	a.miCheck.SetTitle("Проверяю серверы…")
	start := time.Now()
	err := a.cl.testGroup(a.conf.selector, checkTimeout)
	a.miCheck.SetTitle(checkLabel)
	if err != nil {
		a.notify("Проверка серверов", "Не вышло: "+err.Error())
		return
	}
	a.mu.Lock()
	a.checkedAt = time.Now()
	a.mu.Unlock()
	a.tick()

	a.mu.RLock()
	px := a.snap.proxies
	a.mu.RUnlock()
	a.notify("Проверка серверов", checkSummary(px, a.conf.servers, start))
}

// checkSummary counts who answered a check started at start.
func checkSummary(px map[string]proxyInfo, servers []server, start time.Time) string {
	total, alive := 0, 0
	best, bestMs := "", 0
	for _, sv := range servers {
		p, known := px[sv.Tag]
		if !known || p.group() {
			continue
		}
		total++
		// A server that failed lost its result; one the check never got to
		// in time still shows an older one.
		if !p.alive() || p.Tested.Before(start.Add(-time.Second)) {
			continue
		}
		alive++
		if best == "" || p.Delay < bestMs {
			best, bestMs = sv.Tag, p.Delay
		}
	}
	if alive == 0 {
		return fmt.Sprintf("Не ответил ни один из %d. Проверь интернет.", total)
	}
	return fmt.Sprintf("Отвечают %d из %d. Самый быстрый: %s — %d мс.", alive, total, best, bestMs)
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

	if s.state == stOff {
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
	s.state = a.health.observe(time.Now(), s, false)
	a.snap = s
	fmt.Println()
	fmt.Printf("state      : %s\n", s.state)
	fmt.Printf("mode       : %s %v\n", s.mode, s.modes)
	fmt.Printf("tooltip    : %q (%d рун)\n", tooltip(s), len([]rune(tooltip(s))))
	fmt.Println()
	fmt.Println("меню:")
	fmt.Printf("   %s\n", statusLine(s))
	if apiUp(s) {
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
	fmt.Println("   Проверить все серверы / Полный тест / Обновить подписку")
	fmt.Println("   ---")
	fmt.Println("   Правила маршрутизации… / Открыть веб-панель / Показать лог")
	fmt.Println("   ---")
	power := "Остановить VPN"
	if s.state == stOff {
		power = "Запустить VPN"
	}
	fmt.Printf("   Перезапустить VPN / %s\n", power)
	fmt.Println("   ---")
	fmt.Printf("   Автозапуск VPN: %v\n", logonTaskExists())
	fmt.Printf("   Автозапуск иконки: %v\n", startupEnabled(a.exePath))
	fmt.Printf("   Уведомления: %s\n", a.settings.Notify)
	fmt.Println("   Закрыть иконку")
}
