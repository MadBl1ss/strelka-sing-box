//go:build !windows

package main

import (
	"os/exec"
	"path/filepath"
	"time"
)

// The tray only ships for Windows, and everything that touches the OS lives
// in *_windows.go. These stand-ins exist so the portable logic and its tests
// also build and run elsewhere (CI, a Linux dev box).

const (
	coreImage         = "sing-box"
	elevHint          = ""
	autostartLabel    = ""
	vpnAutostartLabel = ""
)

type firstRun struct{ active bool }

func trayLogPath(dir string) string                { return filepath.Join(dir, "sing-box-tray.log") }
func coreExe(dir string) string                    { return filepath.Join(dir, coreImage) }
func hideWindow(*exec.Cmd)                         {}
func iconBytes(png []byte, _ int) []byte           { return png }
func singleInstance() bool                         { return true }
func openURL(string) error                         { return nil }
func setClipboard(string) error                    { return nil }
func startupEnabled(string) bool                   { return false }
func setStartup(string, bool) error                { return nil }
func logonTaskExists() bool                        { return false }
func currentAccount() string                       { return "" }
func runBoot(string, bool, string) int             { return 0 }
func runAutostart(_, _, _ string) int              { return 0 }
func findProcess(string) (uint32, time.Time, bool) { return 0, time.Time{}, false }

func (a *app) restartCore()        {}
func (a *app) stopCore()           {}
func (a *app) showLog()            {}
func (a *app) openBench()          {}
func (a *app) firstRunStep()       {}
func (a *app) toggleVPNAutostart() {}
