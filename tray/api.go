package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const pingURL = "http://www.gstatic.com/generate_204"

type server struct {
	Tag  string
	Addr string
}

type cfg struct {
	controller  string // host:port of the Clash API
	secret      string
	selector    string // tag of the selector outbound, e.g. "proxy"
	selectorIdx int    // its index inside outbounds, for sjson writes
	defaultTag  string
	servers     []server
	proxies     int // real servers in servers; 0 means a template not set up yet
	wslPort     int
}

// Everything the tray shows in one snapshot, so the UI never reads
// half-updated fields while polling is in flight.
type snapshot struct {
	state    string // ok | warn | error | off
	now      string // what the selector points at, e.g. "auto"
	leaf     string // the server traffic actually leaves through
	ping     int
	pingOK   bool
	down     uint64
	up       uint64
	conns    int
	viaVPN   int
	sinceSet bool
	since    time.Time
	mode     string   // Rule | Global, as the core reports it
	modes    []string // modes the running core knows
}

func loadConfig(path string) (*cfg, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !gjson.ValidBytes(raw) {
		return nil, fmt.Errorf("config.json не является корректным JSON")
	}
	c := &cfg{
		controller: gjson.GetBytes(raw, "experimental.clash_api.external_controller").String(),
		secret:     gjson.GetBytes(raw, "experimental.clash_api.secret").String(),
	}
	if c.controller == "" {
		return nil, fmt.Errorf("в config.json не задан experimental.clash_api.external_controller")
	}

	c.selectorIdx = -1
	var xa map[string]string
	gjson.GetBytes(raw, "outbounds").ForEach(func(k, v gjson.Result) bool {
		switch v.Get("type").String() {
		case "selector":
			if c.selectorIdx < 0 {
				c.selectorIdx = int(k.Int())
				c.selector = v.Get("tag").String()
				c.defaultTag = v.Get("default").String()
			}
		case "direct", "block", "dns":
		case "urltest":
			c.servers = append(c.servers, server{
				Tag:  v.Get("tag").String(),
				Addr: "лучший по пингу",
			})
		default:
			s := server{Tag: v.Get("tag").String(), Addr: v.Get("server").String()}
			// An Xray server is a local port here; show where it really goes.
			if v.Get("type").String() == "socks" {
				if xa == nil {
					xa = xrayAddrs(filepath.Dir(path))
				}
				if addr, ok := xa[s.Tag]; ok {
					s.Addr = addr + " (xray)"
				}
			}
			c.servers = append(c.servers, s)
		}
		return true
	})
	if c.selector == "" {
		return nil, fmt.Errorf("в config.json нет outbound типа selector")
	}
	c.proxies = countProxies(raw)

	gjson.GetBytes(raw, "inbounds").ForEach(func(_, v gjson.Result) bool {
		if v.Get("tag").String() == "wsl-in" {
			c.wslPort = int(v.Get("listen_port").Int())
		}
		return true
	})
	return c, nil
}

// countProxies counts the real servers in a config, groups and the built-in
// outbounds aside. The shared template has none.
func countProxies(raw []byte) int {
	n := 0
	gjson.GetBytes(raw, "outbounds").ForEach(func(_, v gjson.Result) bool {
		switch v.Get("type").String() {
		case "selector", "urltest", "direct", "block", "dns":
		default:
			n++
		}
		return true
	})
	return n
}

// pinDefault rewrites just the selector's "default". sjson edits the JSON
// text in place, so every field the tray does not model survives untouched -
// a struct round-trip would silently drop them.
func pinDefault(path string, c *cfg, tag string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	p := fmt.Sprintf("outbounds.%d.default", c.selectorIdx)
	if gjson.GetBytes(raw, p).String() == tag {
		return nil
	}
	out, err := sjson.SetBytes(raw, p, tag)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return err
	}
	c.defaultTag = tag
	return nil
}

type client struct {
	base   string
	secret string
	http   *http.Client
}

func newClient(c *cfg) *client {
	return &client{
		base:   "http://" + c.controller,
		secret: c.secret,
		http: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				// The API is always loopback; a proxy env var must not hijack it,
				// and least of all the tunnel this very app is watching.
				Proxy:       nil,
				DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			},
		},
	}
}

func (cl *client) do(method, path string, body []byte, out any, timeout time.Duration) error {
	var rdr *bytes.Reader
	if body == nil {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, cl.base+path, rdr)
	if err != nil {
		return err
	}
	if cl.secret != "" {
		req.Header.Set("Authorization", "Bearer "+cl.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := *cl.http
	if timeout > 0 {
		hc.Timeout = timeout
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (cl *client) selected(selector string) (now string, all []string, err error) {
	var r struct {
		Now string   `json:"now"`
		All []string `json:"all"`
	}
	err = cl.do("GET", "/proxies/"+url.PathEscape(selector), nil, &r, 0)
	return r.Now, r.All, err
}

// leaf follows groups down to a real server: "auto" names whichever server
// it currently prefers. A plain server has no "now" and is its own leaf.
func (cl *client) leaf(tag string) string {
	for i := 0; i < 3; i++ {
		now, _, err := cl.selected(tag)
		if err != nil || now == "" {
			break
		}
		tag = now
	}
	return tag
}

func (cl *client) traffic() (down, up uint64, total, viaVPN int, err error) {
	var r struct {
		DownloadTotal uint64 `json:"downloadTotal"`
		UploadTotal   uint64 `json:"uploadTotal"`
		Connections   []struct {
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if err = cl.do("GET", "/connections", nil, &r, 0); err != nil {
		return
	}
	total = len(r.Connections)
	for _, c := range r.Connections {
		direct := false
		for _, ch := range c.Chains {
			if ch == "direct" {
				direct = true
				break
			}
		}
		if !direct {
			viaVPN++
		}
	}
	return r.DownloadTotal, r.UploadTotal, total, viaVPN, nil
}

func (cl *client) delay(tag string) (int, error) {
	var r struct {
		Delay int `json:"delay"`
	}
	p := fmt.Sprintf("/proxies/%s/delay?timeout=3000&url=%s",
		url.PathEscape(tag), url.QueryEscape(pingURL))
	err := cl.do("GET", p, nil, &r, 8*time.Second)
	return r.Delay, err
}

// mode reads the routing mode and the modes this core knows. A core started
// from a config without mode rules lists only "Rule".
func (cl *client) mode() (cur string, list []string, err error) {
	var r struct {
		Mode     string   `json:"mode"`
		ModeList []string `json:"mode-list"`
	}
	err = cl.do("GET", "/configs", nil, &r, 0)
	return r.Mode, r.ModeList, err
}

// setMode switches the mode. sing-box answers 204 even to a mode it does not
// know and just keeps the old one, so callers check mode-list first.
func (cl *client) setMode(m string) error {
	body, _ := json.Marshal(map[string]string{"mode": m})
	return cl.do("PATCH", "/configs", body, nil, 5*time.Second)
}

// closeAll drops open connections: they were routed under the old mode and
// would keep that route until they close on their own.
func (cl *client) closeAll() error {
	return cl.do("DELETE", "/connections", nil, nil, 5*time.Second)
}

func (cl *client) switchTo(selector, tag string) error {
	body, _ := json.Marshal(map[string]string{"name": tag})
	return cl.do("PUT", "/proxies/"+url.PathEscape(selector), body, nil, 5*time.Second)
}
