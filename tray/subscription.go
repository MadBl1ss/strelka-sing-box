package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Only the "outbounds" array is rebuilt; routing rules, DNS, TUN and
// experimental settings are left exactly as they are.
//
// subscription.txt may list several providers, one per line. Their servers
// go into one pool: the "proxy" selector offers every server by hand plus
// "auto", a urltest group that keeps picking the one with the lowest ping.

const autoTag = "auto"

// proxyOutbound covers every protocol the updater understands. Fields a
// protocol does not use stay empty and are dropped by omitempty.
type proxyOutbound struct {
	Type           string     `json:"type"`
	Tag            string     `json:"tag"`
	Server         string     `json:"server"`
	ServerPort     int        `json:"server_port"`
	UUID           string     `json:"uuid,omitempty"`
	Flow           string     `json:"flow,omitempty"`
	Method         string     `json:"method,omitempty"`
	Password       string     `json:"password,omitempty"`
	Plugin         string     `json:"plugin,omitempty"`
	PluginOpts     string     `json:"plugin_opts,omitempty"`
	Obfs           *obfsOpts  `json:"obfs,omitempty"`
	TLS            *tlsOpts   `json:"tls,omitempty"`
	Transport      *transport `json:"transport,omitempty"`
	PacketEncoding string     `json:"packet_encoding,omitempty"`
}

type tlsOpts struct {
	Enabled    bool         `json:"enabled"`
	ServerName string       `json:"server_name,omitempty"`
	Insecure   bool         `json:"insecure,omitempty"`
	ALPN       []string     `json:"alpn,omitempty"`
	UTLS       *utlsOpts    `json:"utls,omitempty"`
	Reality    *realityOpts `json:"reality,omitempty"`
}

type utlsOpts struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type realityOpts struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

type obfsOpts struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

type transport struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

type selectorOutbound struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds"`
	Default   string   `json:"default"`
}

type urltestOutbound struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds"`
	Interval  string   `json:"interval"`
	Tolerance int      `json:"tolerance"`
}

type directOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

// subscription is one line of subscription.txt: "name url" or just "url".
type subscription struct {
	name string // tag prefix, "" only for a lone unnamed subscription
	url  string
}

// entry is one server headed for the new config. It is either freshly parsed
// or carried over verbatim from the current config.
type entry struct {
	tag  string
	ob   any  // the sing-box outbound; for an Xray server, set once its port is known
	xray any  // the Xray outbound, nil when sing-box talks to the server itself
	auto bool // takes part in the "auto" group
}

var tagMarker = regexp.MustCompile(`\[([^\]]+)\]`)
var validName = regexp.MustCompile(`[^A-Za-z0-9_.]`)
var hwidOK = regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`)

// updateSubscriptionFile refreshes config.json in place. A missing, empty or
// unreachable subscription is not an error: the existing config stays and the
// VPN still comes up, which matters when this runs at boot before the network
// has settled.
func updateSubscriptionFile(dir string, logf func(string, ...any)) error {
	cfgPath := filepath.Join(dir, "config.json")
	subPath := filepath.Join(dir, "subscription.txt")
	tmpPath := filepath.Join(dir, "config.new.json")
	bakPath := filepath.Join(dir, "config.bak.json")
	xrayPath := filepath.Join(dir, "xray.json")
	xrayTmp := filepath.Join(dir, "xray.new.json")
	exePath := coreExe(dir)

	subRaw, err := os.ReadFile(subPath)
	if err != nil {
		logf("subscription.txt отсутствует — оставляю текущий конфиг")
		return nil
	}
	subs := parseSubscriptions(string(subRaw))
	if len(subs) == 0 {
		logf("в subscription.txt не вписана ссылка — оставляю текущий конфиг")
		return nil
	}

	cur, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	hwid := deviceID(dir)
	useXray := xrayPresent(dir)
	oldXray := map[string]json.RawMessage{}
	if useXray {
		oldXray = xrayOutboundsByTag(dir)
	}

	// Tags the config itself uses can never go to a server.
	used := map[string]int{"proxy": 1, autoTag: 1, "direct": 1}
	var entries []entry
	var failed []string
	fresh := 0
	for _, sub := range subs {
		label := orDefault(sub.name, "подписка")
		links, err := fetchLinks(sub.url, hwid)
		var got []entry
		if err == nil {
			got = parseLinks(links, sub.name, used, useXray, logf)
			if len(got) == 0 {
				err = fmt.Errorf("ни одного подходящего сервера")
			}
		}
		if err != nil {
			// One flaky provider must not empty the list: keep what it gave
			// last time. That needs a prefix to recognise its servers by.
			kept := carryOver(cur, sub.name, used, oldXray)
			logf("%s: не обновилась (%v) — оставляю прежние серверы: %d", label, err, len(kept))
			entries = append(entries, kept...)
			failed = append(failed, label)
			continue
		}
		logf("%s: %d серверов", label, len(got))
		entries = append(entries, got...)
		fresh++
	}
	if fresh == 0 {
		logf("ни одна подписка не скачалась — оставляю текущий конфиг")
		return nil
	}
	if len(entries) == 0 {
		logf("ни одна ссылка не разобралась — оставляю текущий конфиг")
		return nil
	}

	// Give each Xray server a local port. Handing them out in list order
	// keeps a server on the same port from one refresh to the next.
	busy := listenPorts(cur)
	var xs []xrayServer
	port := xrayBasePort
	for i, e := range entries {
		if e.xray == nil {
			continue
		}
		for busy[port] {
			port++
		}
		xs = append(xs, xrayServer{tag: e.tag, port: port, ob: e.xray})
		entries[i].ob = socksTo(e.tag, port)
		port++
	}

	var tags, pool []string
	for _, e := range entries {
		tags = append(tags, e.tag)
		if e.auto {
			pool = append(pool, e.tag)
		}
	}
	if len(pool) == 0 {
		pool = tags
	}
	choices := append([]string{autoTag}, tags...)

	// Keep the selected server across refreshes when it is still on offer.
	prev := ""
	gjson.GetBytes(cur, "outbounds").ForEach(func(_, v gjson.Result) bool {
		if v.Get("type").String() == "selector" {
			prev = v.Get("default").String()
			return false
		}
		return true
	})
	next := autoTag
	for _, t := range choices {
		if t == prev {
			next = prev
			break
		}
	}
	// "direct" is the empty template's placeholder, not a lost server.
	if prev != "" && prev != next && prev != "direct" {
		logf("сервер %q пропал из подписки — переключаюсь на %q", prev, next)
	}

	all := make([]any, 0, len(entries)+3)
	all = append(all, selectorOutbound{Type: "selector", Tag: "proxy", Outbounds: choices, Default: next})
	all = append(all, urltestOutbound{Type: "urltest", Tag: autoTag, Outbounds: pool, Interval: "3m", Tolerance: 50})
	for _, e := range entries {
		all = append(all, e.ob)
	}
	all = append(all, directOutbound{Type: "direct", Tag: "direct"})

	blob, err := json.Marshal(all)
	if err != nil {
		return err
	}
	out, err := sjson.SetRawBytes(cur, "outbounds", blob)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, out, 0o644); err != nil {
		return err
	}

	// Never swap in a config the core will not accept.
	if err := runQuiet(exePath, []string{"check", "-c", tmpPath}, dir); err != nil {
		logf("новый конфиг не прошёл проверку (%v) — оставляю старый", err)
		os.Remove(tmpPath)
		return nil
	}
	if len(xs) > 0 {
		xb, err := json.MarshalIndent(buildXrayConfig(xs), "", "  ")
		if err == nil {
			err = os.WriteFile(xrayTmp, xb, 0o644)
		}
		if err == nil {
			err = runQuiet(xrayExe(dir), []string{"run", "-test", "-c", xrayTmp}, dir)
		}
		if err != nil {
			logf("новый xray.json не прошёл проверку (%v) — оставляю старые конфиги", err)
			os.Remove(tmpPath)
			os.Remove(xrayTmp)
			return nil
		}
	}

	if err := os.WriteFile(bakPath, cur, 0o644); err != nil {
		logf("не удалось сохранить бэкап: %v", err)
	}
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		os.Remove(tmpPath)
		os.Remove(xrayTmp)
		return err
	}
	_ = runQuiet(exePath, []string{"format", "-c", cfgPath, "-w"}, dir)
	if len(xs) > 0 {
		if err := os.Rename(xrayTmp, xrayPath); err != nil {
			return err
		}
	} else {
		os.Remove(xrayPath) // nothing for Xray to do: boot will not start it
	}
	// New servers may have new names; Global mode must resolve them locally.
	if gjson.GetBytes(out, `route.rule_set.#(tag=="`+serversDNSTag+`")`).Exists() {
		if err := writeServersDNS(dir, out); err != nil {
			logf("не удалось обновить %s: %v", serversDNSTag, err)
		}
	}

	msg := fmt.Sprintf("config.json обновлён: %d серверов", len(entries))
	if len(xs) > 0 {
		msg += fmt.Sprintf(" (через Xray: %d)", len(xs))
	}
	msg += ", активен " + next
	if len(failed) > 0 {
		msg += "; не обновились: " + strings.Join(failed, ", ")
	}
	logf("%s", msg)
	return nil
}

// fetchLinks downloads one subscription and returns its share links.
//
// Remnawave panels with a device limit answer a request without x-hwid with
// a stub server named "App not supported", so every request carries this
// machine's id. The same headers are what Happ or v2RayTun would send.
func fetchLinks(subURL, hwid string) ([]string, error) {
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sing-box")
	req.Header.Set("x-hwid", hwid)
	req.Header.Set("x-device-os", "Windows")
	req.Header.Set("x-device-model", "sing-box-tray")
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	if resp.Header.Get("x-hwid-max-devices-reached") == "true" {
		return nil, fmt.Errorf("лимит устройств исчерпан — удали старое устройство в боте провайдера")
	}
	if resp.Header.Get("x-hwid-not-supported") == "true" {
		return nil, fmt.Errorf("панель не приняла HWID")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	text := strings.TrimSpace(string(body))
	// Most providers base64 the list; some serve it as plain text.
	if dec, err := base64.StdEncoding.DecodeString(text); err == nil {
		text = string(dec)
	} else if dec, err := base64.RawStdEncoding.DecodeString(text); err == nil {
		text = string(dec)
	}

	var links []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.Contains(ln, "://") {
			links = append(links, ln)
		}
	}
	return links, nil
}

// parseLinks turns share links into outbounds tagged "<prefix>-<label>".
// With useXray, links that need Xray (see needsXray) become Xray outbounds.
// Links nothing here can use are skipped and counted, one log line per reason.
func parseLinks(links []string, prefix string, used map[string]int, useXray bool, logf func(string, ...any)) []entry {
	type parsed struct {
		ob   *proxyOutbound
		xray map[string]any
		name string
		n    int // 1-based position in the subscription
	}
	var good []parsed
	skipped := map[string]int{}

	for i, link := range links {
		scheme, _, _ := strings.Cut(link, "://")
		scheme = strings.ToLower(scheme)
		var ob *proxyOutbound
		var xob map[string]any
		var name string
		var err error
		switch scheme {
		case "vless", "trojan":
			if u, host, port, e := splitLink(link); e == nil && useXray && needsXray(u.Query()) {
				xob, name, err = xrayOutbound(link)
				// Only for the stub check below; sing-box gets a socks outbound.
				ob = &proxyOutbound{Server: host, ServerPort: port}
			} else if scheme == "vless" {
				ob, name, err = parseVLESS(link)
			} else {
				ob, name, err = parseTrojan(link)
			}
		case "ss":
			ob, name, err = parseSS(link)
		case "hysteria2", "hy2":
			ob, name, err = parseHysteria2(link)
		default:
			err = fmt.Errorf("протокол %s не поддерживается", scheme)
		}
		if err == nil && (ob.Server == "" || ob.Server == "0.0.0.0" || ob.ServerPort < 2) {
			// Panels put these in as notices ("App not supported", "limit
			// reached"), not as servers.
			err = fmt.Errorf("заглушка вместо сервера")
		}
		if err != nil {
			skipped[err.Error()]++
			continue
		}
		good = append(good, parsed{ob, xob, name, i + 1})
	}

	// Some panels shuffle the list on every request. Sorting by name keeps
	// "lider-DE2" the same server from one refresh to the next.
	sort.SliceStable(good, func(a, b int) bool { return good[a].name < good[b].name })

	var out []entry
	for _, p := range good {
		label, country := nameLabel(p.name)
		if label == "" {
			label = fmt.Sprintf("srv%d", p.n)
		}
		tag := uniqueTag(joinTag(prefix, label), used)
		// A Russian exit is close and wins every ping race, yet unblocks
		// nothing; it stays in the list for manual use only.
		e := entry{tag: tag, auto: country != "RU"}
		if p.xray != nil {
			p.xray["tag"] = tag
			e.xray = p.xray
		} else {
			p.ob.Tag = tag
			e.ob = p.ob
		}
		out = append(out, e)
	}

	reasons := make([]string, 0, len(skipped))
	for r := range skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	who := orDefault(prefix, "подписка")
	for _, r := range reasons {
		logf("%s: пропущено %d — %s", who, skipped[r], r)
	}
	return out
}

func parseVLESS(link string) (*proxyOutbound, string, error) {
	u, host, port, err := splitLink(link)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	if e := q.Get("encryption"); e != "" && e != "none" {
		return nil, "", fmt.Errorf("VLESS encryption не поддерживается sing-box")
	}
	ob := &proxyOutbound{
		Type:           "vless",
		Server:         host,
		ServerPort:     port,
		UUID:           u.User.Username(),
		Flow:           q.Get("flow"),
		PacketEncoding: "xudp",
	}
	ob.TLS = tlsFromQuery(q, q.Get("security"))
	if ob.Transport, err = transportFromQuery(q); err != nil {
		return nil, "", err
	}
	return ob, u.Fragment, nil
}

func parseTrojan(link string) (*proxyOutbound, string, error) {
	u, host, port, err := splitLink(link)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	ob := &proxyOutbound{
		Type:       "trojan",
		Server:     host,
		ServerPort: port,
		Password:   u.User.Username(),
	}
	// Trojan runs over TLS unless the link explicitly says otherwise.
	ob.TLS = tlsFromQuery(q, orDefault(q.Get("security"), "tls"))
	if ob.Transport, err = transportFromQuery(q); err != nil {
		return nil, "", err
	}
	return ob, u.Fragment, nil
}

func parseHysteria2(link string) (*proxyOutbound, string, error) {
	u, host, port, err := splitLink(link)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	pass := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pass += ":" + p
	}
	ob := &proxyOutbound{
		Type:       "hysteria2",
		Server:     host,
		ServerPort: port,
		Password:   pass,
		TLS:        tlsFromQuery(q, "tls"),
	}
	if o := q.Get("obfs"); o != "" {
		ob.Obfs = &obfsOpts{Type: o, Password: q.Get("obfs-password")}
	}
	return ob, u.Fragment, nil
}

// parseSS reads both Shadowsocks link styles:
//
//	ss://BASE64(method:password)@host:port?plugin=...#name   (SIP002)
//	ss://BASE64(method:password@host:port)#name              (legacy)
//
// Not through url.Parse: base64 may carry '/' and '+', which it would take
// for a path.
func parseSS(link string) (*proxyOutbound, string, error) {
	_, body, _ := strings.Cut(link, "://")
	body, frag, _ := strings.Cut(body, "#")
	name, _ := url.PathUnescape(frag)
	body, query, _ := strings.Cut(body, "?")
	body = strings.TrimSuffix(body, "/")

	userinfo, hostport, ok := cutLast(body, "@")
	if !ok {
		dec, err := decodeB64(body)
		if err != nil {
			return nil, "", fmt.Errorf("битая ссылка")
		}
		if userinfo, hostport, ok = cutLast(dec, "@"); !ok {
			return nil, "", fmt.Errorf("битая ссылка")
		}
	} else if un, err := url.PathUnescape(userinfo); err == nil && strings.Contains(un, ":") {
		userinfo = un // SIP022 keys go in plain, percent-encoded
	} else if dec, err := decodeB64(userinfo); err == nil {
		userinfo = dec
	} else {
		return nil, "", fmt.Errorf("битая ссылка")
	}

	method, pass, ok := strings.Cut(userinfo, ":")
	if !ok {
		return nil, "", fmt.Errorf("битая ссылка")
	}
	u, err := url.Parse("ss://" + hostport)
	if err != nil {
		return nil, "", fmt.Errorf("битая ссылка")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, "", fmt.Errorf("ссылка без порта")
	}

	ob := &proxyOutbound{
		Type:       "shadowsocks",
		Server:     u.Hostname(),
		ServerPort: port,
		Method:     method,
		Password:   pass,
	}
	if q, err := url.ParseQuery(query); err == nil {
		if p := q.Get("plugin"); p != "" {
			plugin, opts, _ := strings.Cut(p, ";")
			if plugin == "simple-obfs" {
				plugin = "obfs-local"
			}
			if plugin != "obfs-local" && plugin != "v2ray-plugin" {
				return nil, "", fmt.Errorf("плагин %s не поддерживается sing-box", plugin)
			}
			ob.Plugin, ob.PluginOpts = plugin, opts
		}
	}
	return ob, name, nil
}

// splitLink parses a URL-shaped share link and checks it names a server.
func splitLink(link string) (*url.URL, string, int, error) {
	u, err := url.Parse(link)
	if err != nil || u.User == nil {
		return nil, "", 0, fmt.Errorf("битая ссылка")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, "", 0, fmt.Errorf("ссылка без порта")
	}
	return u, u.Hostname(), port, nil
}

func tlsFromQuery(q url.Values, sec string) *tlsOpts {
	if sec != "tls" && sec != "reality" {
		return nil
	}
	t := &tlsOpts{Enabled: true, ServerName: q.Get("sni")}
	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
		t.Insecure = true
	}
	if a := q.Get("alpn"); a != "" {
		t.ALPN = strings.Split(a, ",")
	}
	fp := q.Get("fp")
	if sec == "reality" {
		// sing-box builds the Reality handshake with uTLS only.
		fp = orDefault(fp, "chrome")
		t.Reality = &realityOpts{Enabled: true, PublicKey: q.Get("pbk"), ShortID: q.Get("sid")}
	}
	if fp != "" {
		t.UTLS = &utlsOpts{Enabled: true, Fingerprint: fp}
	}
	return t
}

func transportFromQuery(q url.Values) (*transport, error) {
	switch typ := q.Get("type"); typ {
	case "", "tcp", "raw":
		if q.Get("headerType") == "http" {
			return nil, fmt.Errorf("TCP с HTTP-маскировкой не поддерживается sing-box")
		}
		return nil, nil
	case "ws":
		tr := &transport{Type: "ws", Path: orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			tr.Headers = map[string]string{"Host": h}
		}
		return tr, nil
	case "grpc":
		return &transport{Type: "grpc", ServiceName: q.Get("serviceName")}, nil
	case "httpupgrade":
		return &transport{Type: "httpupgrade", Path: orDefault(q.Get("path"), "/"), Host: q.Get("host")}, nil
	case "http", "h2":
		return &transport{Type: "http", Path: q.Get("path"), Host: q.Get("host")}, nil
	default:
		return nil, fmt.Errorf("транспорт %s не поддерживается sing-box", typ)
	}
}

// nameLabel turns a server's display name into a short tag and, when the
// name shows one, its exit country. Providers mark the server as "[FI]" or
// with a flag emoji, often both ("🇷🇺 [RU3] ..."); failing either, the first
// word of the name will do. The flag is the more reliable country: markers
// carry counters and nicknames like RU3 or SW.
func nameLabel(name string) (label, country string) {
	country = flagCountry(name)
	if m := tagMarker.FindStringSubmatch(name); m != nil {
		label = m[1]
	} else if country != "" {
		label = country
	} else {
		for _, w := range strings.FieldsFunc(name, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			if !isDigits(w) {
				label = w
				break
			}
		}
	}
	if r := []rune(label); len(r) > 20 {
		label = string(r[:20])
	}
	if country == "" && len(label) == 2 && strings.ToUpper(label) == label {
		country = label
	}
	return label, country
}

// flagCountry reads the first flag emoji: two regional indicator symbols,
// one per letter of the ISO country code.
func flagCountry(s string) string {
	r := []rune(s)
	for i := 0; i+1 < len(r); i++ {
		if isRegional(r[i]) && isRegional(r[i+1]) {
			return string([]rune{'A' + r[i] - 0x1F1E6, 'A' + r[i+1] - 0x1F1E6})
		}
	}
	return ""
}

func isRegional(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }

func isDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func joinTag(prefix, label string) string {
	if prefix == "" {
		return label
	}
	return prefix + "-" + label
}

func uniqueTag(tag string, used map[string]int) string {
	n, seen := used[tag]
	if !seen {
		used[tag] = 1
		return tag
	}
	for {
		n++
		t := fmt.Sprintf("%s%d", tag, n)
		if _, taken := used[t]; !taken {
			used[tag] = n
			used[t] = 1
			return t
		}
	}
}

// carryOver lifts a provider's servers out of the current config verbatim,
// for when its subscription could not be fetched this time. Servers are
// recognised by the "<prefix>-" tag prefix, so an unnamed subscription
// has nothing to carry. An Xray server comes back with its Xray outbound
// from oldXray; without one it is dropped.
func carryOver(cur []byte, prefix string, used map[string]int, oldXray map[string]json.RawMessage) []entry {
	if prefix == "" {
		return nil
	}
	inAuto := map[string]bool{}
	gjson.GetBytes(cur, `outbounds.#(tag=="`+autoTag+`").outbounds`).ForEach(func(_, t gjson.Result) bool {
		inAuto[t.String()] = true
		return true
	})
	var out []entry
	gjson.GetBytes(cur, "outbounds").ForEach(func(_, v gjson.Result) bool {
		tag := v.Get("tag").String()
		switch v.Get("type").String() {
		case "selector", "urltest", "direct", "block", "dns":
			return true
		}
		if !strings.HasPrefix(tag, prefix+"-") {
			return true
		}
		if _, taken := used[tag]; taken {
			return true
		}
		e := entry{tag: tag, ob: json.RawMessage(v.Raw), auto: inAuto[tag]}
		if v.Get("type").String() == "socks" {
			xo, ok := oldXray[tag]
			if !ok {
				return true
			}
			e.xray = xo
		}
		used[tag] = 1
		out = append(out, e)
		return true
	})
	return out
}

// listenPorts collects the ports config.json already listens on (the panel
// and the inbounds), so Xray's local ports stay clear of them.
func listenPorts(cur []byte) map[int]bool {
	busy := map[int]bool{}
	ctrl := gjson.GetBytes(cur, "experimental.clash_api.external_controller").String()
	if i := strings.LastIndex(ctrl, ":"); i >= 0 {
		if p, err := strconv.Atoi(ctrl[i+1:]); err == nil {
			busy[p] = true
		}
	}
	gjson.GetBytes(cur, "inbounds.#.listen_port").ForEach(func(_, p gjson.Result) bool {
		busy[int(p.Int())] = true
		return true
	})
	return busy
}

// parseSubscriptions reads subscription.txt: one subscription per line,
// optionally preceded by a short name that prefixes its servers' tags.
// Blank lines and # comments are skipped, so the file can carry its own
// instructions. So is any line without a "://" link: a stray word or a BOM
// glued to the first comment must not pass for a subscription, since the
// first-run setup starts as soon as one is found.
func parseSubscriptions(s string) []subscription {
	var subs []subscription
	s = strings.TrimPrefix(s, "Feff")
	for _, ln := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Fields(ln)
		sub := subscription{url: f[len(f)-1]}
		if !strings.Contains(sub.url, "://") {
			continue
		}
		if len(f) > 1 {
			sub.name = validName.ReplaceAllString(f[0], "")
		}
		subs = append(subs, sub)
	}
	// A lone unnamed subscription keeps plain tags, as it always has.
	if len(subs) > 1 {
		seen := map[string]bool{}
		for i := range subs {
			if subs[i].name == "" || seen[subs[i].name] {
				subs[i].name = fmt.Sprintf("sub%d", i+1)
			}
			seen[subs[i].name] = true
		}
	}
	return subs
}

// deviceID is the id device-limited panels count this machine by. It lives
// in hwid.txt so it never changes: a new id would take another device slot.
func deviceID(dir string) string {
	p := filepath.Join(dir, "hwid.txt")
	if b, err := os.ReadFile(p); err == nil {
		if id := strings.TrimSpace(string(b)); hwidOK.MatchString(id) {
			return id
		}
	}
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	id := hex.EncodeToString(buf)
	_ = os.WriteFile(p, []byte(id+"\n"), 0o644)
	return id
}

func decodeB64(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("не base64")
}

func cutLast(s, sep string) (before, after string, ok bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func runQuiet(exe string, args []string, dir string) error {
	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	hideWindow(cmd)
	return cmd.Run()
}
