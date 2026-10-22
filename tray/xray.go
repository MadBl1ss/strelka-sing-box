package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
)

// Some servers only work through Xray-core, so xray.exe runs next to
// sing-box as a helper. sing-box keeps the TUN, the routing and the tray;
// each such server becomes a local SOCKS port in xray.json, and in
// config.json a socks outbound with the server's tag points at that port.
//
// Two kinds go to Xray:
//   - REALITY: sing-box introduces itself to the server as Xray 1.8.1, and
//     panels that set a minimum client version reject it ("reality
//     verification failed");
//   - XHTTP, which sing-box does not implement at all.
//
// Without xray.exe in the folder the updater falls back to what sing-box
// can do alone.

const (
	xrayImage    = "xray.exe"
	xrayBasePort = 17100
)

func xrayExe(dir string) string { return filepath.Join(dir, xrayImage) }

func xrayPresent(dir string) bool {
	_, err := os.Stat(xrayExe(dir))
	return err == nil
}

// needsXray tells whether a vless/trojan link must go through Xray.
func needsXray(q url.Values) bool {
	switch q.Get("type") {
	case "xhttp", "splithttp":
		return true
	}
	if e := q.Get("encryption"); e != "" && e != "none" {
		return true // VLESS post-quantum encryption: Xray only
	}
	return q.Get("security") == "reality"
}

// xrayOutbound builds the Xray outbound for a vless:// or trojan:// link.
// Xray reads these links' parameters natively, so this is mostly renaming.
func xrayOutbound(link string) (map[string]any, string, error) {
	u, host, port, err := splitLink(link)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	scheme := strings.ToLower(u.Scheme)

	ob := map[string]any{"protocol": scheme}
	switch scheme {
	case "vless":
		user := map[string]any{"id": u.User.Username(), "encryption": orDefault(q.Get("encryption"), "none")}
		if f := q.Get("flow"); f != "" {
			user["flow"] = f
		}
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": host, "port": port, "users": []any{user},
		}}}
	case "trojan":
		ob["settings"] = map[string]any{"servers": []any{map[string]any{
			"address": host, "port": port, "password": u.User.Username(),
		}}}
	default:
		return nil, "", fmt.Errorf("протокол %s не поддерживается", scheme)
	}

	ss, err := xrayStream(q, scheme)
	if err != nil {
		return nil, "", err
	}
	ob["streamSettings"] = ss
	return ob, u.Fragment, nil
}

func xrayStream(q url.Values, scheme string) (map[string]any, error) {
	ss := map[string]any{}

	network := q.Get("type")
	switch network {
	case "", "tcp", "raw":
		network = "raw"
		if q.Get("headerType") == "http" {
			req := map[string]any{"path": []string{orDefault(q.Get("path"), "/")}}
			if h := q.Get("host"); h != "" {
				req["headers"] = map[string]any{"Host": strings.Split(h, ",")}
			}
			ss["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		ss["wsSettings"] = map[string]any{"path": orDefault(q.Get("path"), "/"), "host": q.Get("host")}
	case "httpupgrade":
		ss["httpupgradeSettings"] = map[string]any{"path": orDefault(q.Get("path"), "/"), "host": q.Get("host")}
	case "grpc":
		ss["grpcSettings"] = map[string]any{"serviceName": q.Get("serviceName"), "multiMode": q.Get("mode") == "multi"}
	case "xhttp", "splithttp":
		network = "xhttp"
		xs := map[string]any{"path": orDefault(q.Get("path"), "/"), "host": q.Get("host"), "mode": orDefault(q.Get("mode"), "auto")}
		if extra := q.Get("extra"); extra != "" {
			if !json.Valid([]byte(extra)) {
				return nil, fmt.Errorf("битый параметр extra у XHTTP")
			}
			xs["extra"] = json.RawMessage(extra)
		}
		ss["xhttpSettings"] = xs
	default:
		return nil, fmt.Errorf("транспорт %s не поддерживается", network)
	}
	ss["network"] = network

	sec := q.Get("security")
	if scheme == "trojan" && sec == "" {
		sec = "tls"
	}
	switch sec {
	case "reality":
		rs := map[string]any{
			"serverName":  q.Get("sni"),
			"fingerprint": orDefault(q.Get("fp"), "chrome"),
			"publicKey":   q.Get("pbk"),
			"shortId":     q.Get("sid"),
		}
		if v := q.Get("spx"); v != "" {
			rs["spiderX"] = v
		}
		if v := q.Get("pqv"); v != "" {
			rs["mldsa65Verify"] = v
		}
		ss["security"] = "reality"
		ss["realitySettings"] = rs
	case "tls":
		ts := map[string]any{"serverName": q.Get("sni")}
		if v := q.Get("fp"); v != "" {
			ts["fingerprint"] = v
		}
		if v := q.Get("alpn"); v != "" {
			ts["alpn"] = strings.Split(v, ",")
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			ts["allowInsecure"] = true
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = ts
	case "", "none":
		ss["security"] = "none"
	default:
		return nil, fmt.Errorf("защита %s не поддерживается", sec)
	}

	// "fm" carries Xray's finalmask as is, e.g. TLS ClientHello fragmenting
	// for servers that DPI otherwise cuts off.
	if fm := q.Get("fm"); fm != "" && json.Valid([]byte(fm)) {
		ss["finalmask"] = json.RawMessage(fm)
	}
	return ss, nil
}

// buildXrayConfig lays out xray.json: one SOCKS inbound per server on
// 127.0.0.1, each routed to its own outbound.
func buildXrayConfig(servers []xrayServer) map[string]any {
	var inbounds, outbounds, rules []any
	for _, s := range servers {
		in := "in-" + s.tag
		inbounds = append(inbounds, map[string]any{
			"tag": in, "listen": "127.0.0.1", "port": s.port, "protocol": "socks",
			"settings": map[string]any{"udp": true, "ip": "127.0.0.1"},
		})
		outbounds = append(outbounds, s.ob)
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{in}, "outboundTag": s.tag})
	}
	outbounds = append(outbounds, map[string]any{"tag": "direct", "protocol": "freedom"})
	return map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none", "error": "xray.log"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"rules": rules},
	}
}

// xrayServer is one server handled by Xray: its outbound (tag included) and
// the local port sing-box reaches it on.
type xrayServer struct {
	tag  string
	port int
	ob   any
}

// socksTo is the sing-box side of an Xray server.
func socksTo(tag string, port int) map[string]any {
	return map[string]any{"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": port, "version": "5"}
}

// xrayOutboundsByTag reads the current xray.json so a provider that failed
// to download can keep its Xray servers too.
func xrayOutboundsByTag(dir string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	raw, err := os.ReadFile(filepath.Join(dir, "xray.json"))
	if err != nil {
		return out
	}
	gjson.GetBytes(raw, "outbounds").ForEach(func(_, v gjson.Result) bool {
		if t := v.Get("tag").String(); t != "" && t != "direct" {
			out[t] = json.RawMessage(v.Raw)
		}
		return true
	})
	return out
}

// xrayAddrs maps each Xray-backed tag to the real server address, for the
// tray menu: in config.json those servers all point at 127.0.0.1.
func xrayAddrs(dir string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(filepath.Join(dir, "xray.json"))
	if err != nil {
		return out
	}
	gjson.GetBytes(raw, "outbounds").ForEach(func(_, v gjson.Result) bool {
		addr := v.Get("settings.vnext.0.address").String()
		if addr == "" {
			addr = v.Get("settings.servers.0.address").String()
		}
		if addr != "" {
			out[v.Get("tag").String()] = addr
		}
		return true
	})
	return out
}
