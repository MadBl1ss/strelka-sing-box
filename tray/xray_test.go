package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestNeedsXray(t *testing.T) {
	cases := map[string]bool{
		"security=reality&type=tcp":         true,
		"security=tls&type=xhttp":           true,
		"security=tls&type=ws":              false,
		"security=none&type=grpc":           false,
		"encryption=mlkem768x25519plus.x":   true,
		"security=tls&type=tcp&encryption=": false,
	}
	for q, want := range cases {
		u, _, _, _ := splitLink("vless://id@h:443?" + q)
		if got := needsXray(u.Query()); got != want {
			t.Errorf("%s: получил %v, ожидал %v", q, got, want)
		}
	}
}

func TestXrayOutbound(t *testing.T) {
	reality := "vless://uid@r.example.com:443?encryption=none&flow=xtls-rprx-vision&type=grpc&serviceName=g&security=reality&sni=a.com&fp=edge&pbk=PBK&sid=ab12&spx=%2F" +
		`&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%7D%5D%7D#x`
	ob, name, err := xrayOutbound(reality)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ob)
	for path, want := range map[string]string{
		"protocol":                                 "vless",
		"settings.vnext.0.address":                 "r.example.com",
		"settings.vnext.0.port":                    "443",
		"settings.vnext.0.users.0.id":              "uid",
		"settings.vnext.0.users.0.flow":            "xtls-rprx-vision",
		"streamSettings.network":                   "grpc",
		"streamSettings.grpcSettings.serviceName":  "g",
		"streamSettings.security":                  "reality",
		"streamSettings.realitySettings.publicKey": "PBK",
		"streamSettings.realitySettings.shortId":   "ab12",
		"streamSettings.realitySettings.spiderX":   "/",
		"streamSettings.finalmask.tcp.0.type":      "fragment",
	} {
		if got := gjson.GetBytes(b, path).String(); got != want {
			t.Errorf("%s = %q, ожидал %q", path, got, want)
		}
	}
	if name != "x" {
		t.Errorf("имя %q", name)
	}

	xhttp := "vless://uid@x.example.com:443?encryption=none&type=xhttp&path=%2Fmedia%2F&host=x.example.com&mode=packet-up" +
		"&extra=%7B%22xPaddingBytes%22%3A%2248-300%22%7D&security=tls&sni=cdn.example.net&fp=firefox&alpn=h2%2Chttp%2F1.1#y"
	ob, _, err = xrayOutbound(xhttp)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(ob)
	for path, want := range map[string]string{
		"streamSettings.network":                           "xhttp",
		"streamSettings.xhttpSettings.path":                "/media/",
		"streamSettings.xhttpSettings.mode":                "packet-up",
		"streamSettings.xhttpSettings.extra.xPaddingBytes": "48-300",
		"streamSettings.tlsSettings.serverName":            "cdn.example.net",
		"streamSettings.tlsSettings.alpn.1":                "http/1.1",
		"streamSettings.tlsSettings.fingerprint":           "firefox",
	} {
		if got := gjson.GetBytes(b, path).String(); got != want {
			t.Errorf("xhttp %s = %q, ожидал %q", path, got, want)
		}
	}
}

func TestParseLinksRoutesToXray(t *testing.T) {
	links := []string{
		"vless://id@r.example.com:443?security=reality&sni=a&pbk=K#%F0%9F%87%A9%F0%9F%87%AA%20R",
		"vless://id@x.example.com:443?security=tls&type=xhttp#%F0%9F%87%B1%F0%9F%87%BB%20X",
		"vless://id@w.example.com:443?security=tls&type=ws#%F0%9F%87%B3%F0%9F%87%B1%20W",
	}
	got := parseLinks(links, "p", map[string]int{}, true, func(string, ...any) {})
	if len(got) != 3 {
		t.Fatalf("серверов %d, ожидал 3", len(got))
	}
	kind := map[string]string{}
	for _, e := range got {
		if e.xray != nil {
			kind[e.tag] = "xray"
			if e.xray.(map[string]any)["tag"] != e.tag {
				t.Errorf("%s: у Xray-outbound не тот тег", e.tag)
			}
		} else {
			kind[e.tag] = "sing-box"
		}
	}
	if kind["p-DE"] != "xray" || kind["p-LV"] != "xray" || kind["p-NL"] != "sing-box" {
		t.Errorf("распределение: %v", kind)
	}

	// Without xray.exe the REALITY one falls back to sing-box and XHTTP is dropped.
	got = parseLinks(links, "p", map[string]int{}, false, func(string, ...any) {})
	if len(got) != 2 || got[0].xray != nil || got[1].xray != nil {
		t.Errorf("без xray: %+v", got)
	}
}

func TestBuildXrayConfig(t *testing.T) {
	cfg := buildXrayConfig([]xrayServer{
		{tag: "a-DE", port: 17100, ob: map[string]any{"tag": "a-DE", "protocol": "vless"}},
		{tag: "b-LV", port: 17101, ob: json.RawMessage(`{"tag":"b-LV","protocol":"vless"}`)},
	})
	b, _ := json.Marshal(cfg)
	if gjson.GetBytes(b, "inbounds.1.port").Int() != 17101 || gjson.GetBytes(b, "inbounds.1.listen").String() != "127.0.0.1" ||
		!gjson.GetBytes(b, "inbounds.0.settings.udp").Bool() {
		t.Errorf("inbounds: %s", gjson.GetBytes(b, "inbounds").Raw)
	}
	if gjson.GetBytes(b, `routing.rules.#(outboundTag=="b-LV").inboundTag.0`).String() != "in-b-LV" {
		t.Errorf("routing: %s", gjson.GetBytes(b, "routing").Raw)
	}
	if !strings.Contains(string(b), `"protocol":"freedom"`) {
		t.Error("нет direct")
	}
}

func TestCarryOverXrayServer(t *testing.T) {
	cur := []byte(`{"outbounds":[
		{"type":"socks","tag":"a-DE","server":"127.0.0.1","server_port":17100,"version":"5"},
		{"type":"socks","tag":"a-NL","server":"127.0.0.1","server_port":17101,"version":"5"}]}`)
	old := map[string]json.RawMessage{"a-DE": json.RawMessage(`{"tag":"a-DE","protocol":"vless"}`)}
	got := carryOver(cur, "a", map[string]int{}, old)
	if len(got) != 1 || got[0].tag != "a-DE" || got[0].xray == nil {
		t.Errorf("перенос xray-сервера: %+v", got)
	}
}
