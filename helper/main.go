// SPDX-License-Identifier: GPL-3.0-only

// The helper of a SimNest self-hosted media relay. It makes the relay's secret on the first run, writes coturn's
// configuration, and shows a page, in the machine's own network only, with the code the owner's gateway scans and a
// check of the relay. It never contacts the SimNest service or anything else outside this machine.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"rsc.io/qr"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		config, secret, err := setUp()
		if err != nil {
			log.Fatal(err)
		}
		serve(config, secret)
	case "render":
		// The same configuration, printed: for a relay set up without this package's compose file.
		config, err := LoadConfig(os.Getenv)
		if err != nil {
			log.Fatal(err)
		}
		secret, err := Secret(config.DataDir)
		if err != nil {
			log.Fatal(err)
		}
		conf, err := Render(config, secret)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(conf)
	case "healthy":
		// For the container's health check: coturn starts once its configuration is there.
		dir := os.Getenv("DATA_DIR")
		if dir == "" {
			dir = "/data"
		}
		if _, err := os.Stat(filepath.Join(dir, "turnserver.conf")); err != nil {
			os.Exit(1)
		}
	default:
		log.Fatalf("unknown command %q: serve, render or healthy", cmd)
	}
}

// setUp makes the secret if there is none and writes coturn's configuration.
func setUp() (Config, string, error) {
	config, err := LoadConfig(os.Getenv)
	if err != nil {
		return config, "", err
	}
	if len(config.LANHosts) == 0 {
		config.LANHosts = lanAddresses()
	}
	secret, err := Secret(config.DataDir)
	if err != nil {
		return config, "", err
	}
	conf, err := Render(config, secret)
	if err != nil {
		return config, "", err
	}
	return config, secret, os.WriteFile(filepath.Join(config.DataDir, "turnserver.conf"), []byte(conf), 0o600)
}

// pageToken is the key to the setup page, kept across restarts; the page's address with it is printed in the log.
func pageToken(dir string) (string, error) {
	path := filepath.Join(dir, "page-token")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	return token, os.WriteFile(path, []byte(token+"\n"), 0o600)
}

func serve(config Config, secret string) {
	token, err := pageToken(config.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	k := &checker{config: config, secret: secret, now: time.Now}
	host := "这台机器的局域网地址"
	if len(config.LANHosts) > 0 {
		host = config.LANHosts[0]
	}
	log.Printf("SimNest relay helper %s. Setup page (this network only): http://%s/?t=%s", Version, net.JoinHostPort(host, strconv.Itoa(config.PagePort)), token)
	go func() {
		// Once coturn is up, and then now and again, so the log shows when the relay stopped answering.
		for wait := 3 * time.Second; ; wait = 10 * time.Minute {
			time.Sleep(wait)
			if r := k.report(time.Minute); !r.OK() {
				for _, c := range r.Checks {
					if !c.OK {
						log.Printf("check failed: %s: %s", c.Name, c.Detail)
					}
				}
			}
		}
	}()
	server := &http.Server{Addr: ":" + strconv.Itoa(config.PagePort), Handler: page(config, secret, token, k),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 8 << 10}
	log.Fatal(server.ListenAndServe())
}

// local says whether a request comes from this machine or its own network: the page shows the relay's secret.
func local(remoteAddr string) bool {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-Hans"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>SimNest 自建中继</title>
<style>
:root{--bg:#f6f6f4;--card:#fff;--ink:#1c1c1a;--dim:#6b6b66;--ok:#1d7a46;--bad:#b3261e;--line:#e3e3df}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--card:#222220;--ink:#ecece8;--dim:#a0a09a;--ok:#6fcf97;--bad:#f2857d;--line:#34342f}}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}
main{max-width:560px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 8px}
p{margin:0 0 12px}.dim{color:var(--dim);font-size:14px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-top:16px}
img{display:block;width:260px;max-width:100%;height:auto;margin:8px auto;background:#fff;padding:12px;border-radius:8px;image-rendering:pixelated}
li{list-style:none;margin:0 0 8px;padding-left:26px;position:relative}ul{margin:0;padding:0}
li:before{position:absolute;left:0;font-weight:700}li.ok:before{content:"✓";color:var(--ok)}li.bad:before{content:"✕";color:var(--bad)}
textarea{width:100%;box-sizing:border-box;height:96px;font:13px/1.4 ui-monospace,monospace;border:1px solid var(--line);border-radius:8px;padding:8px;background:var(--bg);color:var(--ink)}
</style></head><body><main>
<h1>SimNest 自建中继</h1>
<p class="dim">部署包版本 {{.Version}}。这个页面只能在这台机器所在的局域网里打开。</p>
<section><h2>在网关上添加</h2>
<p>在网关上打开“自建中继”，拍下这个二维码，或者把下面的文字粘贴进去。</p>
<img alt="给网关扫的二维码" src="data:image/png;base64,{{.QR}}">
<details><summary>显示可以粘贴的文字</summary><textarea readonly>{{.Code}}</textarea></details>
<p class="dim">二维码里有这台中继的密钥。拿到它的人就能使用你的中继，所以不要截图发给别人。通话内容不受影响：通话两端之间另有加密，中继听不到。</p>
</section>
<section><h2>自检</h2><ul>
{{range .Report.Checks}}<li class="{{if .OK}}ok{{else}}bad{{end}}"><b>{{.Name}}</b>　{{.Detail}}</li>{{end}}
</ul>
<p class="dim">以上是从这台机器自己看到的。外面能不能连进来（端口 {{.Port}} 的 UDP 和 TCP、{{.MinPort}} 到 {{.MaxPort}} 的 UDP），由网关在添加时实测，结果显示在网关上。每通电话大约占 100 kbps 上行带宽。</p>
</section>
</main></body></html>`))

// page is the setup page and its JSON twin. Both want the token from the log, from a local address.
func page(config Config, secret, token string, k *checker) http.Handler {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'")
			if r.Method != http.MethodGet || !local(r.RemoteAddr) || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(token)) != 1 {
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/{$}", guard(func(w http.ResponseWriter, r *http.Request) {
		code := config.Code(secret)
		q, err := qr.Encode(code, qr.M)
		if err != nil {
			http.Error(w, "could not draw the code", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTemplate.Execute(w, map[string]any{"Version": Version, "QR": base64.StdEncoding.EncodeToString(q.PNG()), "Code": code,
			"Report": k.report(30 * time.Second), "Port": config.Port, "MinPort": config.MinPort, "MaxPort": config.MaxPort})
	}))
	mux.HandleFunc("/status.json", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"version": Version, "report": k.report(30 * time.Second)})
	}))
	return mux
}
