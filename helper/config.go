// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// Version of this deployment package; shown on the page and carried in the code the gateway scans.
const Version = "0.1.0"

//go:embed turnserver.conf.tmpl
var confTemplate string

// Config is what the owner sets in .env. Only ExternalIP has no default.
type Config struct {
	// ExternalIP is this machine's public address, which the far end of a call sends to.
	ExternalIP string
	// Host is what phones are told to connect to: ExternalIP, or a domain name pointing at it.
	Host string
	// LANHosts are this machine's addresses in its own network, for a gateway in the same network: a home router
	// often will not carry a connection from inside to its own public address.
	LANHosts   []string
	Port       int
	MinPort    int
	MaxPort    int
	TotalQuota int
	UserQuota  int
	MaxKbps    int
	Realm      string
	// CoturnAddr is where the helper reaches coturn for its checks.
	CoturnAddr string
	// PagePort is the setup page's port.
	PagePort int
	DataDir  string
}

func envInt(get func(string) string, name string, def, lo, hi int) (int, error) {
	v := strings.TrimSpace(get(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be a number from %d to %d", name, lo, hi)
	}
	return n, nil
}

// LoadConfig reads and checks the settings; get is os.Getenv outside tests.
func LoadConfig(get func(string) string) (Config, error) {
	c := Config{ExternalIP: strings.TrimSpace(get("EXTERNAL_IP")), Host: strings.TrimSpace(get("RELAY_HOST")), Realm: strings.TrimSpace(get("REALM")),
		CoturnAddr: strings.TrimSpace(get("COTURN_ADDR")), DataDir: strings.TrimSpace(get("DATA_DIR"))}
	ip, err := netip.ParseAddr(c.ExternalIP)
	if err != nil {
		return c, errors.New("EXTERNAL_IP must be this machine's public IP address (set it in .env)")
	}
	c.ExternalIP = ip.String()
	if c.Host == "" {
		c.Host = c.ExternalIP
	}
	if strings.ContainsAny(c.Host, " /?#@\"'\\\n") || len(c.Host) > 253 {
		return c, errors.New("RELAY_HOST must be a host name or an IP address")
	}
	if c.Realm == "" {
		c.Realm = "cloudsim-relay"
	}
	if strings.ContainsAny(c.Realm, " \n=\"") {
		return c, errors.New("REALM must be one word")
	}
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	for _, h := range strings.Split(get("LAN_IP"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			a, err := netip.ParseAddr(h)
			if err != nil {
				return c, errors.New("LAN_IP must be IP addresses, separated by commas")
			}
			c.LANHosts = append(c.LANHosts, a.String())
		}
	}
	ints := []struct {
		to          *int
		name        string
		def, lo, hi int
	}{
		{&c.Port, "LISTEN_PORT", 3478, 1, 65535}, {&c.MinPort, "MIN_PORT", 49160, 1024, 65535}, {&c.MaxPort, "MAX_PORT", 49200, 1024, 65535},
		{&c.TotalQuota, "TOTAL_QUOTA", 20, 1, 10000}, {&c.UserQuota, "USER_QUOTA", 6, 1, 1000}, {&c.MaxKbps, "MAX_KBPS", 256, 32, 100000},
		{&c.PagePort, "PAGE_PORT", 8787, 1, 65535},
	}
	for _, i := range ints {
		if *i.to, err = envInt(get, i.name, i.def, i.lo, i.hi); err != nil {
			return c, err
		}
	}
	if c.MaxPort < c.MinPort {
		return c, errors.New("MAX_PORT must not be below MIN_PORT")
	}
	if c.CoturnAddr == "" {
		c.CoturnAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port))
	}
	return c, nil
}

// lanAddresses are this machine's private IPv4 addresses, for a gateway in the same network. Only meaningful when
// the helper shares the host's network; in a container network of its own it sees the container's.
func lanAddresses() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() && ip.Unmap().IsPrivate() {
				out = append(out, ip.Unmap().String())
			}
		}
	}
	return out
}

// Secret returns the relay's secret, making one on the first run: 32 random bytes, written as text, since coturn
// takes its secret as a string. It never leaves this machine except in the code the owner's gateway scans.
func Secret(dir string) (string, error) {
	path := filepath.Join(dir, "secret")
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= 32 {
			return s, nil
		}
		return "", fmt.Errorf("%s is too short to be a secret; delete it to have a new one made", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(raw)
	return s, os.WriteFile(path, []byte(s+"\n"), 0o600)
}

// Render is coturn's configuration for these settings.
func Render(c Config, secret string) (string, error) {
	t, err := template.New("conf").Parse(confTemplate)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	err = t.Execute(&out, struct {
		Config
		Secret string
		MaxBps int
	}{c, secret, c.MaxKbps * 1000 / 8})
	return out.String(), err
}

// Code is what the gateway scans or has pasted in: where the relay is and its secret.
type Code struct {
	Type string `json:"t"`
	V    int    `json:"v"`
	// Host and Port are for phones away from home; LAN for a gateway in the relay's own network.
	Host   string   `json:"host"`
	Port   int      `json:"port"`
	LAN    []string `json:"lan,omitempty"`
	Secret string   `json:"secret"`
	// Ver is this package's version, so the gateway can say when it is old.
	Ver string `json:"ver"`
}

// CodeType marks the code as ours, so a gateway does not take any other QR code for a relay.
const CodeType = "cloudsim-relay"

func (c Config) Code(secret string) string {
	b, _ := json.Marshal(Code{Type: CodeType, V: 1, Host: c.Host, Port: c.Port, LAN: c.LANHosts, Secret: secret, Ver: Version})
	return string(b)
}
