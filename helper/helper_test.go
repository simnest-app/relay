// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigDefaultsAndChecks(t *testing.T) {
	c, err := LoadConfig(env(map[string]string{"EXTERNAL_IP": "203.0.113.7"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "203.0.113.7" || c.Port != 3478 || c.MinPort != 49160 || c.MaxPort != 49359 || c.TotalQuota != 160 || c.UserQuota != 24 || c.MaxKbps != 256 ||
		c.CoturnAddr != "127.0.0.1:3478" || c.DataDir != "/data" {
		t.Fatalf("%+v", c)
	}
	for name, m := range map[string]map[string]string{
		"no address":        {},
		"a name as address": {"EXTERNAL_IP": "relay.example"},
		"port not a number": {"EXTERNAL_IP": "203.0.113.7", "LISTEN_PORT": "x"},
		"ports reversed":    {"EXTERNAL_IP": "203.0.113.7", "MIN_PORT": "50000", "MAX_PORT": "49000"},
		"host with a path":  {"EXTERNAL_IP": "203.0.113.7", "RELAY_HOST": "relay.example/x"},
		"realm with a line": {"EXTERNAL_IP": "203.0.113.7", "REALM": "a\nstatic-auth-secret=x"},
		"lan not an ip":     {"EXTERNAL_IP": "203.0.113.7", "LAN_IP": "nas.local"},
	} {
		if _, err := LoadConfig(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The secret is made once, long enough, readable only by its owner, and stays across restarts.
func TestSecretIsMadeOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	a, err := Secret(dir)
	if err != nil || len(a) < 43 {
		t.Fatalf("%q %v", a, err)
	}
	if b, _ := Secret(dir); b != a {
		t.Fatal("a second start made another secret")
	}
	if info, _ := os.Stat(filepath.Join(dir, "secret")); info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %v", info.Mode().Perm())
	}
	other, _ := Secret(t.TempDir())
	if other == a {
		t.Fatal("two relays got the same secret")
	}
	os.WriteFile(filepath.Join(dir, "secret"), []byte("short"), 0o600)
	if _, err := Secret(dir); err == nil {
		t.Fatal("a short secret was accepted")
	}
}

// The configuration keeps every protection the plan asks for (RELAY_SOFTWARE.md 5.1); a line lost here is a hole.
func TestRenderedConfigurationKeepsTheProtections(t *testing.T) {
	c, _ := LoadConfig(env(map[string]string{"EXTERNAL_IP": "203.0.113.7", "MAX_KBPS": "256"}))
	conf, err := Render(c, "the-secret")
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(conf, "\n") {
		lines[strings.TrimSpace(l)] = true
	}
	for _, want := range []string{
		"use-auth-secret", "static-auth-secret=the-secret", "fingerprint", "no-tcp-relay", "no-multicast-peers", "no-tls",
		"listening-port=3478", "min-port=49160", "max-port=49359", "external-ip=203.0.113.7", "total-quota=160", "user-quota=24", "max-bps=32000",
		// Private, loopback, link-local, carrier NAT and multicast, and IPv4 written as IPv6.
		"denied-peer-ip=10.0.0.0-10.255.255.255", "denied-peer-ip=127.0.0.0-127.255.255.255", "denied-peer-ip=169.254.0.0-169.254.255.255",
		"denied-peer-ip=172.16.0.0-172.31.255.255", "denied-peer-ip=192.168.0.0-192.168.255.255", "denied-peer-ip=100.64.0.0-100.127.255.255",
		"denied-peer-ip=224.0.0.0-255.255.255.255", "denied-peer-ip=::1", "denied-peer-ip=::ffff:0:0-::ffff:ffff:ffff", "denied-peer-ip=64:ff9b::-64:ff9b::ffff:ffff",
		"denied-peer-ip=2002::-2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		if !lines[want] {
			t.Errorf("the configuration lacks %q", want)
		}
	}
	// Nothing turns on what is off by default in coturn 4.18 (the management port, DTLS), and nothing it no longer
	// takes is left in: it logs those as errors.
	for _, gone := range []string{"cli", "cli-password", "no-cli", "no-dtls", "dtls-listening-port", "web-admin"} {
		for l := range lines {
			if l == gone || strings.HasPrefix(l, gone+"=") {
				t.Errorf("the configuration has %q", l)
			}
		}
	}
	// Every denied range is a pair of addresses of one family, low then high, and the ones an attack would use fall inside one.
	var ranges [][2]netip.Addr
	for l := range lines {
		if v, ok := strings.CutPrefix(l, "denied-peer-ip="); ok {
			lo, hi, isRange := strings.Cut(v, "-")
			if !isRange {
				hi = lo
			}
			a, errA := netip.ParseAddr(lo)
			b, errB := netip.ParseAddr(hi)
			if errA != nil || errB != nil || a.Is4() != b.Is4() || a.Compare(b) > 0 {
				t.Errorf("bad range %q", l)
			}
			ranges = append(ranges, [2]netip.Addr{a, b})
		}
	}
	for _, s := range []string{"10.1.2.3", "127.0.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1",
		"64:ff9b::a00:1", "64:ff9b:1::a00:1", "::ffff:0:10.0.0.1", "2002:a00:1::1", "fd00::1", "fe80::1"} {
		ip := netip.MustParseAddr(s)
		if ip.Is4In6() {
			ip = netip.AddrFrom16(ip.As16())
		}
		denied := false
		for _, r := range ranges {
			denied = denied || (r[0].Is4() == ip.Is4() && r[0].Compare(ip) <= 0 && ip.Compare(r[1]) <= 0)
		}
		if !denied {
			t.Errorf("%s is not in any denied range", s)
		}
	}
	// coturn compares an IPv4 peer as ::a.b.c.d: a range holding that form of a public address refuses every IPv4
	// peer (what happened on 2026-11-11). The last three are those forms of 1.1.1.1, 8.8.8.8 and 223.5.5.5.
	for _, s := range []string{"8.8.8.8", "203.0.113.7", "2400:3200::1", "::101:101", "::808:808", "::df05:505"} {
		ip := netip.MustParseAddr(s)
		for _, r := range ranges {
			if s != "203.0.113.7" && r[0].Is4() == ip.Is4() && r[0].Compare(ip) <= 0 && ip.Compare(r[1]) <= 0 {
				t.Errorf("public address %s is denied by %v", s, r)
			}
		}
	}
}

func TestCodeForTheGateway(t *testing.T) {
	c, _ := LoadConfig(env(map[string]string{"EXTERNAL_IP": "203.0.113.7", "RELAY_HOST": "relay.example", "LAN_IP": "192.168.1.10"}))
	var got Code
	if err := json.Unmarshal([]byte(c.Code("s3cret")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != CodeType || got.V != 1 || got.Host != "relay.example" || got.Port != 3478 || got.Secret != "s3cret" || got.Ver != Version || len(got.LAN) != 1 || got.LAN[0] != "192.168.1.10" {
		t.Fatalf("%+v", got)
	}
}

// fakeRelay answers as a TURN server does, checking the credential the way coturn checks one made from its secret.
func fakeRelay(t *testing.T, secret string, relayed netip.AddrPort) string {
	t.Helper()
	return fakeRelayDenying(t, secret, relayed, func(peer netip.Addr) bool {
		return peer.IsPrivate() || peer.IsLoopback() || peer.IsLinkLocalUnicast() || cgnat.Contains(peer)
	})
}

// fakeRelayDenying is fakeRelay with its own forwarding rule: the peers it refuses a permission for.
func fakeRelayDenying(t *testing.T, secret string, relayed netip.AddrPort, denied func(netip.Addr) bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	xor := func(m *stunMessage, ap netip.AddrPort) []byte {
		a := ap.Addr().As4()
		v := []byte{0, 1, 0, 0, a[0], a[1], a[2], a[3]}
		binary.BigEndian.PutUint16(v[2:], ap.Port()^(stunCookie>>16))
		var mask [4]byte
		binary.BigEndian.PutUint32(mask[:], stunCookie)
		for i := range mask {
			v[4+i] ^= mask[i]
		}
		return v
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := decodeStun(buf[:n])
			if err != nil {
				continue
			}
			reply := &stunMessage{txid: m.txid}
			switch {
			case m.typ == typeBinding:
				reply.typ = typeBinding | classSuccess
				reply.attrs = []stunAttr{{attrXorMappedAddress, xor(m, netip.MustParseAddrPort(from.String()))}}
			case m.get(attrUsername) == nil:
				reply.typ = m.typ | classError
				reply.attrs = []stunAttr{{attrErrorCode, []byte{0, 0, 4, 1}}, {attrRealm, []byte("test-realm")}, {attrNonce, []byte("nonce-1")}}
			default:
				// The password is recomputed from the user name, as coturn does, then the integrity over the packet.
				user := string(m.get(attrUsername))
				h := hmac.New(sha1.New, []byte(secret))
				h.Write([]byte(user))
				pass := base64.StdEncoding.EncodeToString(h.Sum(nil))
				key := md5.Sum([]byte(user + ":test-realm:" + pass))
				body := buf[:n-24]
				check := hmac.New(sha1.New, key[:])
				check.Write(body)
				if !hmac.Equal(check.Sum(nil), m.get(attrMessageIntegrity)) || string(m.get(attrNonce)) != "nonce-1" {
					reply.typ = m.typ | classError
					reply.attrs = []stunAttr{{attrErrorCode, []byte{0, 0, 4, 31}}}
				} else if m.typ == typeAllocate {
					reply.typ = typeAllocate | classSuccess
					reply.attrs = []stunAttr{{attrXorRelayedAddress, xor(m, relayed)}}
				} else if peer, ok := m.xorAddress(attrXorPeerAddress); m.typ == typeCreatePermision && ok && denied(peer.Addr()) {
					reply.typ = m.typ | classError
					reply.attrs = []stunAttr{{attrErrorCode, []byte{0, 0, 4, 3}}}
				} else {
					reply.typ = m.typ | classSuccess
				}
			}
			pc.WriteTo(reply.encode(nil), from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestBindingAndAllocation(t *testing.T) {
	relayed := netip.MustParseAddrPort("203.0.113.7:49170")
	addr := fakeRelay(t, "right-secret", relayed)
	mapped, rtt, err := stunBinding(addr, time.Second)
	if err != nil || !mapped.Addr().IsLoopback() || rtt <= 0 {
		t.Fatalf("binding: %v %v %v", mapped, rtt, err)
	}
	user, pass := credential("right-secret", "selfcheck", time.Now().Add(time.Minute))
	open, shut, v6 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")
	if got, peers, err := turnAllocate(addr, user, pass, time.Second, open, shut, v6); err != nil || got != relayed || peers[open] != 0 || peers[shut] != 403 || peers[v6] != 403 {
		t.Fatalf("allocation: %v %v %v", got, peers, err)
	}
	user, pass = credential("wrong-secret", "selfcheck", time.Now().Add(time.Minute))
	if _, _, err := turnAllocate(addr, user, pass, time.Second); err == nil {
		t.Fatal("a credential from another secret was accepted")
	}
	if _, _, err := stunBinding("127.0.0.1:9", 200*time.Millisecond); err == nil {
		t.Fatal("a port nobody listens on answered")
	}
}

// The coturn vector the control service's tests use: the helper, the service and the gateway must agree.
func TestCredentialMatchesCoturn(t *testing.T) {
	user, pass := credential("north", "username", time.Unix(1433895918, 0))
	if user != "1433895918:username" || pass != "Lnvy4u5dznX7KxCwfYaMn6dzmXQ=" {
		t.Fatalf("%s %s", user, pass)
	}
}

func TestChecksSayWhatIsWrong(t *testing.T) {
	c, _ := LoadConfig(env(map[string]string{"EXTERNAL_IP": "203.0.113.7"}))
	c.CoturnAddr = fakeRelay(t, "s", netip.MustParseAddrPort("203.0.113.7:49170"))
	// The fake relay speaks UDP only: the TCP line fails, the others pass.
	r := RunChecks(c, "s", time.Now())
	byName := map[string]Check{}
	for _, k := range r.Checks {
		byName[k.Name] = k
	}
	if !byName["公网地址"].OK || !byName["中继在运行（UDP）"].OK || !byName["用密钥申请中继"].OK || !byName["转发规则"].OK || byName["中继在运行（TCP）"].OK || r.OK() {
		t.Fatalf("%+v", r.Checks)
	}
	// A rule too many (every IPv4 address shut out, as a range over IPv4 written as IPv6 did on an older coturn) and
	// a rule too few (the relay's own network reachable) are both caught, though the allocation itself works.
	c.CoturnAddr = fakeRelayDenying(t, "s", netip.MustParseAddrPort("203.0.113.7:49170"), func(netip.Addr) bool { return true })
	if r := RunChecks(c, "s", time.Now()); r.Checks[len(r.Checks)-1].Name != "转发规则" || r.Checks[len(r.Checks)-1].OK || !strings.Contains(r.Checks[len(r.Checks)-1].Detail, "8.8.8.8") {
		t.Fatalf("every peer refused: %+v", r.Checks)
	}
	c.CoturnAddr = fakeRelayDenying(t, "s", netip.MustParseAddrPort("203.0.113.7:49170"), func(netip.Addr) bool { return false })
	if r := RunChecks(c, "s", time.Now()); r.Checks[len(r.Checks)-1].OK || !strings.Contains(r.Checks[len(r.Checks)-1].Detail, "10.0.0.1") {
		t.Fatalf("no peer refused: %+v", r.Checks)
	}
	c.CoturnAddr = fakeRelay(t, "s", netip.MustParseAddrPort("10.0.0.5:49170"))
	if r := RunChecks(c, "s", time.Now()); r.Checks[3].Name != "用密钥申请中继" || r.Checks[3].OK {
		t.Fatalf("a relay handing out a private address passed: %+v", r.Checks)
	}
	for ip, bad := range map[string]bool{"100.64.1.1": true, "192.168.1.5": true, "203.0.113.7": false, "2400:3200::1": false, "fd00::1": true} {
		if got := addressNote(netip.MustParseAddr(ip)) != ""; got != bad {
			t.Errorf("%s: flagged %v, want %v", ip, got, bad)
		}
	}
}

// The page shows the secret: it wants the token, from an address in this network, and nothing else is served.
func TestThePageWantsTheTokenFromThisNetwork(t *testing.T) {
	c, _ := LoadConfig(env(map[string]string{"EXTERNAL_IP": "203.0.113.7"}))
	c.CoturnAddr = "127.0.0.1:9"
	k := &checker{config: c, secret: "the-secret-of-this-relay", now: time.Now, last: Report{At: time.Now(), Checks: []Check{{"x", true, "y"}}}}
	h := page(c, k.secret, "0123456789abcdef0123456789abcdef", k)
	get := func(method, target, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	const good = "/?t=0123456789abcdef0123456789abcdef"
	if w := get("GET", good, "192.168.1.20:5000"); w.Code != 200 || !strings.Contains(w.Body.String(), "data:image/png;base64,") || !strings.Contains(w.Body.String(), "the-secret-of-this-relay") {
		t.Fatalf("the owner in the same network: %d", w.Code)
	}
	if w := get("GET", "/status.json?t=0123456789abcdef0123456789abcdef", "127.0.0.1:5000"); w.Code != 200 || strings.Contains(w.Body.String(), "the-secret") {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no token":            get("GET", "/", "192.168.1.20:5000"),
		"wrong token":         get("GET", "/?t=0123456789abcdef0123456789abcdee", "192.168.1.20:5000"),
		"from outside":        get("GET", good, "8.8.8.8:5000"),
		"from outside (IPv6)": get("GET", good, "[2400:3200::1]:5000"),
		"a POST":              get("POST", good, "192.168.1.20:5000"),
		"another path":        get("GET", "/secret?t=0123456789abcdef0123456789abcdef", "192.168.1.20:5000"),
		"the data directory":  get("GET", "/data/secret?t=0123456789abcdef0123456789abcdef", "192.168.1.20:5000"),
	} {
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "the-secret") {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

func TestPageTokenIsKept(t *testing.T) {
	dir := t.TempDir()
	a, err := pageToken(dir)
	b, _ := pageToken(dir)
	if err != nil || len(a) != 32 || a != b {
		t.Fatalf("%q %q %v", a, b, err)
	}
}
