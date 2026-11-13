// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Check is one line of the self-check, in the owner's words.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Report is what the helper found out about the relay from this machine. Whether the relay can be reached from
// outside is checked by the gateway, which shows it on its own screen: the helper asks nobody outside.
type Report struct {
	At     time.Time `json:"at"`
	Checks []Check   `json:"checks"`
}

func (r Report) OK() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// addressNote says what kind of address the owner gave as the public one; empty when it looks public.
func addressNote(ip netip.Addr) string {
	switch {
	case cgnat.Contains(ip):
		return "这是运营商内网地址（运营商级 NAT）：外面连不进来，这台机器当不了中继"
	case ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified():
		return "这是内网地址，不是公网地址：请填路由器或云主机的公网地址"
	}
	return ""
}

// RunChecks looks at the relay from here: is it listening, does it take a credential made from the secret, and does
// it hand out the public address.
func RunChecks(c Config, secret string, now time.Time) Report {
	r := Report{At: now}
	add := func(name string, ok bool, detail string) { r.Checks = append(r.Checks, Check{name, ok, detail}) }
	ip, _ := netip.ParseAddr(c.ExternalIP)
	if note := addressNote(ip); note != "" {
		add("公网地址", false, note)
	} else {
		add("公网地址", true, c.ExternalIP)
	}
	if _, rtt, err := stunBinding(c.CoturnAddr, 2*time.Second); err != nil {
		add("中继在运行（UDP）", false, "没有应答："+err.Error())
		return r
	} else {
		add("中继在运行（UDP）", true, "应答用时 "+rtt.Round(time.Millisecond).String())
	}
	if conn, err := net.DialTimeout("tcp", c.CoturnAddr, 2*time.Second); err != nil {
		add("中继在运行（TCP）", false, "连不上："+err.Error())
	} else {
		conn.Close()
		add("中继在运行（TCP）", true, "可以连接")
	}
	user, pass := credential(secret, "selfcheck", now.Add(5*time.Minute))
	relayed, peers, err := turnAllocate(c.CoturnAddr, user, pass, 2*time.Second, append(append([]netip.Addr{}, publicPeers...), privatePeers...)...)
	switch {
	case err != nil:
		add("用密钥申请中继", false, err.Error())
	case relayed.Addr().Unmap() != ip.Unmap():
		add("用密钥申请中继", false, "中继给出的地址是 "+relayed.Addr().String()+"，不是设置的公网地址")
	case int(relayed.Port()) < c.MinPort || int(relayed.Port()) > c.MaxPort:
		add("用密钥申请中继", false, "中继给出的端口不在设置的范围内")
	default:
		add("用密钥申请中继", true, "成功，对方会连到 "+relayed.String())
	}
	if err == nil {
		// Both ways a forwarding rule can be wrong: one too many, and calls to ordinary addresses fail without any
		// other sign (the allocation above still works); one too few, and the relay reaches into its own network.
		var blocked, open []string
		for _, p := range publicPeers {
			if peers[p] != 0 {
				blocked = append(blocked, p.String())
			}
		}
		for _, p := range privatePeers {
			if peers[p] == 0 {
				open = append(open, p.String())
			}
		}
		switch {
		case len(blocked) > 0:
			add("转发规则", false, "中继拒绝转发到公网地址（"+strings.Join(blocked, "、")+"）：通话会连不通，请检查配置里的禁止规则")
		case len(open) > 0:
			add("转发规则", false, "中继愿意转发到内网地址（"+strings.Join(open, "、")+"）：请检查配置里的禁止规则")
		default:
			add("转发规则", true, "公网地址放行，内网和保留地址拒绝")
		}
	}
	return r
}

// The addresses the forwarding rules are tried with. No packet goes to any of them: the relay is only asked whether
// it would forward there. Public ones it must accept (IPv4 above all: a rule that covers IPv4 written as IPv6 has
// been seen to shut out every IPv4 address on an older coturn); the others it must refuse.
var (
	publicPeers  = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("223.5.5.5")}
	privatePeers = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("172.16.0.1"),
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("100.64.0.1")}
)

// checker keeps the latest report and runs the checks again when it is asked for one that has grown old.
type checker struct {
	mu     sync.Mutex
	last   Report
	config Config
	secret string
	now    func() time.Time
}

func (k *checker) report(maxAge time.Duration) Report {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now := k.now(); k.last.At.IsZero() || now.Sub(k.last.At) > maxAge {
		k.last = RunChecks(k.config, k.secret, now)
	}
	return k.last
}
