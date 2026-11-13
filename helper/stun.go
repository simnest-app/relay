// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// A small STUN/TURN client (RFC 8489, RFC 8656), only what the self-check needs: a binding request, to see that the
// relay answers and how fast, and one allocation with a credential made from the secret, to see that the relay would
// really carry a call. Nothing is sent anywhere but to the relay being checked.

const (
	stunCookie = 0x2112A442

	typeBinding                = 0x0001
	typeAllocate               = 0x0003
	typeRefresh                = 0x0004
	typeCreatePermision        = 0x0008
	classSuccess        uint16 = 0x0100
	classError          uint16 = 0x0110

	attrUsername          = 0x0006
	attrMessageIntegrity  = 0x0008
	attrErrorCode         = 0x0009
	attrLifetime          = 0x000D
	attrXorPeerAddress    = 0x0012
	attrRealm             = 0x0014
	attrNonce             = 0x0015
	attrXorRelayedAddress = 0x0016
	attrRequestedTranport = 0x0019
	attrXorMappedAddress  = 0x0020
)

type stunAttr struct {
	typ uint16
	val []byte
}

type stunMessage struct {
	typ   uint16
	txid  [12]byte
	attrs []stunAttr
}

func newRequest(typ uint16, attrs ...stunAttr) *stunMessage {
	m := &stunMessage{typ: typ, attrs: attrs}
	rand.Read(m.txid[:])
	return m
}

// encode writes the message; with a key, MESSAGE-INTEGRITY is added last, over everything before it.
func (m *stunMessage) encode(key []byte) []byte {
	var body []byte
	for _, a := range m.attrs {
		body = binary.BigEndian.AppendUint16(body, a.typ)
		body = binary.BigEndian.AppendUint16(body, uint16(len(a.val)))
		body = append(body, a.val...)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
	}
	length := len(body)
	if key != nil {
		length += 24
	}
	out := make([]byte, 0, 20+length)
	out = binary.BigEndian.AppendUint16(out, m.typ)
	out = binary.BigEndian.AppendUint16(out, uint16(length))
	out = binary.BigEndian.AppendUint32(out, stunCookie)
	out = append(out, m.txid[:]...)
	out = append(out, body...)
	if key != nil {
		mac := hmac.New(sha1.New, key)
		mac.Write(out)
		out = binary.BigEndian.AppendUint16(out, attrMessageIntegrity)
		out = binary.BigEndian.AppendUint16(out, 20)
		out = mac.Sum(out)
	}
	return out
}

func decodeStun(b []byte) (*stunMessage, error) {
	if len(b) < 20 || binary.BigEndian.Uint32(b[4:8]) != stunCookie || int(binary.BigEndian.Uint16(b[2:4])) != len(b)-20 {
		return nil, errors.New("not a STUN message")
	}
	m := &stunMessage{typ: binary.BigEndian.Uint16(b[0:2])}
	copy(m.txid[:], b[8:20])
	for rest := b[20:]; len(rest) >= 4; {
		typ, n := binary.BigEndian.Uint16(rest[0:2]), int(binary.BigEndian.Uint16(rest[2:4]))
		if 4+n > len(rest) {
			return nil, errors.New("attribute runs past the message")
		}
		m.attrs = append(m.attrs, stunAttr{typ, rest[4 : 4+n]})
		rest = rest[min(len(rest), 4+(n+3)/4*4):]
	}
	return m, nil
}

func (m *stunMessage) get(typ uint16) []byte {
	for _, a := range m.attrs {
		if a.typ == typ {
			return a.val
		}
	}
	return nil
}

// errorCode is the code of an error response, 0 when there is none.
func (m *stunMessage) errorCode() int {
	v := m.get(attrErrorCode)
	if len(v) < 4 {
		return 0
	}
	return int(v[2]&7)*100 + int(v[3])
}

// xorAddress reads XOR-MAPPED-ADDRESS or XOR-RELAYED-ADDRESS.
func (m *stunMessage) xorAddress(typ uint16) (netip.AddrPort, bool) {
	v := m.get(typ)
	if len(v) < 8 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4]) ^ (stunCookie >> 16)
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[:4], stunCookie)
	copy(mask[4:], m.txid[:])
	switch {
	case v[1] == 1 && len(v) == 8:
		var a [4]byte
		for i := range a {
			a[i] = v[4+i] ^ mask[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case v[1] == 2 && len(v) == 20:
		var a [16]byte
		for i := range a {
			a[i] = v[4+i] ^ mask[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

// exchange sends a request over UDP and waits for its answer, sending again twice if none comes.
func exchange(conn net.Conn, req *stunMessage, key []byte, timeout time.Duration) (*stunMessage, time.Duration, error) {
	packet := req.encode(key)
	buf := make([]byte, 2048)
	wait := timeout / 4
	for try := 0; try < 3; try, wait = try+1, wait*2 {
		start := time.Now()
		if _, err := conn.Write(packet); err != nil {
			return nil, 0, err
		}
		conn.SetReadDeadline(start.Add(wait))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if m, err := decodeStun(buf[:n]); err == nil && m.txid == req.txid {
				return m, time.Since(start), nil
			}
		}
	}
	return nil, 0, errors.New("no answer")
}

// stunBinding asks the relay what address it sees us at; the time it takes is the round trip to the relay.
func stunBinding(addr string, timeout time.Duration) (netip.AddrPort, time.Duration, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	defer conn.Close()
	m, rtt, err := exchange(conn, newRequest(typeBinding), nil, timeout)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	mapped, ok := m.xorAddress(attrXorMappedAddress)
	if m.typ != typeBinding|classSuccess || !ok {
		return netip.AddrPort{}, 0, fmt.Errorf("unexpected answer 0x%04x", m.typ)
	}
	return mapped, rtt, nil
}

// credential is coturn's short-term credential (use-auth-secret): the user name carries its expiry, the password is
// HMAC-SHA1 of the user name with the shared secret.
func credential(secret, tag string, expires time.Time) (username, password string) {
	username = strconv.FormatInt(expires.Unix(), 10) + ":" + tag
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// xorPeer writes XOR-PEER-ADDRESS for an IPv4 or IPv6 peer.
func xorPeer(txid [12]byte, peer netip.Addr) []byte {
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[:4], stunCookie)
	copy(mask[4:], txid[:])
	raw := peer.AsSlice()
	v := []byte{0, 1, 0, 0}
	if len(raw) == 16 {
		v[1] = 2
	}
	binary.BigEndian.PutUint16(v[2:], 9^(stunCookie>>16))
	for i, b := range raw {
		v = append(v, b^mask[i])
	}
	return v
}

// turnAllocate makes one relay allocation with these credentials and gives it back at once. It returns the relayed
// address the relay handed out: what the other end of a call would send to. For each of peers it also asks the
// relay whether it would forward to that address (a permission; nothing is sent to the address itself) and returns
// the relay's answer: 0 for yes, else its error code (403 for an address it is told never to forward to).
func turnAllocate(addr, username, password string, timeout time.Duration, peers ...netip.Addr) (netip.AddrPort, map[netip.Addr]int, error) {
	relayed, answers, err := allocate(addr, username, password, timeout, peers)
	return relayed, answers, err
}

func allocate(addr, username, password string, timeout time.Duration, peers []netip.Addr) (netip.AddrPort, map[netip.Addr]int, error) {
	fail := func(err error) (netip.AddrPort, map[netip.Addr]int, error) { return netip.AddrPort{}, nil, err }
	relayed, answers, err := func() (netip.AddrPort, map[netip.Addr]int, error) {
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			return fail(err)
		}
		defer conn.Close()
		transport := stunAttr{attrRequestedTranport, []byte{17, 0, 0, 0}}
		// The first request carries no credentials; the relay answers 401 with its realm and a nonce.
		m, _, err := exchange(conn, newRequest(typeAllocate, transport), nil, timeout)
		if err != nil {
			return fail(err)
		}
		if m.typ != typeAllocate|classError || m.errorCode() != 401 || m.get(attrRealm) == nil || m.get(attrNonce) == nil {
			return fail(fmt.Errorf("the relay did not ask for credentials (0x%04x, error %d)", m.typ, m.errorCode()))
		}
		realm, nonce := m.get(attrRealm), m.get(attrNonce)
		key := md5.Sum([]byte(username + ":" + string(realm) + ":" + password))
		auth := []stunAttr{{attrUsername, []byte(username)}, {attrRealm, realm}, {attrNonce, nonce}}
		m, _, err = exchange(conn, newRequest(typeAllocate, append([]stunAttr{transport}, auth...)...), key[:], timeout)
		if err != nil {
			return fail(err)
		}
		if m.typ != typeAllocate|classSuccess {
			return fail(fmt.Errorf("the relay refused the allocation (error %d)", m.errorCode()))
		}
		relayed, ok := m.xorAddress(attrXorRelayedAddress)
		if !ok {
			return fail(errors.New("the relay gave no relayed address"))
		}
		answers := map[netip.Addr]int{}
		for _, peer := range peers {
			req := newRequest(typeCreatePermision)
			req.attrs = append([]stunAttr{{attrXorPeerAddress, xorPeer(req.txid, peer)}}, auth...)
			m, _, err := exchange(conn, req, key[:], timeout)
			switch {
			case err != nil:
				answers[peer] = -1
			case m.typ == typeCreatePermision|classSuccess:
				answers[peer] = 0
			default:
				answers[peer] = max(m.errorCode(), 1)
			}
		}
		// Given back, so a check does not hold one of the relay's ports until it times out.
		exchange(conn, newRequest(typeRefresh, append([]stunAttr{{attrLifetime, []byte{0, 0, 0, 0}}}, auth...)...), key[:], timeout/2)
		return relayed, answers, nil
	}()
	return relayed, answers, err
}
