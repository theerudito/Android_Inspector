package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

const pairingMDNSType = "_adb-tls-pairing._tcp.local."

func pairingMDNSNames(instance string) (host, fullName string) {
	return dns.Fqdn(instance + ".local"), dns.Fqdn(instance + "._adb-tls-pairing._tcp.local")
}

func pairingMDNSRecords(instance string, port int, ip net.IP) (answers, extras []dns.RR, err error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("mDNS advertisement requires IPv4")
	}
	host, fullName := pairingMDNSNames(instance)
	const cacheFlush = 0x8000
	answers = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{Name: pairingMDNSType, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
			Ptr: fullName,
		},
	}
	extras = []dns.RR{
		&dns.SRV{
			Hdr:    dns.RR_Header{Name: fullName, Rrtype: dns.TypeSRV, Class: dns.ClassINET | cacheFlush, Ttl: 120},
			Port:   uint16(port),
			Target: host,
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: fullName, Rrtype: dns.TypeTXT, Class: dns.ClassINET | cacheFlush, Ttl: 120},
			Txt: []string{""},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET | cacheFlush, Ttl: 120},
			A:   ip4,
		},
	}
	return answers, extras, nil
}

func packPairingMDNS(instance string, port int, ip net.IP) ([]byte, error) {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Authoritative = true
	msg.Compress = true
	var err error
	msg.Answer, msg.Extra, err = pairingMDNSRecords(instance, port, ip)
	if err != nil {
		return nil, err
	}
	return msg.Pack()
}

func startPairingMDNS(ctx context.Context, iface net.Interface, ip net.IP, instance string, port int) (func(), error) {
	answers, extras, err := pairingMDNSRecords(instance, port, ip)
	if err != nil {
		return nil, err
	}
	announcePacket, err := packPairingMDNS(instance, port, ip)
	if err != nil {
		return nil, err
	}
	conn, err := listenMDNSUDP()
	if err != nil {
		return nil, fmt.Errorf("listen mDNS: %w", err)
	}
	pc := ipv4.NewPacketConn(conn)
	_ = pc.SetControlMessage(ipv4.FlagInterface, true)
	_ = pc.SetMulticastTTL(255)
	if iface.Index != 0 {
		_ = pc.SetMulticastInterface(&iface)
		_ = pc.JoinGroup(&iface, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)})
	}
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	cm := (*ipv4.ControlMessage)(nil)
	if iface.Index != 0 {
		cm = &ipv4.ControlMessage{IfIndex: iface.Index}
	}
	host, fullName := pairingMDNSNames(instance)
	announce := func() {
		_, _ = pc.WriteTo(announcePacket, cm, dst)
	}
	announce()
	go func() {
		defer conn.Close()
		buf := make([]byte, 2048)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				announce()
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			reply := replyPairingMDNS(buf[:n], answers, extras, host, fullName)
			if reply == nil {
				continue
			}
			if udp, ok := src.(*net.UDPAddr); ok && !udp.IP.IsMulticast() && udp.Port != 5353 {
				_, _ = conn.WriteTo(reply, src)
				continue
			}
			_, _ = pc.WriteTo(reply, cm, dst)
		}
	}()
	return func() { _ = conn.Close() }, nil
}

func replyPairingMDNS(packet []byte, answers, extras []dns.RR, host, fullName string) []byte {
	var query dns.Msg
	if err := query.Unpack(packet); err != nil || query.Response || len(query.Question) == 0 {
		return nil
	}
	want := false
	for _, q := range query.Question {
		name := strings.ToLower(q.Name)
		if name == pairingMDNSType || name == fullName || name == host {
			want = true
			break
		}
	}
	if !want {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(&query)
	resp.Compress = true
	resp.Authoritative = true
	resp.RecursionDesired = false
	resp.Question = nil
	resp.Answer = answers
	resp.Extra = extras
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}
