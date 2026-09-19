package main

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestIsVirtualInterface(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Wi-Fi", false},
		{"Ethernet", false},
		{"eth0", false},
		{"en0", false},
		{"wlan0", false},
		{"vEthernet (WSL)", true},
		{"VMware Network Adapter", true},
		{"Hyper-V Virtual Ethernet Adapter", true},
		{"docker0", true},
		{"veth0", true},
		{"br-1234abcd", true},
		{"utun0", true},
		{"awdl0", true},
		{"llw0", true},
	}
	for _, tt := range tests {
		if got := isVirtualInterface(tt.name); got != tt.want {
			t.Fatalf("isVirtualInterface(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestEncodeWifiQRImage(t *testing.T) {
	image, err := encodeWifiQRImage("WIFI:T:ADB;S:insp-abcd1234;P:Ab3dEf9k;;")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(image, "data:image/png;base64,") {
		t.Fatalf("unexpected image prefix %q", image[:min(32, len(image))])
	}
}

func TestPackPairingMDNSContainsService(t *testing.T) {
	packet, err := packPairingMDNS("insp-abcd1234", 37199, net.ParseIP("192.168.1.8"))
	if err != nil {
		t.Fatal(err)
	}
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		t.Fatal(err)
	}
	foundPTR := false
	foundSRV := false
	for _, rr := range msg.Answer {
		if rec, ok := rr.(*dns.PTR); ok && rec.Hdr.Name == pairingMDNSType && strings.HasPrefix(rec.Ptr, "insp-abcd1234.") {
			foundPTR = true
		}
	}
	for _, rr := range msg.Extra {
		if rec, ok := rr.(*dns.SRV); ok {
			if rec.Port != 37199 {
				t.Fatalf("SRV port=%d", rec.Port)
			}
			foundSRV = true
		}
	}
	if !foundPTR || !foundSRV {
		t.Fatalf("PTR=%v SRV=%v answers=%v extra=%v", foundPTR, foundSRV, msg.Answer, msg.Extra)
	}
}

func TestReplyPairingMDNSAnswersQuery(t *testing.T) {
	answers, extras, err := pairingMDNSRecords("insp-abcd1234", 37199, net.ParseIP("192.168.1.8"))
	if err != nil {
		t.Fatal(err)
	}
	host, fullName := pairingMDNSNames("insp-abcd1234")
	query := new(dns.Msg)
	query.SetQuestion(pairingMDNSType, dns.TypePTR)
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply := replyPairingMDNS(packed, answers, extras, host, fullName)
	if reply == nil {
		t.Fatal("expected mDNS reply")
	}
}

func TestWifiQRPayloadUsesADBWifiFormat(t *testing.T) {
	got := wifiQRPayload("insp-abcd1234", "Ab3dEf9k")
	want := "WIFI:T:ADB;S:insp-abcd1234;P:Ab3dEf9k;;"
	if got != want {
		t.Fatalf("wifiQRPayload() = %q, want %q", got, want)
	}
}

func TestGenerateWifiPairingIdentity(t *testing.T) {
	service, password, payload, err := generateWifiPairingIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(service, "insp-") || len(service) != 13 {
		t.Fatalf("service name %q", service)
	}
	if len(password) != 8 {
		t.Fatalf("password length %d", len(password))
	}
	if payload != wifiQRPayload(service, password) {
		t.Fatalf("payload %q", payload)
	}
}

func TestPairingHeaderRoundTrip(t *testing.T) {
	header := encodePairingHeader(wifiPairingTypeSPAKE2, 32)
	packetType, payloadLen, err := decodePairingHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if packetType != wifiPairingTypeSPAKE2 || payloadLen != 32 {
		t.Fatalf("type=%d len=%d", packetType, payloadLen)
	}
}

func TestDecodePairingHeaderRejectsEmptyPayload(t *testing.T) {
	header := encodePairingHeader(wifiPairingTypePeerInfo, 0)
	if _, _, err := decodePairingHeader(header); err == nil {
		t.Fatal("expected error")
	}
}

func TestPackPeerInfoWritesHostKey(t *testing.T) {
	info := packPeerInfo("QAAAATEST key@host")
	if len(info) != wifiPeerInfoSize {
		t.Fatalf("len=%d", len(info))
	}
	if info[0] != wifiPeerInfoRSAKey {
		t.Fatalf("type=%d", info[0])
	}
	got := string(bytes.TrimRight(info[1:], "\x00"))
	if got != "QAAAATEST key@host" {
		t.Fatalf("data=%q", got)
	}
}

func TestPairingAEADRoundTrip(t *testing.T) {
	alice, err := newPairingAEAD([]byte("same-key-material-for-both-peers"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := newPairingAEAD([]byte("same-key-material-for-both-peers"))
	if err != nil {
		t.Fatal(err)
	}
	plain := packPeerInfo("example")
	secret, err := alice.encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bob.decrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted peer info mismatch")
	}
}

func TestSPAKE2SamePasswordAgrees(t *testing.T) {
	password := []byte("secret-password")
	alice, err := newSPAKE2(spake2Alice, password)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := newSPAKE2(spake2Bob, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.finish(bob.msg); err != nil {
		t.Fatal(err)
	}
	if err := bob.finish(alice.msg); err != nil {
		t.Fatal(err)
	}
	plain := []byte("peer-info-bytes")
	secret, err := alice.cipher.encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bob.cipher.decrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("shared pairing cipher mismatch")
	}
}

func TestSPAKE2DifferentPasswordFails(t *testing.T) {
	alice, err := newSPAKE2(spake2Alice, []byte("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := newSPAKE2(spake2Bob, []byte("bravo"))
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.finish(bob.msg); err != nil {
		t.Fatal(err)
	}
	if err := bob.finish(alice.msg); err != nil {
		t.Fatal(err)
	}
	secret, err := alice.cipher.encrypt([]byte("payload-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.cipher.decrypt(secret); err == nil {
		t.Fatal("expected decrypt failure")
	}
}

func TestParseMdnsServices(t *testing.T) {
	got := parseMdnsServices("List of discovered mdns services\nadb-XYZ._adb-tls-connect._tcp\t192.168.1.8:40367\nadb-XYZ._adb-tls-pairing._tcp 192.168.1.8:37199\n")
	if len(got) != 2 {
		t.Fatalf("len=%d want 2: %#v", len(got), got)
	}
	if got[0].Kind != "connect" || got[0].Address != "192.168.1.8:40367" {
		t.Fatalf("connect = %#v", got[0])
	}
	if got[1].Kind != "pairing" || got[1].Address != "192.168.1.8:37199" {
		t.Fatalf("pairing = %#v", got[1])
	}
}

func TestConnHost(t *testing.T) {
	if got := connHost("192.168.1.9:5555"); got != "192.168.1.9" {
		t.Fatalf("got %q", got)
	}
}
