package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

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

func TestMdnsInstanceName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"insp-47ccc14c._adb-tls-pairing._tcp", "insp-47ccc14c"},
		{"studio-gEyOIY6ovq._adb-tls-pairing._tcp.", "studio-gEyOIY6ovq"},
		{"adb-XYZ._adb-tls-connect._tcp", "adb-XYZ"},
	}
	for _, tt := range tests {
		if got := mdnsInstanceName(tt.name); got != tt.want {
			t.Fatalf("mdnsInstanceName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestFindNamedMdnsServiceMatchesQRInstance(t *testing.T) {
	services := parseMdnsServices("List of discovered mdns services\nadb-XYZ._adb-tls-connect._tcp\t192.168.1.8:40367\ninsp-47ccc14c._adb-tls-pairing._tcp\t192.168.1.9:37199\n")
	got, ok := findNamedMdnsService(services, "pairing", "insp-47ccc14c")
	if !ok || got.Address != "192.168.1.9:37199" {
		t.Fatalf("got=%#v ok=%v", got, ok)
	}
	if _, ok := findNamedMdnsService(services, "pairing", "studio-gEyOIY6ovq"); ok {
		t.Fatal("matched a different QR instance")
	}
}

func TestFindNamedMdnsServiceNormalizesInstance(t *testing.T) {
	services := parseMdnsServices(
		"List of discovered mdns services\n" +
			"insp-47ccc14c (2)\t_adb-tls-pairing._tcp\t192.168.1.9:37199\n" +
			"PIXEL-8._adb-tls-pairing._tcp\t192.168.1.10:37200\n" +
			"adb-XYZ._adb-tls-connect._tcp\t192.168.1.8:40367\n",
	)
	tests := []struct {
		name     string
		kind     string
		instance string
		wantAddr string
		wantOK   bool
	}{
		{"dedup suffix still matches the QR instance", "pairing", "insp-47ccc14c", "192.168.1.9:37199", true},
		{"instance match is case-insensitive", "pairing", "pixel-8", "192.168.1.10:37200", true},
		{"different instance does not match", "pairing", "insp-deadbeef", "", false},
		{"kind mismatch does not match", "connect", "insp-47ccc14c", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := findNamedMdnsService(services, tt.kind, tt.instance)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tt.wantOK)
			}
			if ok && got.Address != tt.wantAddr {
				t.Fatalf("address=%q, want %q", got.Address, tt.wantAddr)
			}
		})
	}
}

func shrinkWifiPollIntervals(t *testing.T) {
	t.Helper()
	oldPair, oldConn := wifiPairingPollInterval, wifiConnectPollInterval
	wifiPairingPollInterval, wifiConnectPollInterval = 5*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() {
		wifiPairingPollInterval, wifiConnectPollInterval = oldPair, oldConn
	})
}

// scriptedADB replays canned adb responses keyed on the invoked subcommand.
type scriptedADB struct {
	t            *testing.T
	mdnsCalls    int
	pairCalls    int
	connectCalls int
	mdns         func(calls int) string
	pair         func(calls int) ([]byte, error)
}

func (s *scriptedADB) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case joined == "mdns services":
		s.mdnsCalls++
		return []byte(s.mdns(s.mdnsCalls)), nil
	case strings.HasPrefix(joined, "pair "):
		s.pairCalls++
		return s.pair(s.pairCalls)
	case strings.HasPrefix(joined, "connect "):
		s.connectCalls++
		return []byte("connected to 192.168.3.195:37591\n"), nil
	case joined == "devices -l":
		return []byte("List of devices attached\n"), nil
	default:
		s.t.Fatalf("unexpected adb invocation: %v", args)
		return nil, nil
	}
}

const qrTestService = "insp-testqr01"
const qrTestPassword = "TestPass1"
const qrTestPairAddr = "192.168.3.195:37517"
const qrTestConnAddr = "192.168.3.195:37591"

func qrPairingMdns(paired bool) func(int) string {
	return func(calls int) string {
		if calls < 3 {
			return "List of discovered mdns services\n"
		}
		out := "List of discovered mdns services\n" +
			qrTestService + "\t_adb-tls-pairing._tcp\t" + qrTestPairAddr + "\n"
		if paired {
			out += "adb-AC4VVB4920006139-e7qVDv\t_adb-tls-connect._tcp\t" + qrTestConnAddr + "\n"
		}
		return out
	}
}

func TestRunWifiPairingConnectsAfterScan(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &scriptedADB{
		t:    t,
		mdns: qrPairingMdns(true),
		pair: func(calls int) ([]byte, error) {
			return []byte("Successfully paired to " + qrTestPairAddr + " [guid=adb-xxx]\n"), nil
		},
	}
	app := &App{client: &ADBClient{run: script.run}}
	session := &wifiPairingSession{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	app.runWifiPairing(ctx, session, qrTestService, qrTestPassword)
	got := session.snapshot()
	if got.State != "connected" {
		t.Fatalf("state=%q message=%q, want connected", got.State, got.Message)
	}
	if got.Serial != qrTestConnAddr {
		t.Fatalf("serial=%q, want %q", got.Serial, qrTestConnAddr)
	}
	if script.pairCalls != 1 {
		t.Fatalf("pairCalls=%d, want 1", script.pairCalls)
	}
}

func TestRunWifiPairingRetriesFailedPair(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &scriptedADB{
		t:    t,
		mdns: qrPairingMdns(true),
		pair: func(calls int) ([]byte, error) {
			if calls == 1 {
				return []byte("Failed to pair with " + qrTestPairAddr + "\n"), errors.New("exit status 1")
			}
			return []byte("Successfully paired to " + qrTestPairAddr + " [guid=adb-xxx]\n"), nil
		},
	}
	app := &App{client: &ADBClient{run: script.run}}
	session := &wifiPairingSession{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	app.runWifiPairing(ctx, session, qrTestService, qrTestPassword)
	if got := session.snapshot(); got.State != "connected" {
		t.Fatalf("state=%q message=%q, want connected after retry", got.State, got.Message)
	}
	if script.pairCalls != 2 {
		t.Fatalf("pairCalls=%d, want 2", script.pairCalls)
	}
}

func TestRunWifiPairingTimeoutWhenPhoneNeverScans(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &scriptedADB{
		t:    t,
		mdns: func(calls int) string { return "List of discovered mdns services\n" },
		pair: func(calls int) ([]byte, error) {
			t.Fatal("pair must not run when the phone never appears")
			return nil, nil
		},
	}
	app := &App{client: &ADBClient{run: script.run}}
	session := &wifiPairingSession{}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	app.runWifiPairing(ctx, session, qrTestService, qrTestPassword)
	got := session.snapshot()
	if got.State != "failed" || !strings.Contains(got.Message, "timed out") {
		t.Fatalf("got=%#v, want failed/timeout", got)
	}
}

func TestRunWifiPairingStoppedOnCancel(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &scriptedADB{
		t: t,
		mdns: func(calls int) string {
			// A broken daemon must not turn an explicit stop into a failure.
			return "List of discovered mdns services\n"
		},
		pair: func(calls int) ([]byte, error) {
			t.Fatal("pair must not run")
			return nil, nil
		},
	}
	app := &App{client: &ADBClient{run: script.run}}
	session := &wifiPairingSession{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	app.runWifiPairing(ctx, session, qrTestService, qrTestPassword)
	if got := session.snapshot(); got.State != "stopped" {
		t.Fatalf("got=%#v, want stopped", got)
	}
}
func TestPairAcceptsSuccessfulResponse(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) != 3 || args[0] != "pair" || args[1] != "192.168.1.9:37199" || args[2] != "GRtUBuwh" {
			t.Fatalf("args=%v", args)
		}
		return []byte("Successfully paired to 192.168.1.9:37199 [guid=adb-xxx]\n"), nil
	}}
	if err := client.Pair(context.Background(), "192.168.1.9:37199", "GRtUBuwh"); err != nil {
		t.Fatal(err)
	}
}

func TestPairRejectsFailedResponse(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Failed to pair with 192.168.1.9:37199\n"), nil
	}}
	if err := client.Pair(context.Background(), "192.168.1.9:37199", "secret"); err == nil {
		t.Fatal("expected error")
	}
}

func TestConnHost(t *testing.T) {
	if got := connHost("192.168.1.9:5555"); got != "192.168.1.9" {
		t.Fatalf("got %q", got)
	}
}

func TestWifiPairingDeviceFromService(t *testing.T) {
	tests := []struct {
		name    string
		service mdnsService
		want    WifiPairingDevice
	}{
		{
			name:    "ipv4 pairing service",
			service: mdnsService{Name: "Pixel-8._adb-tls-pairing._tcp", Kind: "pairing", Address: "192.168.1.9:37199"},
			want:    WifiPairingDevice{Name: "Pixel-8", Address: "192.168.1.9:37199", Host: "192.168.1.9", Port: "37199"},
		},
		{
			name:    "trailing dot in instance name",
			service: mdnsService{Name: "studio-gEyOIY6ovq._adb-tls-pairing._tcp.", Kind: "pairing", Address: "192.168.1.10:40011"},
			want:    WifiPairingDevice{Name: "studio-gEyOIY6ovq", Address: "192.168.1.10:40011", Host: "192.168.1.10", Port: "40011"},
		},
		{
			name:    "address without port keeps host and empty port",
			service: mdnsService{Name: "adb-XYZ._adb-tls-pairing._tcp", Kind: "pairing", Address: "192.168.1.11"},
			want:    WifiPairingDevice{Name: "adb-XYZ", Address: "192.168.1.11", Host: "192.168.1.11", Port: ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wifiPairingDeviceFromService(tt.service); got != tt.want {
				t.Fatalf("got=%#v want=%#v", got, tt.want)
			}
		})
	}
}

func TestIsPairingCode(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		valid bool
	}{
		{"six digits", "123456", true},
		{"too short", "12345", false},
		{"too long", "1234567", false},
		{"letters rejected", "ab12cd", false},
		{"empty", "", false},
		{"spaces rejected", "12 456", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPairingCode(tt.code); got != tt.valid {
				t.Fatalf("isPairingCode(%q) = %v, want %v", tt.code, got, tt.valid)
			}
		})
	}
}

func TestPairWithCodeValidation(t *testing.T) {
	tests := []struct {
		name    string
		address string
		code    string
		wantErr string
	}{
		{"empty address", "", "123456", "invalid pairing address"},
		{"malformed address", "not an address!", "123456", "invalid pairing address"},
		{"missing port", "192.168.1.9", "123456", "invalid pairing address"},
		{"bad port", "192.168.1.9:99999", "123456", "invalid pairing address"},
		{"empty code", "192.168.1.9:37199", "", "invalid pairing code"},
		{"short code", "192.168.1.9:37199", "123", "invalid pairing code"},
		{"non-numeric code", "192.168.1.9:37199", "ab12cd", "invalid pairing code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &App{client: &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				t.Fatal("adb must not run for invalid input")
				return nil, nil
			}}}
			err := app.PairWithCode(tt.address, tt.code)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// codeFlowADB replays a pairing-code flow: pair against the pairing port,
// then mDNS discovery of the _adb-tls-connect._tcp address on a different
// port. Call counters prove which phases ran.
type codeFlowADB struct {
	t            *testing.T
	mdnsCalls    int
	pairCalls    int
	connectCalls int
	connectAddr  string
	mdnsOutput   string
	pairOutput   string
	pairErr      error
}

func (s *codeFlowADB) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case joined == "mdns services":
		s.mdnsCalls++
		return []byte(s.mdnsOutput), nil
	case strings.HasPrefix(joined, "pair "):
		s.pairCalls++
		if len(args) != 3 {
			s.t.Fatalf("pair args=%v", args)
		}
		if s.pairErr != nil {
			return []byte(s.pairOutput), s.pairErr
		}
		return []byte(s.pairOutput), nil
	case strings.HasPrefix(joined, "connect "):
		s.connectCalls++
		s.connectAddr = args[1]
		return []byte("already connected to " + args[1] + "\n"), nil
	case joined == "devices -l":
		return []byte("List of devices attached\n"), nil
	default:
		s.t.Fatalf("unexpected adb invocation: %v", args)
		return nil, nil
	}
}

func TestPairWithCodeSuccessConnectsAfterPair(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t:          t,
		mdnsOutput: "List of discovered mdns services\nadb-PIXEL\t_adb-tls-connect._tcp\t192.168.1.9:40011\n",
		pairOutput: "Successfully paired to 192.168.1.9:37199 [guid=adb-xxx]\n",
	}
	app := &App{client: &ADBClient{run: script.run}}
	if err := app.PairWithCode("192.168.1.9:37199", "482910"); err != nil {
		t.Fatal(err)
	}
	if script.pairCalls != 1 {
		t.Fatalf("pairCalls=%d, want 1", script.pairCalls)
	}
	if script.connectCalls != 1 {
		t.Fatalf("connectCalls=%d, want 1: pair-only leaves the device list empty", script.connectCalls)
	}
	// The pairing port (37199) and the connect port (40011) differ: adb
	// connect must target the _adb-tls-connect._tcp address, never the
	// pairing address the code was typed against.
	if script.connectAddr != "192.168.1.9:40011" {
		t.Fatalf("connectAddr=%q, want 192.168.1.9:40011", script.connectAddr)
	}
}

func TestPairWithCodeFailure(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Failed to pair with 192.168.1.9:37199\n"), nil
	}}
	app := &App{client: client}
	if err := app.PairWithCode("192.168.1.9:37199", "482910"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPairAndConnectReturnsSerial(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t:          t,
		mdnsOutput: "List of discovered mdns services\nadb-PIXEL\t_adb-tls-connect._tcp\t192.168.1.9:40011\n",
		pairOutput: "Successfully paired to 192.168.1.9:37199 [guid=adb-xxx]\n",
	}
	app := &App{client: &ADBClient{run: script.run}}
	serial, err := app.PairAndConnect("192.168.1.9:37199", "482910")
	if err != nil {
		t.Fatal(err)
	}
	if serial != "192.168.1.9:40011" {
		t.Fatalf("serial=%q, want 192.168.1.9:40011", serial)
	}
}

func TestPairAndConnectPairFailureSkipsConnect(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t:          t,
		mdnsOutput: "List of discovered mdns services\n",
		pairOutput: "Failed to pair with 192.168.1.9:37199\n",
	}
	app := &App{client: &ADBClient{run: script.run}}
	_, err := app.PairAndConnect("192.168.1.9:37199", "482910")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "could not connect") {
		t.Fatalf("pair failure must not be reported as a connect failure: %v", err)
	}
	if script.connectCalls != 0 || script.mdnsCalls != 0 {
		t.Fatalf("connectCalls=%d mdnsCalls=%d, want 0: connect must not run when pair fails",
			script.connectCalls, script.mdnsCalls)
	}
}

func TestPairAndConnectConnectFailureWrapped(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t:          t,
		mdnsOutput: "List of discovered mdns services\n",
		pairOutput: "Successfully paired to 192.168.1.9:37199 [guid=adb-xxx]\n",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	app := &App{ctx: ctx, client: &ADBClient{run: script.run}}
	_, err := app.PairAndConnect("192.168.1.9:37199", "482910")
	if err == nil {
		t.Fatal("expected error")
	}
	// Pair succeeded but no _adb-tls-connect._tcp service ever appears: the
	// error must say so explicitly instead of looking like a pair failure.
	for _, want := range []string{"paired with 192.168.1.9:37199", "could not connect"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err=%q, want substring %q", err, want)
		}
	}
}

func TestPairAndConnectSelectsSafeConnectService(t *testing.T) {
	shrinkWifiPollIntervals(t)
	tests := []struct {
		name      string
		mdns      string
		wantAddr  string
		wantCalls int
	}{
		{
			name: "connects to the entry matching the paired host",
			mdns: "List of discovered mdns services\n" +
				"adb-OTHER\t_adb-tls-connect._tcp\t192.168.1.20:40011\n" +
				"adb-PIXEL\t_adb-tls-connect._tcp\t192.168.1.9:40011\n",
			wantAddr:  "192.168.1.9:40011",
			wantCalls: 1,
		},
		{
			name: "uses sole service when advertised host changed",
			mdns: "List of discovered mdns services\n" +
				"adb-PIXEL\t_adb-tls-connect._tcp\t192.168.3.94:38429\n",
			wantAddr:  "192.168.3.94:38429",
			wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := &codeFlowADB{
				t:          t,
				mdnsOutput: tt.mdns,
				pairOutput: "Successfully paired to 192.168.1.9:37199 [guid=adb-xxx]\n",
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			app := &App{ctx: ctx, client: &ADBClient{run: script.run}}
			_, err := app.PairAndConnect("192.168.1.9:37199", "482910")
			if script.connectAddr != tt.wantAddr {
				t.Fatalf("connectAddr=%q, want %q", script.connectAddr, tt.wantAddr)
			}
			if script.connectCalls != tt.wantCalls {
				t.Fatalf("connectCalls=%d, want %d", script.connectCalls, tt.wantCalls)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPairAndConnectRejectsAmbiguousMismatchedServices(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t: t,
		mdnsOutput: "List of discovered mdns services\n" +
			"adb-PIXEL\t_adb-tls-connect._tcp\t192.168.3.94:38429\n" +
			"adb-GALAXY\t_adb-tls-connect._tcp\t192.168.3.88:40123\n",
		pairOutput: "Successfully paired to 192.168.3.195:37905 [guid=adb-xxx]\n",
	}
	app := &App{client: &ADBClient{run: script.run}}
	_, err := app.PairAndConnect("192.168.3.195:37905", "482910")
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	for _, want := range []string{"multiple _adb-tls-connect services", "192.168.3.94:38429", "192.168.3.88:40123"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err=%q, want substring %q", err, want)
		}
	}
	if script.connectCalls != 0 {
		t.Fatalf("connectCalls=%d, want 0", script.connectCalls)
	}
}

func TestNormalizePairingAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"plain ipv4", "192.168.1.101:37743", "192.168.1.101:37743", false},
		{"surrounding whitespace", "  192.168.1.101:37743\n", "192.168.1.101:37743", false},
		{"inner spaces around colon", "192.168.1.101 : 37743", "192.168.1.101:37743", false},
		{"hostname lowercased", "Pixel-8:37743", "pixel-8:37743", false},
		{"ipv6 bracketed", "[fe80::1]:37199", "[fe80::1]:37199", false},
		{"missing port rejected", "192.168.1.9", "", true},
		{"empty rejected", "   ", "", true},
		{"port out of range", "192.168.1.9:99999", "", true},
		{"non-numeric port", "192.168.1.9:abc", "", true},
		{"garbage rejected", "not an address!", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePairingAddress(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizePairingAddress(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePairingAddress(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizePairingAddress(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePairingCode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"plain digits", "482910", "482910", false},
		{"spaces stripped", "482 910", "482910", false},
		{"dashes stripped", "482-910", "482910", false},
		{"newline trimmed", " 482910\n", "482910", false},
		{"too short", "123", "", true},
		{"letters only", "abcdef", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePairingCode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizePairingCode(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePairingCode(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizePairingCode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPairWithCodeNormalizesManualInput(t *testing.T) {
	shrinkWifiPollIntervals(t)
	var pairAddr, pairCode string
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case joined == "mdns services":
			return []byte("List of discovered mdns services\nadb-PIXEL\t_adb-tls-connect._tcp\t192.168.1.101:40011\n"), nil
		case strings.HasPrefix(joined, "pair "):
			pairAddr, pairCode = args[1], args[2]
			return []byte("Successfully paired to 192.168.1.101:37743 [guid=adb-xxx]\n"), nil
		case strings.HasPrefix(joined, "connect "):
			if args[1] != "192.168.1.101:40011" {
				t.Fatalf("connect args=%v, want the discovered connect address", args)
			}
			return []byte("connected to 192.168.1.101:40011\n"), nil
		case joined == "devices -l":
			return []byte("List of devices attached\n"), nil
		default:
			t.Fatalf("unexpected adb invocation: %v", args)
			return nil, nil
		}
	}}
	app := &App{client: client}
	if err := app.PairWithCode("  192.168.1.101 : 37743 ", "482 910"); err != nil {
		t.Fatal(err)
	}
	if pairAddr != "192.168.1.101:37743" || pairCode != "482910" {
		t.Fatalf("pairAddr=%q pairCode=%q", pairAddr, pairCode)
	}
}

func TestListWifiPairingDevicesFiltersPairing(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("List of discovered mdns services\nadb-XYZ._adb-tls-connect._tcp\t192.168.1.8:40367\nPixel-8._adb-tls-pairing._tcp\t192.168.1.9:37199\n"), nil
	}}
	app := &App{client: client}
	got, err := app.ListWifiPairingDevices()
	if err != nil {
		t.Fatal(err)
	}
	want := []WifiPairingDevice{{Name: "Pixel-8", Address: "192.168.1.9:37199", Host: "192.168.1.9", Port: "37199"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestListWifiPairingDevicesEmpty(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("List of discovered mdns services\n"), nil
	}}
	app := &App{client: client}
	got, err := app.ListWifiPairingDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got=%#v want empty", got)
	}
}

func TestParseMdnsServicesTable(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []mdnsService
	}{
		{
			name:  "current adb three column tabs",
			input: "List of discovered mdns services\ninsp-67a637d7\t_adb-tls-pairing._tcp\t192.168.3.195:37517\nadb-AC4VVB4920006139-e7qVDv\t_adb-tls-connect._tcp\t192.168.3.195:37591\n",
			want: []mdnsService{
				{Name: "insp-67a637d7._adb-tls-pairing._tcp", Kind: "pairing", Address: "192.168.3.195:37517"},
				{Name: "adb-AC4VVB4920006139-e7qVDv._adb-tls-connect._tcp", Kind: "connect", Address: "192.168.3.195:37591"},
			},
		},
		{
			name:  "legacy two column full name",
			input: "List of discovered mdns services\nadb-XYZ._adb-tls-pairing._tcp\t192.168.1.8:37199\n",
			want: []mdnsService{
				{Name: "adb-XYZ._adb-tls-pairing._tcp", Kind: "pairing", Address: "192.168.1.8:37199"},
			},
		},
		{
			name:  "trailing dots and spaces",
			input: "Pixel-8. \t _adb-tls-pairing._tcp. \t 192.168.1.9:37199 \n",
			want: []mdnsService{
				{Name: "Pixel-8._adb-tls-pairing._tcp", Kind: "pairing", Address: "192.168.1.9:37199"},
			},
		},
		{
			name:  "ipv6 pairing address",
			input: "Pixel-8\t_adb-tls-pairing._tcp\t[fe80::1]:37199\n",
			want: []mdnsService{
				{Name: "Pixel-8._adb-tls-pairing._tcp", Kind: "pairing", Address: "[fe80::1]:37199"},
			},
		},
		{
			name:  "header only",
			input: "List of discovered mdns services\n",
			want:  []mdnsService{},
		},
		{
			name:  "service type is never an address",
			input: "insp-67a637d7\t_adb-tls-pairing._tcp\n",
			want:  []mdnsService{},
		},
		{
			name:  "unknown service skipped",
			input: "printer\t_ipp._tcp\t192.168.1.5:631\nPixel-8\t_adb-tls-pairing._tcp\t192.168.1.9:37199\n",
			want: []mdnsService{
				{Name: "Pixel-8._adb-tls-pairing._tcp", Kind: "pairing", Address: "192.168.1.9:37199"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMdnsServices(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("got=%#v want=%#v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got[%d]=%#v want[%d]=%#v", i, got[i], i, tt.want[i])
				}
			}
		})
	}
}

func TestListWifiPairingDevicesThreeColumnFormat(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("List of discovered mdns services\ninsp-67a637d7\t_adb-tls-pairing._tcp\t192.168.3.195:37517\nadb-AC4VVB4920006139-e7qVDv\t_adb-tls-connect._tcp\t192.168.3.195:37591\n"), nil
	}}
	app := &App{client: client}
	got, err := app.ListWifiPairingDevices()
	if err != nil {
		t.Fatal(err)
	}
	want := []WifiPairingDevice{{Name: "insp-67a637d7", Address: "192.168.3.195:37517", Host: "192.168.3.195", Port: "37517"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestListWifiPairingDevicesEmptySkipsRestartWhenMdnsHealthy(t *testing.T) {
	calls := make(map[string]int)
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls[strings.Join(args, " ")]++
		if len(args) == 2 && args[0] == "mdns" && args[1] == "check" {
			return []byte("mdns daemon version [Openscreen discovery 0.0.0]\n"), nil
		}
		return []byte("List of discovered mdns services\n"), nil
	}}
	client.restart = func(ctx context.Context, enableMDNS bool) error {
		t.Fatal("restart must not run when mDNS is healthy but no phone is pairing")
		return nil
	}
	app := &App{client: client}
	got, err := app.ListWifiPairingDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got=%#v want empty", got)
	}
	if calls["mdns services"] != 1 || calls["mdns check"] != 1 {
		t.Fatalf("calls=%v", calls)
	}
}

func TestListWifiPairingDevicesEmptyRetriesAfterMdnsRestart(t *testing.T) {
	servicesCalls := 0
	restarts := 0
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "mdns" && args[1] == "check" {
			return nil, context.DeadlineExceeded
		}
		servicesCalls++
		if servicesCalls == 1 {
			return []byte("List of discovered mdns services\n"), nil
		}
		return []byte("List of discovered mdns services\nPixel-8\t_adb-tls-pairing._tcp\t192.168.1.9:37199\n"), nil
	}}
	client.restart = func(ctx context.Context, enableMDNS bool) error {
		if !enableMDNS {
			t.Fatal("restart must enable mDNS discovery")
		}
		restarts++
		return nil
	}
	app := &App{client: client}
	got, err := app.ListWifiPairingDevices()
	if err != nil {
		t.Fatal(err)
	}
	if restarts != 1 || servicesCalls != 2 {
		t.Fatalf("restarts=%d servicesCalls=%d", restarts, servicesCalls)
	}
	if len(got) != 1 || got[0].Address != "192.168.1.9:37199" {
		t.Fatalf("got=%#v", got)
	}
}

func TestMdnsCheckRejectsUnavailableDaemon(t *testing.T) {
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("mdns is not available\n"), nil
	}}
	if err := client.MdnsCheck(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
func TestListWifiPairingDevicesErrorFallsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping adb server restart fallback")
	}
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}}
	app := &App{client: client}
	if _, err := app.ListWifiPairingDevices(); err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeConnectHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ipv4 unchanged", "192.168.3.195", "192.168.3.195"},
		{"case folded", "PIXEL-8.Local", "pixel-8.local"},
		{"trailing dot stripped", "pixel-8.local.", "pixel-8.local"},
		{"brackets stripped", "[fe80::1]", "fe80::1"},
		{"zone suffix stripped", "fe80::1%wlan0", "fe80::1"},
		{"surrounding whitespace", "  192.168.3.195  ", "192.168.3.195"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeConnectHost(tt.input); got != tt.want {
				t.Fatalf("normalizeConnectHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestConnectHostMatches(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		remoteIP string
		want     bool
	}{
		{"exact ipv4", "192.168.3.195", "192.168.3.195", true},
		{"case insensitive hostname", "PIXEL-8.local", "pixel-8.local", true},
		{"trailing dot tolerated", "pixel-8.local.", "pixel-8.local", true},
		{"different host rejected", "192.168.1.20", "192.168.3.195", false},
		{"empty remote matches anything", "192.168.1.20", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := connectHostMatches(tt.service, tt.remoteIP); got != tt.want {
				t.Fatalf("connectHostMatches(%q, %q) = %v, want %v", tt.service, tt.remoteIP, got, tt.want)
			}
		})
	}
}

func TestSelectConnectServiceUsesIdentityWhenHostsDiffer(t *testing.T) {
	services := []mdnsService{
		{Name: "adb-OTHER._adb-tls-connect._tcp", Kind: "connect", Address: "192.168.3.88:40123"},
		{Name: "adb-PIXEL._adb-tls-connect._tcp", Kind: "connect", Address: "192.168.3.94:38429"},
	}
	got, err := selectConnectService(services, "192.168.3.195", "adb-PIXEL._adb-tls-pairing._tcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "192.168.3.94:38429" {
		t.Fatalf("address=%q, want 192.168.3.94:38429", got.Address)
	}
}

func TestConnectPairedDeviceMatchesNormalizedHost(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t:          t,
		mdnsOutput: "List of discovered mdns services\nadb-PIXEL\t_adb-tls-connect._tcp\t192.168.3.195:42009\n",
		pairOutput: "Successfully paired to 192.168.3.195:41837 [guid=adb-xxx]\n",
	}
	app := &App{client: &ADBClient{run: script.run}}
	// Uppercase + trailing-dot spelling of the same host must still match.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serial, err := app.connectPairedDevice(ctx, "192.168.3.195")
	if err != nil {
		t.Fatal(err)
	}
	if serial != "192.168.3.195:42009" {
		t.Fatalf("serial=%q, want 192.168.3.195:42009", serial)
	}
}

func TestConnectPairedDeviceSurfacesRawMdns(t *testing.T) {
	shrinkWifiPollIntervals(t)
	script := &codeFlowADB{
		t:          t,
		mdnsOutput: "List of discovered mdns services\n",
		pairOutput: "Successfully paired to 192.168.3.195:41837 [guid=adb-xxx]\n",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	app := &App{ctx: ctx, client: &ADBClient{run: script.run}}
	_, err := app.PairAndConnect("192.168.3.195:41837", "541102")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"paired with 192.168.3.195:41837", "could not connect", "mdns services output"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err=%q, want substring %q", err, want)
		}
	}
}

func TestConnectPairedDeviceRetriesTransientConnectFailure(t *testing.T) {
	shrinkWifiPollIntervals(t)
	connectCalls := 0
	client := &ADBClient{run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case joined == "mdns services":
			return []byte("List of discovered mdns services\nadb-PIXEL\t_adb-tls-connect._tcp\t192.168.3.195:42009\n"), nil
		case strings.HasPrefix(joined, "connect "):
			connectCalls++
			if connectCalls == 1 {
				return []byte("failed to connect\n"), errors.New("exit status 1")
			}
			return []byte("connected to 192.168.3.195:42009\n"), nil
		case joined == "devices -l":
			return []byte("List of devices attached\n"), nil
		default:
			t.Fatalf("unexpected adb invocation: %v", args)
			return nil, nil
		}
	}}
	app := &App{client: client}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serial, err := app.connectPairedDevice(ctx, "192.168.3.195")
	if err != nil {
		t.Fatal(err)
	}
	if serial != "192.168.3.195:42009" {
		t.Fatalf("serial=%q, want 192.168.3.195:42009", serial)
	}
	if connectCalls != 2 {
		t.Fatalf("connectCalls=%d, want 2: transient failure must be retried", connectCalls)
	}
}
