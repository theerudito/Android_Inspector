package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	wifiPairingTypeSPAKE2   = 0
	wifiPairingTypePeerInfo = 1
	wifiPeerInfoSize        = 8192
	wifiPeerInfoRSAKey      = 0
	wifiExportedKeySize     = 64
	// wifiPairTimeout bounds only the `adb pair` phase. The connect phase
	// gets its own, longer budget (wifiConnectTimeout) so a slow pair never
	// starves discovery of the _adb-tls-connect service.
	wifiPairTimeout = 30 * time.Second
	// wifiConnectTimeout bounds polling for the _adb-tls-connect service
	// after a successful pair. 60s covers phones that take a while to
	// advertise the connect service after the pairing screen closes.
	wifiConnectTimeout = 60 * time.Second
	wifiPairingTimeout = 5 * time.Minute
	// wifiConnectAttemptTimeout bounds each single `adb mdns services` /
	// `adb connect` / `adb devices -l` attempt inside the connect poll loop,
	// so one hung attempt can never burn the whole connect budget (which
	// previously surfaced as "context deadline exceeded" with no detail).
	wifiConnectAttemptTimeout = 12 * time.Second
	// maxMdnsRawInError caps how much raw `adb mdns services` output is
	// embedded in a connect-timeout error for user bug reports.
	maxMdnsRawInError = 2000
)

// Poll intervals are vars (not consts) so tests can shrink them without
// waiting out real-world mDNS discovery delays.
var (
	wifiPairingPollInterval = 800 * time.Millisecond
	wifiConnectPollInterval = 800 * time.Millisecond
)

var wifiExportedKeyLabel = "adb-label\x00"

type WifiPairingOffer struct {
	ServiceName string `json:"serviceName"`
	Password    string `json:"password"`
	QRPayload   string `json:"qrPayload"`
	QRImage     string `json:"qrImage"`
	Host        string `json:"host"`
}

type WifiPairingStatus struct {
	State   string `json:"state"`
	Message string `json:"message"`
	Serial  string `json:"serial,omitempty"`
}

type mdnsService struct {
	Name    string
	Kind    string
	Address string
}

// WifiPairingDevice describes a phone advertising Wireless debugging pairing
// over mDNS. Note: `adb mdns services` output carries no API-level column,
// so this type intentionally omits it instead of reporting guessed data.
type WifiPairingDevice struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Host    string `json:"host"`
	Port    string `json:"port"`
}

func wifiPairingDeviceFromService(service mdnsService) WifiPairingDevice {
	host, port, err := net.SplitHostPort(service.Address)
	if err != nil {
		host = connHost(service.Address)
		port = ""
	}
	return WifiPairingDevice{
		Name:    mdnsInstanceName(service.Name),
		Address: service.Address,
		Host:    host,
		Port:    port,
	}
}

type wifiPairingSession struct {
	mu     sync.Mutex
	status WifiPairingStatus
	cancel context.CancelFunc
}

type pairingAEAD struct {
	aead   cipher.AEAD
	encSeq uint64
	decSeq uint64
}

func newPairingAEAD(keyMaterial []byte) (*pairingAEAD, error) {
	key, err := hkdf.Key(sha256.New, keyMaterial, nil, "adb pairing_auth aes-128-gcm key", 16)
	if err != nil {
		return nil, fmt.Errorf("derive pairing cipher key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &pairingAEAD{aead: aead}, nil
}

func (c *pairingAEAD) nonce(seq uint64) []byte {
	nonce := make([]byte, c.aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce, seq)
	return nonce
}

func (c *pairingAEAD) encrypt(plain []byte) ([]byte, error) {
	out := c.aead.Seal(nil, c.nonce(c.encSeq), plain, nil)
	c.encSeq++
	return out, nil
}

func (c *pairingAEAD) decrypt(in []byte) ([]byte, error) {
	out, err := c.aead.Open(nil, c.nonce(c.decSeq), in, nil)
	if err != nil {
		return nil, err
	}
	c.decSeq++
	return out, nil
}

func wifiQRPayload(serviceName, password string) string {
	return fmt.Sprintf("WIFI:T:ADB;S:%s;P:%s;;", serviceName, password)
}

func generateWifiPairingIdentity() (serviceName, password, payload string, err error) {
	var raw [8]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", "", "", err
	}
	serviceName = "insp-" + hex.EncodeToString(raw[:4])
	password, err = randomWifiPassword(8)
	if err != nil {
		return "", "", "", err
	}
	return serviceName, password, wifiQRPayload(serviceName, password), nil
}

func encodeWifiQRImage(payload string) (string, error) {
	code, err := qrcode.New(payload, qrcode.High)
	if err != nil {
		return "", err
	}
	code.DisableBorder = false
	png, err := code.PNG(512)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func randomWifiPassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

func encodePairingHeader(packetType byte, payloadLen uint32) []byte {
	header := make([]byte, 6)
	header[0] = 1
	header[1] = packetType
	binary.BigEndian.PutUint32(header[2:], payloadLen)
	return header
}

func decodePairingHeader(header []byte) (byte, uint32, error) {
	if len(header) != 6 {
		return 0, 0, fmt.Errorf("invalid pairing header size")
	}
	if header[0] != 1 {
		return 0, 0, fmt.Errorf("unsupported pairing header version %d", header[0])
	}
	payload := binary.BigEndian.Uint32(header[2:])
	if payload == 0 || payload > wifiPeerInfoSize*2 {
		return 0, 0, fmt.Errorf("unsafe pairing payload size %d", payload)
	}
	return header[1], payload, nil
}

func packPeerInfo(pubKey string) []byte {
	info := make([]byte, wifiPeerInfoSize)
	info[0] = wifiPeerInfoRSAKey
	copy(info[1:], pubKey)
	return info
}

func loadHostADBPublicKey() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate ADB host key: %w", err)
	}
	path := filepath.Join(home, ".android", "adbkey.pub")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("ADB host key not found at %s; start ADB once so it can generate keys", path)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("ADB host key is empty")
	}
	return key, nil
}

func generatePairingCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Android"},
			CommonName:   "Adb",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.Issuer = template.Subject
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func isVirtualInterface(name string) bool {
	n := strings.ToLower(name)
	for _, needle := range []string{
		"virtual", "vmware", "vbox", "hyper-v", "vethernet", "docker",
		"wsl", "loopback", "bluetooth", "vpn", "tap", "tun", "pseudo",
		"awdl", "llw", "utun", "vmenet", "anpi", "veth", "virbr",
		"cni", "flannel", "br-", "kube",
	} {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}

func preferredLANIPv4() (string, net.Interface, error) {
	if ip, iface, err := defaultRouteIPv4(); err == nil {
		return ip, iface, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", net.Interface{}, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isVirtualInterface(iface.Name) {
			continue
		}
		ip, ok := ipv4OnInterface(iface)
		if ok {
			return ip, iface, nil
		}
	}
	return "", net.Interface{}, fmt.Errorf("no IPv4 network address is available for Wi-Fi pairing")
}

func defaultRouteIPv4() (string, net.Interface, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "", net.Interface{}, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil || local.IP.To4() == nil {
		return "", net.Interface{}, fmt.Errorf("no IPv4 default route")
	}
	ip := local.IP.To4().String()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", net.Interface{}, err
	}
	for _, iface := range ifaces {
		found, ok := ipv4OnInterface(iface)
		if ok && found == ip {
			return ip, iface, nil
		}
	}
	return ip, net.Interface{}, nil
}

func ipv4OnInterface(iface net.Interface) (string, bool) {
	addrs, err := iface.Addrs()
	if err != nil {
		return "", false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip.String(), true
	}
	return "", false
}

func parseMdnsServices(output string) []mdnsService {
	services := make([]mdnsService, 0)
	for _, rawLine := range strings.Split(output, "\n") {
		if strings.TrimSpace(rawLine) == "" {
			continue
		}
		fields := splitMdnsLine(rawLine)
		if len(fields) < 2 {
			continue
		}
		name, kind, address, ok := decodeMdnsFields(fields)
		if !ok {
			continue
		}
		services = append(services, mdnsService{Name: name, Kind: kind, Address: address})
	}
	return services
}

// splitMdnsLine splits on tabs when present (adb separates instance,
// service type and address with tabs) so instance names with spaces survive.
func splitMdnsLine(line string) []string {
	if strings.Contains(line, "\t") {
		parts := strings.Split(line, "\t")
		fields := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				fields = append(fields, part)
			}
		}
		return fields
	}
	return strings.Fields(line)
}

func mdnsKind(value string) string {
	switch {
	case strings.Contains(value, "_adb-tls-pairing"):
		return "pairing"
	case strings.Contains(value, "_adb-tls-connect"):
		return "connect"
	default:
		return ""
	}
}

// isMdnsAddress reports whether value looks like a dialable address, so the
// service-type column (e.g. "_adb-tls-pairing._tcp") is never mistaken for one.
func isMdnsAddress(value string) bool {
	if value == "" || strings.Contains(value, " ") || strings.Contains(value, "_adb-tls-") {
		return false
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return true
	}
	return net.ParseIP(strings.Trim(value, "[]")) != nil
}

func decodeMdnsFields(fields []string) (name, kind, address string, ok bool) {
	if len(fields) >= 3 {
		// Current adb format: instance, service-type, address.
		instance := strings.TrimSuffix(fields[0], ".")
		svcType := strings.Join(fields[1:len(fields)-1], " ")
		address = fields[len(fields)-1]
		kind = mdnsKind(svcType)
		if kind == "" {
			kind = mdnsKind(instance)
		}
		if kind == "" || !isMdnsAddress(address) {
			return "", "", "", false
		}
		if mdnsKind(instance) != "" {
			name = strings.TrimSuffix(instance, ".")
		} else {
			name = strings.TrimSuffix(instance+"."+strings.Trim(svcType, "."), ".")
		}
		return name, kind, address, true
	}
	// Legacy format: full-service-name plus address.
	if kind = mdnsKind(fields[0]); kind == "" {
		return "", "", "", false
	}
	if address = fields[1]; !isMdnsAddress(address) {
		return "", "", "", false
	}
	return strings.TrimSuffix(fields[0], "."), kind, address, true
}

func mdnsInstanceName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if i := strings.Index(name, "."); i >= 0 {
		return name[:i]
	}
	return name
}

// pairingDedupSuffix strips the " (N)" rename mDNS applies when two hosts
// claim the same instance name (adb shows e.g. "Pixel-8 (2)"). A renamed
// instance that still normalizes to our QR service name is the phone that
// scanned our code, so it must keep matching.
var pairingDedupSuffix = regexp.MustCompile(`\s\(\d+\)$`)

// normalizePairingInstance folds the two spellings adb may report for one
// mDNS instance: instance names are case-insensitive (RFC 6762) and adb
// appends a dedup suffix on collisions.
func normalizePairingInstance(name string) string {
	short := mdnsInstanceName(name)
	short = pairingDedupSuffix.ReplaceAllString(short, "")
	return strings.ToLower(short)
}

func findNamedMdnsService(services []mdnsService, kind, instance string) (mdnsService, bool) {
	want := normalizePairingInstance(instance)
	for _, service := range services {
		if service.Kind == kind && normalizePairingInstance(service.Name) == want {
			return service, true
		}
	}
	return mdnsService{}, false
}

func (c *ADBClient) restartADBServer(ctx context.Context, enableMDNS bool) error {
	name, err := c.commandName()
	if err != nil {
		return err
	}
	_, _ = c.runADB(ctx, "kill-server")
	cmdCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, "start-server")
	configureCommand(cmd)
	if enableMDNS {
		cmd.Env = append(os.Environ(), "ADB_MDNS_OPENSCREEN=1")
	} else {
		cmd.Env = append(os.Environ(), "ADB_MDNS=0", "ADB_MDNS_OPENSCREEN=0")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("start adb server: %w: %s", err, msg)
		}
		return fmt.Errorf("start adb server: %w", err)
	}
	return nil
}

func (c *ADBClient) Connect(ctx context.Context, address string) error {
	address = strings.TrimSpace(address)
	if address == "" || !serialPattern.MatchString(address) {
		return fmt.Errorf("a valid host:port is required")
	}
	out, err := c.runADB(ctx, "connect", address)
	msg := strings.TrimSpace(string(out))
	if err != nil {
		if msg != "" {
			return fmt.Errorf("connect %s: %w: %s", address, err, msg)
		}
		return fmt.Errorf("connect %s: %w", address, err)
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "failed") || strings.Contains(lower, "unable") || strings.Contains(lower, "cannot") {
		return fmt.Errorf("connect %s: %s", address, msg)
	}
	return nil
}

func (c *ADBClient) Pair(ctx context.Context, address, password string) error {
	normalizedAddress, err := normalizePairingAddress(address)
	if err != nil {
		return err
	}
	address = normalizedAddress
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("pairing password is required")
	}
	out, err := c.runADB(ctx, "pair", address, password)
	msg := strings.TrimSpace(string(out))
	if err != nil {
		if msg != "" {
			return fmt.Errorf("pair %s: %w: %s", address, err, msg)
		}
		return fmt.Errorf("pair %s: %w", address, err)
	}
	if !strings.Contains(strings.ToLower(msg), "successfully paired") {
		if msg == "" {
			return fmt.Errorf("pair %s: pairing was not accepted", address)
		}
		return fmt.Errorf("pair %s: %s", address, msg)
	}
	return nil
}

func (c *ADBClient) MdnsServices(ctx context.Context) ([]mdnsService, error) {
	services, _, err := c.MdnsServicesRaw(ctx)
	return services, err
}

// MdnsServicesRaw is MdnsServices plus the raw `adb mdns services` output,
// so connect-timeout errors can show the user exactly what the daemon
// advertised (missing service vs. mismatched host vs. stale daemon).
func (c *ADBClient) MdnsServicesRaw(ctx context.Context) ([]mdnsService, string, error) {
	out, err := c.runADB(ctx, "mdns", "services")
	if err != nil {
		return nil, "", fmt.Errorf("list mDNS services: %w", err)
	}
	return parseMdnsServices(string(out)), string(out), nil
}

// MdnsCheck reports whether the ADB mDNS daemon itself is answering.
func (c *ADBClient) MdnsCheck(ctx context.Context) error {
	out, err := c.runADB(ctx, "mdns", "check")
	if err != nil {
		return fmt.Errorf("mDNS discovery is unavailable: %w", err)
	}
	lower := strings.ToLower(strings.TrimSpace(string(out)))
	if strings.Contains(lower, "not available") || strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
		return fmt.Errorf("mDNS discovery is unavailable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func runPairingHandshake(conn net.Conn, password []byte, certificate tls.Certificate, peerInfo []byte) error {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("pairing TLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	ekm, err := state.ExportKeyingMaterial(wifiExportedKeyLabel, nil, wifiExportedKeySize)
	if err != nil {
		return fmt.Errorf("export pairing key material: %w", err)
	}
	auth, err := newSPAKE2(spake2Bob, append(append([]byte{}, password...), ekm...))
	if err != nil {
		return err
	}
	if err := writePairingPacket(tlsConn, wifiPairingTypeSPAKE2, auth.msg); err != nil {
		return err
	}
	theirType, theirSPAKE, err := readPairingPacket(tlsConn)
	if err != nil {
		return err
	}
	if theirType != wifiPairingTypeSPAKE2 {
		return fmt.Errorf("expected SPAKE2 pairing packet")
	}
	if err := auth.finish(theirSPAKE); err != nil {
		return err
	}
	encryptedInfo, err := auth.cipher.encrypt(peerInfo)
	if err != nil {
		return err
	}
	if err := writePairingPacket(tlsConn, wifiPairingTypePeerInfo, encryptedInfo); err != nil {
		return err
	}
	peerType, encryptedPeer, err := readPairingPacket(tlsConn)
	if err != nil {
		return err
	}
	if peerType != wifiPairingTypePeerInfo {
		return fmt.Errorf("expected peer-info pairing packet")
	}
	plain, err := auth.cipher.decrypt(encryptedPeer)
	if err != nil {
		return fmt.Errorf("decrypt peer info: %w", err)
	}
	if len(plain) != wifiPeerInfoSize {
		return fmt.Errorf("unexpected peer info size %d", len(plain))
	}
	return nil
}

func writePairingPacket(w io.Writer, packetType byte, payload []byte) error {
	if _, err := w.Write(encodePairingHeader(packetType, uint32(len(payload)))); err != nil {
		return fmt.Errorf("write pairing header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write pairing payload: %w", err)
	}
	return nil
}

func readPairingPacket(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("read pairing header: %w", err)
	}
	packetType, payloadLen, err := decodePairingHeader(header)
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read pairing payload: %w", err)
	}
	return packetType, payload, nil
}

func (s *wifiPairingSession) setStatus(state, message, serial string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = WifiPairingStatus{State: state, Message: message, Serial: serial}
}

func (s *wifiPairingSession) snapshot() WifiPairingStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// StartWifiPairing returns a scannable QR offer and waits for the phone to advertise pairing.
func (a *App) StartWifiPairing() (WifiPairingOffer, error) {
	if _, err := a.client.commandName(); err != nil {
		return WifiPairingOffer{}, err
	}
	if err := a.client.StartServer(a.ctx); err != nil {
		return WifiPairingOffer{}, err
	}
	if _, err := a.client.MdnsServices(a.ctx); err != nil {
		if err := a.client.restartADB(a.ctx, true); err != nil {
			return WifiPairingOffer{}, fmt.Errorf("enable ADB mDNS discovery: %w", err)
		}
	}
	serviceName, password, payload, err := generateWifiPairingIdentity()
	if err != nil {
		return WifiPairingOffer{}, err
	}
	qrImage, err := encodeWifiQRImage(payload)
	if err != nil {
		return WifiPairingOffer{}, fmt.Errorf("encode pairing QR: %w", err)
	}
	ip, _, err := preferredLANIPv4()
	if err != nil {
		ip = ""
	}
	ctx, cancel := context.WithTimeout(a.ctx, wifiPairingTimeout)
	session := &wifiPairingSession{cancel: cancel}
	session.setStatus("waiting", "Scan the QR code from Wireless debugging on the phone.", "")

	a.pairingMu.Lock()
	if a.pairing != nil {
		a.pairing.cancel()
	}
	a.pairing = session
	a.pairingMu.Unlock()

	go a.runWifiPairing(ctx, session, serviceName, password)
	return WifiPairingOffer{
		ServiceName: serviceName,
		Password:    password,
		QRPayload:   payload,
		QRImage:     qrImage,
		Host:        ip,
	}, nil
}

// WifiPairingStatus returns the current Wi-Fi pairing session state.
func (a *App) WifiPairingStatus() WifiPairingStatus {
	a.pairingMu.Lock()
	session := a.pairing
	a.pairingMu.Unlock()
	if session == nil {
		return WifiPairingStatus{State: "idle", Message: ""}
	}
	return session.snapshot()
}

// ListWifiPairingDevices returns phones currently advertising pairing mode
// over mDNS (Developer options > Wireless debugging > Pair with pairing code).
func (a *App) ListWifiPairingDevices() ([]WifiPairingDevice, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	services, err := a.client.MdnsServices(ctx)
	if err != nil {
		// Same recovery as StartWifiPairing: a stale server may have mDNS disabled.
		if restartErr := a.client.restartADB(ctx, true); restartErr != nil {
			return nil, fmt.Errorf("enable ADB mDNS discovery: %w", restartErr)
		}
		services, err = a.client.MdnsServices(ctx)
		if err != nil {
			return nil, err
		}
	}
	devices := pairingDevices(services)
	if len(devices) == 0 {
		// A stale server started without mDNS advertises nothing at all.
		// Restart with discovery enabled only when the daemon itself is
		// broken; otherwise an empty list simply means the phone is not on
		// the pairing screen. Restarting on every empty poll would drop
		// existing connections on each frontend refresh.
		if chkErr := a.client.MdnsCheck(ctx); chkErr != nil {
			if restartErr := a.client.restartADB(ctx, true); restartErr != nil {
				return nil, fmt.Errorf("enable ADB mDNS discovery: %w", restartErr)
			}
			services, err = a.client.MdnsServices(ctx)
			if err != nil {
				return nil, err
			}
			devices = pairingDevices(services)
		}
	}
	return devices, nil
}

func pairingDevices(services []mdnsService) []WifiPairingDevice {
	devices := make([]WifiPairingDevice, 0)
	for _, service := range services {
		if service.Kind != "pairing" {
			continue
		}
		devices = append(devices, wifiPairingDeviceFromService(service))
	}
	return devices
}

// PairWithCode pairs with a device using the 6-digit code shown on the phone
// and then auto-connects to it. It is a backward-compatible wrapper around
// PairAndConnect: the signature stays `(string, string) error` so existing
// Wails bindings and callers keep compiling, while the behavior is now
// pair+connect instead of pair-only.
func (a *App) PairWithCode(address, code string) error {
	_, err := a.PairAndConnect(address, code)
	return err
}

// PairAndConnect pairs with a device using the 6-digit code shown on the
// phone, then connects to it, returning the connected device serial
// (the `_adb-tls-connect._tcp` address, e.g. 192.168.1.9:37591).
//
// Why auto-connect is required: `adb pair <pairing-ip:pairing-port> <code>`
// only exchanges keys with the phone's pairing service
// (`_adb-tls-pairing._tcp`, an ephemeral port that changes every time the
// "Pair with pairing code" screen is opened). Pairing alone never creates an
// ADB device connection, so without a follow-up
// `adb connect <connect-ip:connect-port>` (`_adb-tls-connect._tcp`, a
// different port) the device list stays empty and the phone shows no
// connect/auth prompt. The QR flow already did this via
// connectPairedDevice; the pairing-code flow did not, which is why a
// successful pair still left the CONNECTION dropdown on
// "Select a device / No device selected".
//
// The connect address is discovered the same way as the QR flow: poll
// `adb mdns services` for a Kind=="connect" entry. The pairing address host is
// only a preference because Android can advertise the same phone from a
// different local address after pairing.
//
// A note on what the phone shows after a successful pair: the Device details
// entry on the phone (e.g. Usuario@JORGE-DEV plus a fingerprint like
// 6A:F9:...) is expected and correct. The name comes from this PC's ADB host
// key comment (the trailing `user@host` field in ~/.android/adbkey.pub) and
// the fingerprint is the phone's view of that key. Neither indicates a
// failure; the missing piece was only the `adb connect` step, added here.
//
// Errors are split so the UI can tell the phases apart: a pair failure is
// returned as-is (connect is never attempted), while a connect failure after
// a successful pair is wrapped as "paired with <addr> but ADB could not
// connect: ...".
func (a *App) PairAndConnect(address, code string) (string, error) {
	normalizedAddress, err := normalizePairingAddress(address)
	if err != nil {
		return "", err
	}
	normalizedCode, err := normalizePairingCode(code)
	if err != nil {
		return "", err
	}
	base := a.ctx
	if base == nil {
		base = context.Background()
	}
	pairCtx, cancelPair := context.WithTimeout(base, wifiPairTimeout)
	pairErr := a.client.Pair(pairCtx, normalizedAddress, normalizedCode)
	cancelPair()
	if pairErr != nil {
		return "", pairErr
	}
	connectCtx, cancelConnect := context.WithTimeout(base, wifiConnectTimeout)
	defer cancelConnect()
	serial, err := a.connectPairedDevice(connectCtx, connHost(normalizedAddress))
	if err != nil {
		return "", fmt.Errorf("paired with %s but ADB could not connect: %w. Keep Wireless debugging on and retry", normalizedAddress, err)
	}
	return serial, nil
}

func isPairingCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// normalizePairingCode strips whitespace and common separators so a typed or
// pasted code ("482 910", "482-910", trailing newline) matches the 6-digit
// code the list-row digit inputs already produce.
func normalizePairingCode(code string) (string, error) {
	var digits strings.Builder
	for _, r := range code {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	normalized := digits.String()
	if !isPairingCode(normalized) {
		return "", fmt.Errorf("invalid pairing code: enter the 6 digits shown on the phone pairing screen")
	}
	return normalized, nil
}

// normalizePairingAddress trims surrounding/inner whitespace, lowercases the
// host, and validates a dialable host:port (IPv4, bracketed IPv6, or DNS
// name). Discovered mDNS addresses already have this shape, so the transform
// is idempotent and the list flow is unaffected.
func normalizePairingAddress(address string) (string, error) {
	compact := strings.Join(strings.Fields(address), "")
	if compact == "" {
		return "", fmt.Errorf("invalid pairing address: enter the IP and port shown on the phone (e.g. 192.168.1.101:37743)")
	}
	host, port, err := net.SplitHostPort(compact)
	if err != nil {
		return "", fmt.Errorf("invalid pairing address %q: use IP:port like 192.168.1.101:37743", strings.TrimSpace(address))
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return "", fmt.Errorf("invalid pairing address %q: host is empty, use IP:port like 192.168.1.101:37743", strings.TrimSpace(address))
	}
	if net.ParseIP(host) == nil && !pairingHostPattern.MatchString(host) {
		return "", fmt.Errorf("invalid pairing address %q: host %q is not a valid IP or hostname", strings.TrimSpace(address), host)
	}
	portNum, err := net.LookupPort("tcp", port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid pairing address %q: port must be 1-65535", strings.TrimSpace(address))
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port, nil
	}
	return host + ":" + port, nil
}

var pairingHostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// StopWifiPairing cancels the active Wi-Fi pairing session, if any.
func (a *App) StopWifiPairing() {
	a.pairingMu.Lock()
	session := a.pairing
	a.pairing = nil
	a.pairingMu.Unlock()
	if session != nil {
		session.cancel()
	}
}

func (a *App) runWifiPairing(ctx context.Context, session *wifiPairingSession, serviceName, password string) {
	for {
		select {
		case <-ctx.Done():
			finishWifiPairing(ctx, session)
			return
		default:
		}
		services, err := a.client.MdnsServices(ctx)
		if err == nil {
			if service, ok := findNamedMdnsService(services, "pairing", serviceName); ok {
				session.setStatus("pairing", "Phone found. Completing secure pairing…", "")
				if err := a.client.Pair(ctx, service.Address, password); err != nil {
					session.setStatus("pairing", "Phone found. Pairing failed: "+shortPairingError(err)+". Retrying…", "")
				} else {
					session.setStatus("connecting", "Paired. Connecting over Wi-Fi…", "")
					serial, err := a.connectPairedDevice(ctx, connHost(service.Address), service.Name)
					if err != nil {
						session.setStatus("failed", "Paired, but ADB could not connect: "+shortPairingError(err)+" Keep Wireless debugging on and try again.", "")
						return
					}
					session.setStatus("connected", "Connected over Wi-Fi.", serial)
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			finishWifiPairing(ctx, session)
			return
		case <-time.After(wifiPairingPollInterval):
		}
	}
}

// finishWifiPairing reports why the QR loop ended: a fired deadline means the
// phone never completed the scan, anything else is an explicit stop.
func finishWifiPairing(ctx context.Context, session *wifiPairingSession) {
	if ctx.Err() == context.DeadlineExceeded {
		session.setStatus("failed", "Waiting for the phone timed out. Keep Wireless debugging on and scan again.", "")
		return
	}
	session.setStatus("stopped", "Wi-Fi pairing closed.", "")
}

// shortPairingError keeps raw adb failure text out of the status line.
func shortPairingError(err error) string {
	msg := strings.TrimSpace(err.Error())
	msg = strings.TrimPrefix(msg, "pair ")
	const maxLen = 120
	if len(msg) > maxLen {
		return msg[:maxLen] + "…"
	}
	return msg
}

func connHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.Trim(host, "[]")
	}
	return host
}

// normalizeConnectHost folds the spellings one mDNS host may appear under:
// case differences, a trailing dot, surrounding brackets (IPv6), and an
// IPv6 zone suffix. Without this, "192.168.3.195" never equals
// "[192.168.3.195]" or "PIXEL-8.local." and the connect poll skips the
// phone it just paired with.
func normalizeConnectHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.Trim(host, "[]")
	if i := strings.LastIndex(host, "%"); i >= 0 {
		if parsed := net.ParseIP(host[:i]); parsed != nil {
			host = host[:i]
		}
	}
	return strings.ToLower(host)
}

func connectHostMatches(serviceHost, remoteIP string) bool {
	if remoteIP == "" {
		return true
	}
	return normalizeConnectHost(serviceHost) == normalizeConnectHost(remoteIP)
}

func selectConnectService(services []mdnsService, remoteIP, identity string) (mdnsService, error) {
	candidates := make([]mdnsService, 0)
	for _, service := range services {
		if service.Kind == "connect" {
			candidates = append(candidates, service)
		}
	}
	if len(candidates) == 0 {
		return mdnsService{}, nil
	}
	for _, service := range candidates {
		if connectHostMatches(connHost(service.Address), remoteIP) {
			return service, nil
		}
	}
	if identity != "" {
		matches := make([]mdnsService, 0, 1)
		for _, service := range candidates {
			if normalizePairingInstance(service.Name) == normalizePairingInstance(identity) {
				matches = append(matches, service)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	addresses := make([]string, 0, len(candidates))
	for _, service := range candidates {
		addresses = append(addresses, service.Address)
	}
	return mdnsService{}, fmt.Errorf("multiple _adb-tls-connect services found with no matching host: %s", strings.Join(addresses, ", "))
}

func truncateMdnsRaw(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > maxMdnsRawInError {
		return raw[:maxMdnsRawInError] + "\n…(truncated)"
	}
	if raw == "" {
		return "(empty)"
	}
	return raw
}

func (a *App) connectPairedDevice(ctx context.Context, remoteIP string, identities ...string) (string, error) {
	deadline := time.Now().Add(wifiConnectTimeout)
	identity := ""
	if len(identities) > 0 {
		identity = identities[0]
	}
	var lastErr error
	var lastRaw string
	var seenConnect []string
	seenSet := make(map[string]bool)
pollLoop:
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, wifiConnectAttemptTimeout)
		services, raw, err := a.client.MdnsServicesRaw(attemptCtx)
		cancelAttempt()
		if err != nil {
			lastErr = err
		} else {
			lastRaw = string(raw)
			for _, service := range services {
				if service.Kind != "connect" {
					continue
				}
				if !seenSet[service.Address] {
					seenSet[service.Address] = true
					seenConnect = append(seenConnect, service.Address)
				}
			}
			service, selectErr := selectConnectService(services, remoteIP, identity)
			if selectErr != nil {
				return "", selectErr
			}
			if service.Address != "" {
				attemptCtx, cancelConnect := context.WithTimeout(ctx, wifiConnectAttemptTimeout)
				connectErr := a.client.Connect(attemptCtx, service.Address)
				cancelConnect()
				if connectErr != nil {
					lastErr = connectErr
					continue
				}
				return service.Address, nil
			}
		}
		attemptCtx, cancelDevices := context.WithTimeout(ctx, wifiConnectAttemptTimeout)
		devices, err := a.client.ListDevices(attemptCtx)
		cancelDevices()
		if err == nil {
			for _, device := range devices {
				if device.State == "device" &&
					(remoteIP == "" || strings.Contains(normalizeConnectHost(device.Serial), normalizeConnectHost(remoteIP))) {
					return device.Serial, nil
				}
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			break pollLoop
		case <-time.After(wifiConnectPollInterval):
		}
		if ctx.Err() != nil {
			break pollLoop
		}
	}
	if lastErr == nil && ctx.Err() != nil {
		lastErr = ctx.Err()
	}
	detail := fmt.Sprintf("no _adb-tls-connect service for host %q became visible; mdns services output:\n%s",
		remoteIP, truncateMdnsRaw(lastRaw))
	if len(seenConnect) > 0 {
		detail += fmt.Sprintf("\nconnect addresses seen during polling: %s", strings.Join(seenConnect, ", "))
	} else {
		detail += "\nno _adb-tls-connect address was advertised at all — close the pairing-code screen back to the main Wireless debugging screen (keep its toggle ON), stay on the same Wi-Fi, and check the PC firewall for ADB/mDNS."
	}
	if lastErr != nil {
		return "", fmt.Errorf("%s (last error: %v)", detail, lastErr)
	}
	return "", fmt.Errorf("%s", detail)
}
