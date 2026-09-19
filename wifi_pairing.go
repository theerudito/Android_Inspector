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
	wifiConnectTimeout      = 30 * time.Second
	wifiPairingTimeout      = 5 * time.Minute
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
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		kind := ""
		switch {
		case strings.Contains(name, "_adb-tls-connect._tcp"):
			kind = "connect"
		case strings.Contains(name, "_adb-tls-pairing._tcp"):
			kind = "pairing"
		default:
			continue
		}
		services = append(services, mdnsService{Name: name, Kind: kind, Address: fields[1]})
	}
	return services
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
	if !enableMDNS {
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

func (c *ADBClient) MdnsServices(ctx context.Context) ([]mdnsService, error) {
	out, err := c.runADB(ctx, "mdns", "services")
	if err != nil {
		return nil, fmt.Errorf("list mDNS services: %w", err)
	}
	return parseMdnsServices(string(out)), nil
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

// StartWifiPairing advertises a host pairing service and returns a scannable QR offer.
func (a *App) StartWifiPairing() (WifiPairingOffer, error) {
	if _, err := a.client.commandName(); err != nil {
		return WifiPairingOffer{}, err
	}
	if err := a.client.StartServer(a.ctx); err != nil {
		return WifiPairingOffer{}, err
	}
	_ = a.client.restartADBServer(a.ctx, false)
	pubKey, err := loadHostADBPublicKey()
	if err != nil {
		return WifiPairingOffer{}, err
	}
	serviceName, password, payload, err := generateWifiPairingIdentity()
	if err != nil {
		return WifiPairingOffer{}, err
	}
	qrImage, err := encodeWifiQRImage(payload)
	if err != nil {
		return WifiPairingOffer{}, fmt.Errorf("encode pairing QR: %w", err)
	}
	cert, err := generatePairingCertificate()
	if err != nil {
		return WifiPairingOffer{}, fmt.Errorf("create pairing certificate: %w", err)
	}
	ip, iface, err := preferredLANIPv4()
	if err != nil {
		return WifiPairingOffer{}, err
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return WifiPairingOffer{}, fmt.Errorf("listen for pairing connections: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(a.ctx, wifiPairingTimeout)
	stopMDNS, err := startPairingMDNS(ctx, iface, net.ParseIP(ip), serviceName, port)
	if err != nil {
		cancel()
		_ = listener.Close()
		return WifiPairingOffer{}, fmt.Errorf("advertise pairing service: %w", err)
	}

	session := &wifiPairingSession{cancel: cancel}
	session.setStatus("waiting", "Scan the QR code from Wireless debugging on the phone.", "")

	a.pairingMu.Lock()
	if a.pairing != nil {
		a.pairing.cancel()
	}
	a.pairing = session
	a.pairingMu.Unlock()

	go a.runWifiPairing(ctx, session, listener, stopMDNS, []byte(password), cert, packPeerInfo(pubKey))
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

func (a *App) runWifiPairing(ctx context.Context, session *wifiPairingSession, listener net.Listener, stopMDNS func(), password []byte, cert tls.Certificate, peerInfo []byte) {
	defer stopMDNS()
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	conn, err := listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			session.setStatus("stopped", "Wi-Fi pairing closed.", "")
			return
		}
		session.setStatus("failed", "Waiting for the phone timed out or was blocked by the firewall.", "")
		return
	}
	defer conn.Close()
	session.setStatus("pairing", "Phone found. Completing secure pairing…", "")
	if err := runPairingHandshake(conn, password, cert, peerInfo); err != nil {
		session.setStatus("failed", "Pairing handshake failed. Scan again from the phone.", "")
		return
	}

	stopMDNS()
	_ = a.client.restartADBServer(ctx, true)
	remoteIP := connHost(conn.RemoteAddr().String())
	session.setStatus("connecting", "Paired. Connecting over Wi-Fi…", "")
	serial, err := a.connectPairedDevice(ctx, remoteIP)
	if err != nil {
		session.setStatus("failed", "Paired, but ADB could not connect yet. Keep Wireless debugging on and refresh devices.", "")
		return
	}
	session.setStatus("connected", "Connected over Wi-Fi.", serial)
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

func (a *App) connectPairedDevice(ctx context.Context, remoteIP string) (string, error) {
	deadline := time.Now().Add(wifiConnectTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		services, err := a.client.MdnsServices(ctx)
		if err != nil {
			lastErr = err
		} else {
			for _, service := range services {
				if service.Kind != "connect" {
					continue
				}
				host := connHost(service.Address)
				if remoteIP != "" && host != remoteIP {
					continue
				}
				if err := a.client.Connect(ctx, service.Address); err != nil {
					lastErr = err
					continue
				}
				return service.Address, nil
			}
		}
		devices, err := a.client.ListDevices(ctx)
		if err == nil {
			for _, device := range devices {
				if strings.Contains(device.Serial, remoteIP) && device.State == "device" {
					return device.Serial, nil
				}
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(800 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("paired device did not become visible over Wi-Fi")
}
