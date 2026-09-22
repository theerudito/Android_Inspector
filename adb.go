package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const commandTimeout = 15 * time.Second
const maxTransferBytes = 64 << 20

type Device struct {
	Serial string `json:"serial"`
	State  string `json:"state"`
	Model  string `json:"model,omitempty"`
}

type FileContent struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Bytes     int    `json:"bytes"`
	LineCount int    `json:"lineCount"`
}

type FilePreview struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Content   string `json:"content,omitempty"`
	MIME      string `json:"mime,omitempty"`
	Type      string `json:"type"`
	Bytes     int    `json:"bytes"`
	LineCount int    `json:"lineCount,omitempty"`
}

type DirectoryEntry struct {
	Name         string `json:"name"`
	RelativePath string `json:"relativePath"`
	IsDirectory  bool   `json:"isDirectory"`
	Size         int64  `json:"size,omitempty"`
}

type DebugPackage struct {
	PackageName string `json:"packageName"`
	Label       string `json:"label"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)
type commandInputRunner func(context.Context, io.Reader, string, ...string) ([]byte, error)

type ADBClient struct {
	run      commandRunner
	runInput commandInputRunner
	adbPath  string
	adbErr   error
	// restart restarts the ADB server with mDNS discovery enabled.
	// It defaults to restartADBServer and is a seam for tests.
	restart func(context.Context, bool) error
}

func NewADBClient() *ADBClient {
	adbPath, err := resolveADBPath()
	c := &ADBClient{run: runCommand, runInput: runCommandInput, adbPath: adbPath, adbErr: err}
	c.restart = c.restartADBServer
	return c
}

// restartADB restarts the ADB server, falling back to restartADBServer when
// no test seam is installed.
func (c *ADBClient) restartADB(ctx context.Context, enableMDNS bool) error {
	if c.restart != nil {
		return c.restart(ctx, enableMDNS)
	}
	return c.restartADBServer(ctx, enableMDNS)
}

const adbSetupHint = "configure ADB_PATH, set ANDROID_HOME or ANDROID_SDK_ROOT, install Android SDK Platform-Tools in a standard SDK location, or add adb to PATH"

func resolveADBPath() (string, error) {
	configured := strings.TrimSpace(os.Getenv("ADB_PATH"))
	if path, ok := selectExistingADBPath(adbCandidates(runtime.GOOS, configured, os.Getenv("ANDROID_HOME"), os.Getenv("ANDROID_SDK_ROOT"), homeDirectory())); ok {
		return path, nil
	}
	name := "adb"
	if runtime.GOOS == "windows" {
		name = "adb.exe"
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("ADB executable not found; %s", adbSetupHint)
}

func homeDirectory() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return ""
}

func adbCandidates(goos, configured, androidHome, sdkRoot, home string) []string {
	executable := "adb"
	if goos == "windows" {
		executable = "adb.exe"
	}
	paths := make([]string, 0, 6)
	if configured != "" {
		paths = append(paths, configured)
	}
	for _, root := range []string{androidHome, sdkRoot} {
		if root != "" {
			paths = append(paths, filepath.Join(root, "platform-tools", executable))
		}
	}
	if home != "" {
		switch goos {
		case "windows":
			paths = append(paths,
				filepath.Join(home, "AppData", "Local", "Android", "Sdk", "platform-tools", executable),
				filepath.Join(home, "AppData", "Android", "Sdk", "platform-tools", executable))
		case "darwin":
			paths = append(paths, filepath.Join(home, "Library", "Android", "sdk", "platform-tools", executable))
		case "linux":
			paths = append(paths, filepath.Join(home, "Android", "Sdk", "platform-tools", executable))
		}
	}
	return paths
}

func selectExistingADBPath(candidates []string) (string, bool) {
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

func (c *ADBClient) commandName() (string, error) {
	if c.adbErr != nil {
		return "", c.adbErr
	}
	if c.adbPath != "" {
		return c.adbPath, nil
	}
	return "adb", nil
}

func (c *ADBClient) runADB(ctx context.Context, args ...string) ([]byte, error) {
	name, err := c.commandName()
	if err != nil {
		return nil, err
	}
	return c.run(ctx, name, args...)
}

func (c *ADBClient) runADBInput(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	name, err := c.commandName()
	if err != nil {
		return nil, err
	}
	return c.runInput(ctx, input, name, args...)
}

func (c *ADBClient) Detect(ctx context.Context) (string, error) {
	out, err := c.runADB(ctx, "version")
	if err != nil {
		return "", fmt.Errorf("adb is not available: %w", err)
	}
	return string(out), nil
}

// StartServer starts the ADB server and performs its normal authentication setup.
func (c *ADBClient) StartServer(ctx context.Context) error {
	if _, err := c.runADB(ctx, "start-server"); err != nil {
		return fmt.Errorf("start adb server: %w", err)
	}
	return nil
}

func (c *ADBClient) ListDevices(ctx context.Context) ([]Device, error) {
	out, err := c.runADB(ctx, "devices", "-l")
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return parseDevices(string(out)), nil
}

func (c *ADBClient) ListDebugPackages(ctx context.Context, serial string) ([]DebugPackage, error) {
	args, err := listPackagesCommand(serial)
	if err != nil {
		return nil, err
	}
	out, err := c.runADB(ctx, args[1:]...)
	if err != nil {
		return nil, fmt.Errorf("list packages on %s: check that the device is authorized and online: %w", serial, err)
	}
	candidates := parseThirdPartyPackages(string(out))
	packages := make([]DebugPackage, 0, len(candidates))
	for _, packageName := range candidates {
		checkArgs, err := runAsCheckCommand(serial, packageName)
		if err != nil {
			continue
		}
		if _, err := c.runADB(ctx, checkArgs[1:]...); err != nil {
			continue
		}
		packages = append(packages, DebugPackage{PackageName: packageName, Label: packageName})
	}
	if len(packages) == 0 && len(candidates) > 0 {
		return nil, fmt.Errorf("no third-party packages are accessible with run-as; only debuggable apps can be inspected")
	}
	return packages, nil
}

func (c *ADBClient) ReadFile(ctx context.Context, serial, packageName, path string) (FileContent, error) {
	args, err := readCommand(serial, packageName, path)
	if err != nil {
		return FileContent{}, err
	}
	out, err := c.runADB(ctx, args[1:]...)
	if err != nil {
		return FileContent{}, fmt.Errorf("read %q: %w", path, err)
	}
	content := string(out)
	return FileContent{Path: path, Content: content, Bytes: len(out), LineCount: lineCount(content)}, nil
}

func (c *ADBClient) PreviewFile(ctx context.Context, serial, packageName, filePath string, size int64) (FilePreview, error) {
	kind, mimeType, fileType := classifyPreview(filePath)
	preview := FilePreview{Path: filePath, Kind: kind, MIME: mimeType, Type: fileType, Bytes: int(size)}
	if kind == "binary" {
		return preview, nil
	}
	if kind == "text" {
		content, err := c.ReadFile(ctx, serial, packageName, filePath)
		if err != nil {
			return FilePreview{}, err
		}
		preview.Content = content.Content
		preview.Bytes = content.Bytes
		preview.LineCount = content.LineCount
		return preview, nil
	}
	content, err := c.downloadBytes(ctx, serial, packageName, filePath)
	if err != nil {
		return FilePreview{}, fmt.Errorf("preview %q: %w", filePath, err)
	}
	if err := validatePreviewBytes(kind, content); err != nil {
		return FilePreview{}, fmt.Errorf("preview %q: %w", filePath, err)
	}
	if kind == "pdf" {
		// Render PDFs in the frontend instead of relying on WebView2's embedded viewer.
		preview.Content = base64.StdEncoding.EncodeToString(content)
		preview.Bytes = len(content)
		return preview, nil
	}
	preview.Content = base64.StdEncoding.EncodeToString(content)
	preview.Bytes = len(content)
	return preview, nil
}

func validatePreviewBytes(kind string, content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("file is empty or unreadable")
	}
	switch kind {
	case "pdf":
		if len(content) < 5 || string(content[:5]) != "%PDF-" {
			return fmt.Errorf("file is not a valid PDF")
		}
	case "image":
		if _, _, err := image.DecodeConfig(bytes.NewReader(content)); err != nil {
			// DecodeConfig does not support every browser image format; validate
			// those headers explicitly while still rejecting truncated payloads.
			if !validExtendedImageHeader(content) {
				return fmt.Errorf("file is not a valid image: %w", err)
			}
		}
	}
	return nil
}

func validExtendedImageHeader(content []byte) bool {
	return (len(content) >= 12 && string(content[:4]) == "RIFF" && string(content[8:12]) == "WEBP") ||
		(len(content) >= 12 && string(content[4:8]) == "ftyp" && (string(content[8:12]) == "avif" || string(content[8:12]) == "avis")) ||
		(len(content) >= 5 && string(content[:5]) == "<?xml")
}

func classifyPreview(filePath string) (kind, mimeType, fileType string) {
	extension := strings.ToLower(path.Ext(strings.TrimSpace(filePath)))
	if textExtensions[extension] {
		return "text", "text/plain; charset=utf-8", "Text file"
	}
	if extension == ".pdf" {
		return "pdf", "application/pdf", "PDF document"
	}
	if imageType, ok := imageExtensions[extension]; ok {
		return "image", imageType, "Image"
	}
	if binaryType, ok := binaryExtensions[extension]; ok {
		return "binary", binaryType, "Binary file"
	}
	if extension != "" {
		if detected := mime.TypeByExtension(extension); detected != "" {
			return "binary", detected, "Binary file"
		}
	}
	return "binary", "application/octet-stream", "Binary file"
}

var textExtensions = map[string]bool{
	".c": true, ".cc": true, ".conf": true, ".cpp": true, ".css": true, ".csv": true,
	".go": true, ".h": true, ".hpp": true, ".html": true, ".ini": true, ".java": true,
	".js": true, ".json": true, ".log": true, ".md": true, ".properties": true,
	".py": true, ".sh": true, ".sql": true, ".toml": true, ".ts": true, ".tsx": true,
	".txt": true, ".xml": true, ".yaml": true, ".yml": true,
}

var imageExtensions = map[string]string{
	".avif": "image/avif", ".gif": "image/gif", ".jpeg": "image/jpeg", ".jpg": "image/jpeg",
	".png": "image/png", ".svg": "image/svg+xml", ".webp": "image/webp",
}

var binaryExtensions = map[string]string{
	".apk": "application/vnd.android.package-archive", ".db": "application/vnd.sqlite3", ".dll": "application/octet-stream",
	".exe": "application/vnd.microsoft.portable-executable", ".rar": "application/vnd.rar", ".zip": "application/zip",
}

func (c *ADBClient) ListPackageDirectory(ctx context.Context, serial, packageName, relativePath string) ([]DirectoryEntry, error) {
	args, err := listPackageDirectoryCommand(serial, packageName, relativePath)
	if err != nil {
		return nil, err
	}
	out, err := c.runADB(ctx, args[1:]...)
	if err != nil {
		return nil, fmt.Errorf("list package directory %q: %w", relativePath, err)
	}
	return parseDirectoryEntries(string(out), relativePath)
}

func (c *ADBClient) downloadBytes(ctx context.Context, serial, packageName, filePath string) ([]byte, error) {
	args, err := downloadCommand(serial, packageName, filePath)
	if err != nil {
		return nil, err
	}
	out, err := c.runADB(ctx, args[1:]...)
	if err != nil {
		return nil, fmt.Errorf("download %q: %w", filePath, err)
	}
	if len(out) > maxTransferBytes {
		return nil, fmt.Errorf("file exceeds the %d MiB transfer limit", maxTransferBytes>>20)
	}
	return out, nil
}

func (c *ADBClient) UploadFile(ctx context.Context, serial, packageName, filePath, contentBase64 string, overwrite bool) error {
	args, err := uploadCommand(serial, packageName, filePath, overwrite)
	if err != nil {
		return err
	}
	content, err := base64.StdEncoding.DecodeString(contentBase64)
	if err != nil {
		return fmt.Errorf("decode upload: %w", err)
	}
	if len(content) > maxTransferBytes {
		return fmt.Errorf("file exceeds the %d MiB transfer limit", maxTransferBytes>>20)
	}
	if c.runInput == nil {
		return fmt.Errorf("upload command runner is not configured")
	}
	if _, err := c.runADBInput(ctx, strings.NewReader(contentBase64), args[1:]...); err != nil {
		return fmt.Errorf("upload %q: %w", filePath, err)
	}
	return nil
}

func (c *ADBClient) Delete(ctx context.Context, serial, packageName, filePath string, isDirectory bool) error {
	args, err := deleteCommand(serial, packageName, filePath, isDirectory)
	if err != nil {
		return err
	}
	if _, err := c.runADB(ctx, args[1:]...); err != nil {
		return fmt.Errorf("delete %q: %w", filePath, err)
	}
	return nil
}

func parseDevices(output string) []Device {
	devices := make([]Device, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] == "List" || fields[0] == "*" {
			continue
		}
		// ADB can expose the mDNS service itself as a synthetic serial in
		// addition to the real host:port serial. The latter is the usable,
		// stable device identity for this application, so do not show both.
		if strings.Contains(strings.ToLower(fields[0]), "_adb-tls-connect._tcp") {
			continue
		}
		device := Device{Serial: fields[0], State: fields[1]}
		for _, field := range fields[2:] {
			if strings.HasPrefix(field, "model:") {
				device.Model = strings.TrimPrefix(field, "model:")
			}
		}
		devices = append(devices, device)
	}
	return devices
}

func listPackagesCommand(serial string) ([]string, error) {
	serial = strings.TrimSpace(serial)
	if serial == "" || !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("a valid device serial is required")
	}
	return []string{"adb", "-s", serial, "shell", "pm", "list", "packages", "-3", "-f"}, nil
}

func runAsCheckCommand(serial, packageName string) ([]string, error) {
	if serial == "" || !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("a valid device serial is required")
	}
	if err := validatePackageName(packageName); err != nil {
		return nil, err
	}
	return []string{"adb", "-s", serial, "shell", "run-as", packageName, "id"}, nil
}

func packageDumpCommand(serial, packageName string) ([]string, error) {
	if _, err := runAsCheckCommand(serial, packageName); err != nil {
		return nil, err
	}
	return []string{"adb", "-s", serial, "shell", "pm", "dump", packageName}, nil
}

func parseThirdPartyPackages(output string) []string {
	seen := make(map[string]bool)
	packages := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "package:"))
		if index := strings.LastIndex(line, "="); index >= 0 {
			line = line[index+1:]
		}
		line = strings.TrimSpace(line)
		if validatePackageName(line) == nil && !seen[line] {
			seen[line] = true
			packages = append(packages, line)
		}
	}
	sort.Strings(packages)
	return packages
}

func parseApplicationLabel(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"application-label:", "label="} {
			if strings.HasPrefix(line, prefix) {
				label := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "'\"")
				if label != "" && !strings.Contains(label, "null") {
					return label
				}
			}
		}
	}
	return ""
}

var serialPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func readCommand(serial, packageName, path string) ([]string, error) {
	return packageCatCommand(serial, packageName, path, false)
}

func downloadCommand(serial, packageName, filePath string) ([]string, error) {
	return packageCatCommand(serial, packageName, filePath, true)
}

func packageCatCommand(serial, packageName, filePath string, rawOutput bool) ([]string, error) {
	serial = strings.TrimSpace(serial)
	packageName = strings.TrimSpace(packageName)
	filePath = strings.TrimSpace(filePath)
	if serial == "" || !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("a valid device serial is required")
	}
	if filePath == "" || strings.ContainsAny(filePath, "\r\n") {
		return nil, fmt.Errorf("a valid device file path is required")
	}
	if packageName == "" {
		return nil, fmt.Errorf("package name is required")
	}
	if err := validatePackageName(packageName); err != nil {
		return nil, err
	}
	relativePath, err := normalizePackagePath(packageName, filePath)
	if err != nil {
		return nil, err
	}
	if relativePath == "." {
		return nil, fmt.Errorf("cannot read a directory")
	}
	if rawOutput {
		return []string{"adb", "-s", serial, "exec-out", "run-as", packageName, "cat", relativePath}, nil
	}
	return []string{"adb", "-s", serial, "shell", "run-as", packageName, "cat", relativePath}, nil
}

func uploadCommand(serial, packageName, filePath string, overwrite bool) ([]string, error) {
	serial = strings.TrimSpace(serial)
	packageName = strings.TrimSpace(packageName)
	filePath = strings.TrimSpace(filePath)
	if serial == "" || !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("a valid device serial is required")
	}
	if err := validatePackageName(packageName); err != nil {
		return nil, err
	}
	relativePath, err := normalizePackagePath(packageName, filePath)
	if err != nil {
		return nil, err
	}
	if relativePath == "." {
		return nil, fmt.Errorf("a file path is required")
	}
	decode := `base64 -d > "$1"`
	if !overwrite {
		// POSIX noclobber makes the redirection itself fail if the target exists.
		decode = "set -C; " + decode
	}
	return []string{"adb", "-s", serial, "shell", "-T", "run-as", packageName, "sh", "-c", shellQuote(decode), "android-inspector-upload", shellQuote(relativePath)}, nil
}

func deleteCommand(serial, packageName, filePath string, isDirectory bool) ([]string, error) {
	serial = strings.TrimSpace(serial)
	packageName = strings.TrimSpace(packageName)
	if serial == "" || !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("a valid device serial is required")
	}
	if err := validatePackageName(packageName); err != nil {
		return nil, err
	}
	relativePath, err := normalizePackagePath(packageName, filePath)
	if err != nil {
		return nil, err
	}
	if relativePath == "." {
		return nil, fmt.Errorf("cannot delete the package root")
	}
	if strings.ContainsAny(relativePath, ";|&$`<>\"'\t") {
		return nil, fmt.Errorf("package path contains unsafe shell characters")
	}
	flags := "-f"
	if isDirectory {
		flags = "-rf"
	}
	return []string{"adb", "-s", serial, "shell", "run-as", packageName, "rm", flags, "--", relativePath}, nil
}

// shellQuote returns one POSIX shell word, preserving every byte except NUL.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func listPackageDirectoryCommand(serial, packageName, relativePath string) ([]string, error) {
	serial = strings.TrimSpace(serial)
	packageName = strings.TrimSpace(packageName)
	relativePath = strings.TrimSpace(relativePath)
	if serial == "" || !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("a valid device serial is required")
	}
	if err := validatePackageName(packageName); err != nil {
		return nil, err
	}
	relativePath, err := normalizePackagePath(packageName, relativePath)
	if err != nil {
		return nil, err
	}
	return []string{"adb", "-s", serial, "shell", "run-as", packageName, "ls", "-la", "-n", "--", relativePath}, nil
}

var packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func validatePackageName(packageName string) error {
	if !packagePattern.MatchString(packageName) {
		return fmt.Errorf("invalid Android package name")
	}
	return nil
}

func normalizePackagePath(packageName, input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" || input == "." {
		return ".", nil
	}
	if strings.ContainsAny(input, "\x00\\\r\n") {
		return "", fmt.Errorf("package paths must use forward slashes and contain no newlines")
	}

	for _, root := range []string{"/data/data/", "/data/user/0/"} {
		absoluteRoot := root + packageName
		if input == absoluteRoot || input == absoluteRoot+"/" {
			return ".", nil
		}
		if strings.HasPrefix(input, absoluteRoot+"/") {
			input = strings.TrimPrefix(input, absoluteRoot+"/")
			break
		}
	}
	return input, validatePackagePath(input)
}

func validatePackagePath(relativePath string) error {
	if relativePath == "" || relativePath == "." {
		return nil
	}
	if strings.HasPrefix(relativePath, "/") || strings.ContainsAny(relativePath, "\x00\\\r\n") {
		return fmt.Errorf("package paths must be relative to the app sandbox")
	}
	for _, segment := range strings.Split(relativePath, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("package path contains an invalid segment")
		}
	}
	return nil
}

func parseDirectoryEntries(output, parent string) ([]DirectoryEntry, error) {
	parent = strings.TrimSpace(parent)
	if parent == "" {
		parent = "."
	}
	entries := make([]DirectoryEntry, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 8 || fields[0] == "total" || (fields[0][0] != 'd' && fields[0][0] != '-' && fields[0][0] != 'l') {
			continue
		}
		nameIndex := 8
		// Android's toybox ls -n omits the year column for recent files,
		// leaving the filename at index 7 instead of index 8.
		if len(fields) == 8 || (strings.Contains(fields[5], "-") && strings.Contains(fields[6], ":")) {
			nameIndex = 7
		}
		if len(fields) <= nameIndex {
			continue
		}
		name := strings.TrimSuffix(strings.Join(fields[nameIndex:], " "), "/")
		if name == "." || name == ".." || name == "" {
			continue
		}
		size, _ := strconv.ParseInt(fields[4], 10, 64)
		entries = append(entries, DirectoryEntry{Name: name, RelativePath: path.Join(parent, name), IsDirectory: fields[0][0] == 'd', Size: size})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDirectory != entries[j].IsDirectory {
			return entries[i].IsDirectory
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

func runCommand(parent context.Context, name string, args ...string) ([]byte, error) {
	return runCommandInput(parent, nil, name, args...)
}

func runCommandInput(parent context.Context, input io.Reader, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	configureCommand(cmd)
	var stdout boundedBuffer
	var stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = input
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("command timed out after %s", commandTimeout)
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("command output exceeds the %d MiB transfer limit", maxTransferBytes>>20)
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("%w: %s", err, message)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

type boundedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	originalLength := len(p)
	remaining := maxTransferBytes + 1 - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return originalLength, nil
	}
	if len(p) > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return originalLength, nil
}

func lineCount(content string) int {
	if content == "" {
		return 0
	}
	return strings.Count(content, "\n") + 1
}
