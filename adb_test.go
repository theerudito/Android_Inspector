package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestADBCandidatesUsePlatformLocationsInPriorityOrder(t *testing.T) {
	home := filepath.Join("home", "user")
	tests := []struct {
		name string
		goos string
		want []string
	}{
		{"windows", "windows", []string{
			filepath.Join("configured", "adb.exe"),
			filepath.Join("sdk", "platform-tools", "adb.exe"),
			filepath.Join("sdk-root", "platform-tools", "adb.exe"),
			filepath.Join(home, "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe"),
			filepath.Join(home, "AppData", "Android", "Sdk", "platform-tools", "adb.exe"),
		}},
		{"macOS", "darwin", []string{
			filepath.Join("sdk", "platform-tools", "adb"),
			filepath.Join("sdk-root", "platform-tools", "adb"),
			filepath.Join(home, "Library", "Android", "sdk", "platform-tools", "adb"),
		}},
		{"linux", "linux", []string{
			filepath.Join("sdk", "platform-tools", "adb"),
			filepath.Join("sdk-root", "platform-tools", "adb"),
			filepath.Join(home, "Android", "Sdk", "platform-tools", "adb"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configured := ""
			if tt.goos == "windows" {
				configured = filepath.Join("configured", "adb.exe")
			}
			got := adbCandidates(tt.goos, configured, "sdk", "sdk-root", home)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("adbCandidates() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSelectExistingADBPathChoosesFirstExistingCandidate(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first", "adb")
	second := filepath.Join(dir, "second", "adb")
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("adb"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, ok := selectExistingADBPath([]string{first, second})
	if !ok || got != second {
		t.Fatalf("selectExistingADBPath() = %q, %v; want %q, true", got, ok, second)
	}
}

func TestParseDevices(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []Device
	}{
		{"devices with models", "List of devices attached\nABC123\tdevice product:foo model:Pixel_8 device:husky\n192.168.1.4:5555\tunauthorized\n", []Device{{Serial: "ABC123", State: "device", Model: "Pixel_8"}, {Serial: "192.168.1.4:5555", State: "unauthorized"}}},
		{"empty list", "List of devices attached\n\n", []Device{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDevices(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseDevices() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestReadCommand(t *testing.T) {
	tests := []struct {
		name    string
		serial  string
		pkg     string
		path    string
		want    []string
		wantErr bool
	}{
		{"missing package", "emulator-5554", "", "/sdcard/Download/log.txt", nil, true},
		{"private package path", "ABC123", "com.example.demo", "files/state.json", []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "cat", "files/state.json"}, false},
		{"data sandbox descendant", "ABC123", "com.example.demo", "/data/data/com.example.demo/files/state.json", []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "cat", "files/state.json"}, false},
		{"reject package root", "ABC123", "com.example.demo", "/data/user/0/com.example.demo/", nil, true},
		{"reject newline", "ABC123", "", "/sdcard/a\nb", nil, true},
		{"reject malformed serial", "ABC 123", "", "/sdcard/a", nil, true},
		{"reject outside package root", "ABC123", "com.example.demo", "/data/data/other/files/state.json", nil, true},
		{"reject package traversal", "ABC123", "com.example.demo", "/data/data/com.example.demo/files/../state.json", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readCommand(tt.serial, tt.pkg, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("readCommand() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestClassifyPreview(t *testing.T) {
	tests := []struct {
		name, filePath, kind, mimeType string
	}{
		{"text", "files/settings.json", "text", "text/plain; charset=utf-8"},
		{"image", "files/photo.PNG", "image", "image/png"},
		{"pdf", "files/report.pdf", "pdf", "application/pdf"},
		{"database", "files/cache.db", "binary", "application/vnd.sqlite3"},
		{"archive", "files/archive.zip", "binary", "application/zip"},
		{"unknown", "files/blob", "binary", "application/octet-stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, mimeType, _ := classifyPreview(tt.filePath)
			if kind != tt.kind || mimeType != tt.mimeType {
				t.Fatalf("classifyPreview() = %q, %q; want %q, %q", kind, mimeType, tt.kind, tt.mimeType)
			}
		})
	}
}

func TestPreviewFileDoesNotReadUnsupportedBinary(t *testing.T) {
	called := false
	client := &ADBClient{run: func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}}
	preview, err := client.PreviewFile(context.Background(), "ABC123", "com.example.demo", "files/cache.db", 42)
	if err != nil || called {
		t.Fatalf("PreviewFile() = %#v, %v; command called=%v", preview, err, called)
	}
	if preview.Kind != "binary" || preview.Bytes != 42 || preview.Content != "" {
		t.Fatalf("unsupported preview = %#v", preview)
	}
}

func TestDownloadCommandUsesBinarySafeExecOut(t *testing.T) {
	got, err := downloadCommand("ABC123", "com.example.demo", "/data/data/com.example.demo/files/blob.bin")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"adb", "-s", "ABC123", "exec-out", "run-as", "com.example.demo", "cat", "files/blob.bin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("downloadCommand() = %#v, want %#v", got, want)
	}
}

func TestListPackageDirectoryCommand(t *testing.T) {
	tests := []struct {
		name              string
		serial, pkg, path string
		want              []string
		wantErr           bool
	}{
		{"sandbox root", "ABC123", "com.example.demo", ".", []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "ls", "-la", "-n", "--", "."}, false},
		{"absolute sandbox root", "ABC123", "com.example.demo", "/data/data/com.example.demo/", []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "ls", "-la", "-n", "--", "."}, false},
		{"absolute nested directory", "ABC123", "com.example.demo", "/data/user/0/com.example.demo/files/cache", []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "ls", "-la", "-n", "--", "files/cache"}, false},
		{"nested directory", "ABC123", "com.example.demo", "files/cache", []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "ls", "-la", "-n", "--", "files/cache"}, false},
		{"reject traversal", "ABC123", "com.example.demo", "files/../data", nil, true},
		{"reject absolute traversal", "ABC123", "com.example.demo", "/data/data/com.example.demo/../other", nil, true},
		{"reject invalid package", "ABC123", "com.example-demo", ".", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listPackageDirectoryCommand(tt.serial, tt.pkg, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("listPackageDirectoryCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("listPackageDirectoryCommand() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestUploadCommandUsesValidatedArguments(t *testing.T) {
	tests := []struct {
		name      string
		overwrite bool
		want      []string
		wantErr   bool
	}{
		{"no overwrite", false, []string{"adb", "-s", "ABC123", "shell", "-T", "run-as", "com.example.demo", "sh", "-c", `'set -C; base64 -d > "$1"'`, "android-inspector-upload", "'files/state.bin'"}, false},
		{"overwrite", true, []string{"adb", "-s", "ABC123", "shell", "-T", "run-as", "com.example.demo", "sh", "-c", `'base64 -d > "$1"'`, "android-inspector-upload", "'files/state.bin'"}, false},
		{"traversal rejected", true, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "files/state.bin"
			if tt.wantErr {
				path = "files/../state.bin"
			}
			got, err := uploadCommand("ABC123", "com.example.demo", path, tt.overwrite)
			if (err != nil) != tt.wantErr || !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("uploadCommand() = %#v, %v", got, err)
			}
		})
	}
}

func TestDeleteCommandUsesSafeModesAndRejectsUnsafePaths(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		isDirectory bool
		want        []string
		wantErr     bool
	}{
		{"file", "files/state.json", false, []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "rm", "-f", "--", "files/state.json"}, false},
		{"directory", "files/cache", true, []string{"adb", "-s", "ABC123", "shell", "run-as", "com.example.demo", "rm", "-rf", "--", "files/cache"}, false},
		{"root", ".", false, nil, true},
		{"traversal", "files/../state.json", false, nil, true},
		{"absolute outside sandbox", "/data/data/other/state.json", false, nil, true},
		{"shell metacharacter", "files/state;id", false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deleteCommand("ABC123", "com.example.demo", tt.path, tt.isDirectory)
			if (err != nil) != tt.wantErr {
				t.Fatalf("deleteCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("deleteCommand() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestShellQuoteProtectsPOSIXShellSyntax(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"plain path", "files/state.bin", "'files/state.bin'"},
		{"shell metacharacters", "files/a;$(id)&.bin", "'files/a;$(id)&.bin'"},
		{"apostrophe", "files/user's.bin", "'files/user'\\''s.bin'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shellQuote(tt.input); got != tt.want {
				t.Fatalf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUploadFilePreservesBinaryBytes(t *testing.T) {
	want := []byte{0x00, 0x0A, 0x0D, 0x1A, 0xFF}
	client := &ADBClient{runInput: func(_ context.Context, input io.Reader, name string, args ...string) ([]byte, error) {
		if name != "adb" || !reflect.DeepEqual(args, []string{"-s", "ABC123", "shell", "-T", "run-as", "com.example.demo", "sh", "-c", `'base64 -d > "$1"'`, "android-inspector-upload", "'files/blob.bin'"}) {
			t.Fatalf("unexpected command: %s %#v", name, args)
		}
		got, err := io.ReadAll(input)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != base64.StdEncoding.EncodeToString(want) {
			t.Fatalf("uploaded transport = %q, want base64 for %v", got, want)
		}
		return nil, nil
	}}
	if err := client.UploadFile(context.Background(), "ABC123", "com.example.demo", "files/blob.bin", base64.StdEncoding.EncodeToString(want), true); err != nil {
		t.Fatal(err)
	}
}

func TestUploadRejectsUnsafePathBytes(t *testing.T) {
	for _, filePath := range []string{"files/a\\b.bin", "files/a\nb.bin", "files/a\x00b.bin", "files/../b.bin"} {
		if _, err := uploadCommand("ABC123", "com.example.demo", filePath, true); err == nil {
			t.Fatalf("uploadCommand accepted unsafe path %q", filePath)
		}
	}
}

func TestDownloadBytesPreservesBinaryBytes(t *testing.T) {
	want := []byte{0, 1, 128, 254, 255}
	client := &ADBClient{run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if !reflect.DeepEqual(append([]string{name}, args...), []string{"adb", "-s", "ABC123", "exec-out", "run-as", "com.example.demo", "cat", "files/blob.bin"}) {
			t.Fatalf("unexpected command: %s %#v", name, args)
		}
		return want, nil
	}}
	got, err := client.downloadBytes(context.Background(), "ABC123", "com.example.demo", "files/blob.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("download bytes = %v; want %v", got, want)
	}
}

func TestPackageDiscoveryParsing(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"apk paths and duplicates", "package:/data/app/base.apk=com.example.z\npackage:/data/app/other.apk=com.example.a\npackage:/data/app/other.apk=com.example.a\n", []string{"com.example.a", "com.example.z"}},
		{"ignore malformed names", "package:/data/app/base.apk=not-a-package\npackage:/data/app/base.apk=com.example.ok\n", []string{"com.example.ok"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseThirdPartyPackages(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseThirdPartyPackages() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseApplicationLabel(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"quoted label", "application-label:'Demo App'\n", "Demo App"},
		{"alternate label", "label=Inspector\n", "Inspector"},
		{"missing label", "application-label:null\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseApplicationLabel(tt.input); got != tt.want {
				t.Fatalf("parseApplicationLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPackageDiscoveryCommands(t *testing.T) {
	if got, err := listPackagesCommand("AC4VVB4920006139"); err != nil || !reflect.DeepEqual(got, []string{"adb", "-s", "AC4VVB4920006139", "shell", "pm", "list", "packages", "-3", "-f"}) {
		t.Fatalf("listPackagesCommand() = %#v, %v", got, err)
	}
	if got, err := runAsCheckCommand("AC4VVB4920006139", "com.example.demo"); err != nil || !reflect.DeepEqual(got, []string{"adb", "-s", "AC4VVB4920006139", "shell", "run-as", "com.example.demo", "id"}) {
		t.Fatalf("runAsCheckCommand() = %#v, %v", got, err)
	}
	if _, err := listPackagesCommand("bad serial"); err == nil {
		t.Fatal("listPackagesCommand() accepted an unsafe serial")
	}
}

func TestParseDirectoryEntries(t *testing.T) {
	input := "total 12\ndrwxr-xr-x 3 1000 1000 4096 Jan 01 12:00 files\n-rw-r--r-- 1 1000 1000 42 Jan 01 12:00 config.json\ndrwxr-xr-x 2 1000 1000 4096 Jan 01 12:00 empty/\n"
	want := []DirectoryEntry{
		{Name: "empty", RelativePath: "files/empty", IsDirectory: true, Size: 4096},
		{Name: "files", RelativePath: "files/files", IsDirectory: true, Size: 4096},
		{Name: "config.json", RelativePath: "files/config.json", Size: 42},
	}
	got, err := parseDirectoryEntries(input, "files")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDirectoryEntries() = %#v, %v; want %#v", got, err, want)
	}
}

func TestParseDirectoryEntriesAndroidToyboxFormat(t *testing.T) {
	input := "total 55\ndrwxrwx--x   3 10623 10623 3452 2026-09-18 12:44 app_flutter\ndrwxrws--x   2 10623 20623 3452 2026-09-18 09:00 cache\n"
	want := []DirectoryEntry{
		{Name: "app_flutter", RelativePath: "app_flutter", IsDirectory: true, Size: 3452},
		{Name: "cache", RelativePath: "cache", IsDirectory: true, Size: 3452},
	}
	got, err := parseDirectoryEntries(input, ".")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDirectoryEntries() = %#v, %v; want %#v", got, err, want)
	}
}

func TestListPackageDirectoryUsesRunner(t *testing.T) {
	client := &ADBClient{run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "adb" || args[len(args)-1] != "files" {
			t.Fatalf("unexpected command: %s %#v", name, args)
		}
		return []byte("-rw-r--r-- 1 1000 1000 8 Jan 01 12:00 note.txt\n"), nil
	}}
	got, err := client.ListPackageDirectory(context.Background(), "ABC123", "com.example.demo", "files")
	if err != nil || len(got) != 1 || got[0].RelativePath != "files/note.txt" {
		t.Fatalf("ListPackageDirectory() = %#v, %v", got, err)
	}
}

func TestReadFileUsesRunner(t *testing.T) {
	client := &ADBClient{run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "adb" || len(args) == 0 || args[len(args)-1] != "files/a.txt" {
			t.Fatalf("unexpected command: %s %#v", name, args)
		}
		return []byte("one\ntwo\n"), nil
	}}
	got, err := client.ReadFile(context.Background(), "ABC123", "com.example.demo", "/data/data/com.example.demo/files/a.txt")
	if err != nil || got.Bytes != 8 || got.LineCount != 3 || got.Content != "one\ntwo\n" {
		t.Fatalf("ReadFile() = %#v, %v", got, err)
	}
}

func TestRunCommandUsesConfiguredProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a local process")
	}
	_, err := runCommand(context.Background(), "cmd", "/c", "exit", "0")
	if err != nil {
		t.Fatalf("runCommand() = %v", err)
	}
}
