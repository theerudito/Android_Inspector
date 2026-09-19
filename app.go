package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx         context.Context
	client      *ADBClient
	startupOnce sync.Once
	pairingMu   sync.Mutex
	pairing     *wifiPairingSession
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{client: NewADBClient()}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.startupOnce.Do(func() {
		if err := a.client.StartServer(ctx); err != nil {
			log.Printf("ADB startup bootstrap failed: %v", err)
		}
	})
}

// DetectADB verifies that adb is available and returns its version string.
func (a *App) DetectADB() (string, error) {
	version, err := a.client.Detect(a.ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(version), nil
}

// ListDevices returns devices currently visible to adb.
func (a *App) ListDevices() ([]Device, error) {
	return a.client.ListDevices(a.ctx)
}

// ListDebugPackages returns third-party packages accessible through run-as.
func (a *App) ListDebugPackages(serial string) ([]DebugPackage, error) {
	return a.client.ListDebugPackages(a.ctx, serial)
}

// ReadFile reads a device file using either run-as or the public device shell.
func (a *App) ReadFile(serial, packageName, path string) (FileContent, error) {
	return a.client.ReadFile(a.ctx, serial, packageName, path)
}

// PreviewFile returns text or bounded binary preview data for supported media.
func (a *App) PreviewFile(serial, packageName, path string, size int64) (FilePreview, error) {
	return a.client.PreviewFile(a.ctx, serial, packageName, path, size)
}

// ListPackageDirectory returns entries inside a package sandbox directory.
func (a *App) ListPackageDirectory(serial, packageName, relativePath string) ([]DirectoryEntry, error) {
	return a.client.ListPackageDirectory(a.ctx, serial, packageName, relativePath)
}

// SaveFile downloads a package file through a native save dialog.
func (a *App) SaveFile(serial, packageName, filePath string) (string, error) {
	fileName := path.Base(strings.TrimSuffix(strings.TrimSpace(filePath), "/"))
	if fileName == "." || fileName == "" || fileName == "/" {
		return "", fmt.Errorf("a file path is required")
	}

	localPath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save downloaded file",
		DefaultFilename: fileName,
	})
	if err != nil {
		return "", fmt.Errorf("choose download destination: %w", err)
	}
	if strings.TrimSpace(localPath) == "" {
		return "", nil
	}

	content, err := a.client.downloadBytes(a.ctx, serial, packageName, filePath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(localPath, content, 0600); err != nil {
		return "", fmt.Errorf("write downloaded file: %w", err)
	}
	return localPath, nil
}

// UploadFile writes a bounded base64 payload into the selected package sandbox.
func (a *App) UploadFile(serial, packageName, path, contentBase64 string, overwrite bool) error {
	return a.client.UploadFile(a.ctx, serial, packageName, path, contentBase64, overwrite)
}

// Delete removes a selected file or directory from the package sandbox.
func (a *App) Delete(serial, packageName, path string, isDirectory bool) error {
	return a.client.Delete(a.ctx, serial, packageName, path, isDirectory)
}

// PackageContext returns the command context used for a package-scoped read.
func (a *App) PackageContext(packageName string) (string, error) {
	packageName = strings.TrimSpace(packageName)
	if packageName == "" {
		return "", fmt.Errorf("package name is required")
	}
	return fmt.Sprintf("run-as %s cat <path>", packageName), nil
}
