# Android Inspector

Android Inspector is a desktop application for inspecting the private sandbox of debuggable Android applications through ADB. It uses Go and Wails with a React frontend and keeps the native window fixed at 1280x760.

## Features

- Discovers connected Android devices through ADB.
- Finds third-party packages that accept `run-as`, which identifies debuggable apps available for inspection.
- Browses files and directories inside an application's sandbox.
- Previews text files, supported images, and PDF documents.
- Downloads and uploads files without treating binary data as text. Transfers are limited to 64 MiB per file.
- Confirms file and directory deletion before issuing the operation.
- Hides ADB console windows on Windows.
- Shows the complete native local path after a successful download.
- Uses a fixed, non-resizable 1280x760 window.

## Prerequisites

Install the tools for your operating system before building:

| Platform | Required software |
| --- | --- |
| Windows | Go, Node.js/npm, Wails CLI, Android SDK Platform-Tools (`adb`), and Microsoft WebView2 Runtime. Inno Setup is also required to build the installer. |
| Ubuntu/Linux | Go, Node.js/npm, Wails CLI, Android SDK Platform-Tools (`adb`), and the WebKit2GTK development packages required by Wails. On Ubuntu, install `libgtk-3-dev`, `libwebkit2gtk-4.0-dev` (or the package version required by your Ubuntu release), `pkg-config`, and `build-essential`. |
| macOS | Go, Node.js/npm, Wails CLI, Android SDK Platform-Tools (`adb`), and Xcode Command Line Tools (`xcode-select --install`). |

Install the Wails CLI with the version used by this project:

```sh
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
```

Make sure the Go and Wails binary directories are on `PATH` (`%USERPROFILE%\go\bin` on Windows and `$(go env GOPATH)/bin` on Unix-like systems).

## ADB Resolution

Android Inspector resolves ADB in this order:

1. `ADB_PATH`, when it points to an existing executable.
2. `ANDROID_HOME/platform-tools/adb`.
3. `ANDROID_SDK_ROOT/platform-tools/adb`.
4. The standard SDK location for the operating system:
   - Windows: `%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe`, then `%USERPROFILE%\AppData\Android\Sdk\platform-tools\adb.exe`.
   - Ubuntu/Linux: `$HOME/Android/Sdk/platform-tools/adb`.
   - macOS: `$HOME/Library/Android/sdk/platform-tools/adb`.
5. `adb` or `adb.exe` on `PATH`.

Verify the installation and device connection from a terminal:

```sh
adb version
adb devices -l
```

Enable USB debugging on the device and accept its authorization prompt. A device should appear with state `device`, not `unauthorized` or `offline`.

## Setup

Clone or enter the repository, then install frontend dependencies:

```sh
cd android_inspector
cd frontend
npm install
cd ..
```

For a development run with hot reload:

```sh
wails dev
```

## Builds

Wails builds the native application for the host OS. Native desktop targets should be built on their respective operating systems because the WebView and platform toolchain are not reliably cross-compiled from another OS.

### Windows

Run PowerShell or Command Prompt from the repository root:

```powershell
npm --prefix frontend run build
go test -count=1 ./...
wails build -platform windows/amd64
```

The Windows executable is written to `build\bin\android_inspector.exe`. To build the installer, install Inno Setup and run its compiler against the root script:

```powershell
ISCC.exe installer.iss
```

The script checks for `build\bin\android_inspector.exe` and `build\windows\icon.ico` before compiling. The installer is written to `build\installer\AndroidInspector-Setup-1.0.0.exe`.

### Ubuntu/Linux

Run from the repository root on Linux:

```sh
npm --prefix frontend run build
go test -count=1 ./...
wails build -platform linux/amd64
```

The Linux release output is under `build/bin/`, including `build/bin/android_inspector` (the exact packaging files can vary by Wails version and Linux target).

### macOS

Run from the repository root on macOS:

```sh
npm --prefix frontend run build
go test -count=1 ./...
wails build -platform darwin/universal
```

The macOS application is written under `build/bin/`, normally as `build/bin/android_inspector.app`.

For the normal native build on any supported host, `wails build` is sufficient. The frontend build output is embedded into the native binary; do not distribute `frontend/dist` as a substitute for the native application.

## Usage

1. Start Android Inspector and click the device discovery action.
2. Select a connected device in the device list.
3. Select a debuggable package discovered through `run-as`.
4. Browse the package sandbox, select a file, and preview supported content.
5. Use download, upload, or delete. Downloads use the native save dialog and report the complete selected local path.

## Limitations and Security

- Only packages for which ADB `run-as` succeeds can be inspected. Release builds normally disable this access.
- The application does not root the device and cannot bypass Android sandbox permissions.
- ADB commands are sent to the selected device and package. Review the package, path, upload contents, and delete confirmation before performing destructive operations.
- Uploads and downloads are limited to 64 MiB per file. Large files must be handled with another tool.
- Preview support is limited to recognized text extensions, valid browser-compatible images, and PDFs. Unsupported or invalid binary files can still be transferred.
- Device access depends on USB debugging, device authorization, the ADB server, and platform-tools compatibility.

## Troubleshooting

### No ADB executable found

Run `adb version`. If the command is unavailable, install Android SDK Platform-Tools and either set `ADB_PATH`, set `ANDROID_HOME` or `ANDROID_SDK_ROOT`, or add the SDK `platform-tools` directory to `PATH`. Restart Android Inspector after changing environment variables.

### The device is missing or unauthorized

Run `adb kill-server`, then `adb start-server` and `adb devices -l`. Reconnect the device, enable USB debugging, and accept the authorization dialog. Use a working USB cable and the appropriate platform driver on Windows.

### No debuggable packages are listed

The package must be installed as a debuggable build and must allow `run-as`. Test the selected device directly:

```sh
adb -s DEVICE_SERIAL shell run-as PACKAGE_NAME id
```

If this command fails, Android Inspector cannot browse that package. Confirm the package name, device state, and that the application is not a release build with `debuggable=false`.

### Wails build fails

Confirm that Go, Node/npm, Wails, and the platform WebView prerequisites are installed. On Linux, install the WebKit2GTK and GTK development packages; on macOS, install Xcode Command Line Tools; on Windows, install or repair WebView2 Runtime. Build the native target on its matching operating system.
