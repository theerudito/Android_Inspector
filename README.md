# Android Inspector

Android Inspector is a [Wails](https://wails.io/) desktop application for inspecting and interacting with Android devices through ADB.

## Supported platforms

- Windows
- Linux
- macOS

## Prerequisites

Install these tools before building:

- Go 1.25 or newer
- Node.js and npm
- Wails CLI v2.16.0
- Android SDK Platform-Tools (for ADB at runtime)

Install the Wails CLI at the version used by this repository. This step is required before compiling on Linux, Windows, or macOS:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
```

Ensure `$(go env GOPATH)/bin` is on `PATH` (use `%USERPROFILE%\go\bin` on Windows).

Platform-specific prerequisites:

| Platform | Additional prerequisites |
| --- | --- |
| Windows | Microsoft WebView2 Runtime, a MinGW-w64 C toolchain, Android Platform-Tools, and the USB driver for the device |
| Linux | GTK 3, WebKitGTK, `pkg-config`, a C compiler, and `adb`; see [Linux dependencies](#linux-dependencies) |
| macOS | Xcode Command Line Tools (`xcode-select --install`) and Android Platform-Tools |

Verify the command-line tools:

```bash
go version
node --version
wails version
adb version
```

## Linux dependencies

Wails v2 uses GTK 3 and WebKitGTK. The Debian builder in this repository uses the WebKitGTK 4.1 Wails tag. On Ubuntu/Debian systems, install these dependencies:

```bash
sudo apt update
sudo apt install adb build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev
```

If your distribution only provides WebKitGTK 4.0, install `libwebkit2gtk-4.0-dev` instead and use a direct Wails build without the `webkit2_41` tag. The packaged script is currently configured for WebKitGTK 4.1.

The `webkit2_41` tag is required because Wails selects the `webkit2gtk-4.1` and `libsoup-3.0` pkg-config dependencies only when that tag is enabled. Without the tag, Wails expects WebKitGTK 4.0.

Check which development package is available:

```bash
pkg-config --modversion webkit2gtk-4.0
pkg-config --modversion webkit2gtk-4.1
```

## Install frontend dependencies

Run this from the repository root. `npm ci` uses `frontend/package-lock.json` and is reproducible; do not replace it with `npm install` for a clean build.

```bash
npm --prefix frontend ci
```

## Development

Start the Wails development application from the repository root:

```bash
wails dev
```

## Native builds

Build on the operating system for which the application is intended. Wails uses the native platform WebView and this repository does not define a supported cross-compilation workflow.

### Windows

Install Microsoft WebView2 Runtime and [Inno Setup](https://jrsoftware.org/isinfo.php). From PowerShell at the repository root:

```powershell
npm --prefix frontend ci
wails build
```

Output: `build\bin\android_inspector.exe`.

Build the Windows installer with Inno Setup:

```powershell
ISCC.exe installer.iss
```

Output: `build\installer\AndroidInspector-Setup-1.0.0.exe`.

### Linux

From the repository root on Ubuntu/Debian:

```bash
npm --prefix frontend ci
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
chmod +x build/linux/build-deb.sh
./build/linux/build-deb.sh
```

The script builds with the `webkit2_41` tag and creates `build/bin/android_inspector`.

Review the generated package and install it:

```bash
ls -lah build/installer/
sudo apt -f install
sudo dpkg -i "build/installer/android-inspector_1.0.0_amd64.deb"
```

The package is written to `build/installer/`. If `dpkg` still reports missing dependencies, run `sudo apt -f install` again and repeat the installation command.

### macOS

Install Xcode Command Line Tools and Android Platform-Tools, then build from Terminal at the repository root:

```bash
xcode-select --install
brew install android-platform-tools
npm --prefix frontend ci
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
wails build
```

Output: `build/bin/android_inspector.app`.

To distribute the macOS application, archive or sign the generated `.app` bundle according to the target macOS version and architecture. This repository does not include a macOS installer package.

## ADB runtime requirement

ADB is not needed to compile the desktop application. It is required when running Android Inspector and communicating with a device. Install Android SDK Platform-Tools, enable USB debugging, connect the device, and verify the connection:

```bash
adb devices
```

The application resolves ADB in this order:

1. `ADB_PATH`, when it points to an executable.
2. `ANDROID_HOME/platform-tools/adb`.
3. `ANDROID_SDK_ROOT/platform-tools/adb`.
4. The standard SDK location for the operating system.
5. `adb` or `adb.exe` on `PATH`.

A device must have status `device`; `unauthorized` and `offline` devices are not ready for inspection. Only debuggable packages that support `run-as` can be inspected.

## Output locations

Wails embeds the frontend into the native application. The distributable application is under `build/bin/`; `frontend/dist/` is only an intermediate frontend build output and is not a replacement for the native application.

## Troubleshooting

- If ADB is not found, install Platform-Tools and configure `ADB_PATH`, `ANDROID_HOME`, `ANDROID_SDK_ROOT`, or `PATH`, then restart the application.
- If a device is unauthorized, accept the USB debugging authorization prompt on the device.
- If no packages are listed, confirm that the package is a debuggable build and that `adb -s DEVICE_SERIAL shell run-as PACKAGE_NAME id` succeeds.
- If a Linux build cannot find WebKitGTK, install the matching development package and use `-tags webkit2_41` for WebKitGTK 4.1.

## License

This project is licensed under the MIT License.
