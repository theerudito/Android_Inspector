import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, ClipboardEvent, KeyboardEvent } from "react";
import * as pdfjsLib from "pdfjs-dist";
import pdfWorker from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import {
  Delete,
  DetectADB,
  ListDebugPackages,
  ListDevices,
  ListPackageDirectory,
  ListWifiPairingDevices,
  PairAndConnect,
  PreviewFile,
  SaveFile,
  StartWifiPairing,
  StopWifiPairing,
  UploadFile,
  WifiPairingStatus,
} from "../wailsjs/go/main/App";
import type { main } from "../wailsjs/go/models";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;
type Device = main.Device;
type DirectoryEntry = main.DirectoryEntry;
type DebugPackage = main.DebugPackage;
type FilePreview = main.FilePreview;
type WifiPairingOffer = main.WifiPairingOffer;
type WifiPairingDevice = main.WifiPairingDevice;
type WifiStatus = main.WifiPairingStatus;

function Progress({ label }: { label: string }) {
  return (
    <div className="progress-wrap">
      <div className="progress-track">
        <div className="progress-fill" />
      </div>
      <span>{label}</span>
    </div>
  );
}
function FileIcon({ directory }: { directory: boolean }) {
  return (
    <span className={directory ? "file-icon folder-icon" : "file-icon"}>
      {directory ? "▰" : "□"}
    </span>
  );
}
function QrIcon() {
  return (
    <svg className="wifi-qr-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 4h6v6H4V4zm10 0h6v6h-6V4zM4 14h6v6H4v-6zm10 4h2v2h-2v-2zm4-4h2v2h-2v-2zm-4 0h2v2h-2v-2zm4 4h2v2h-2v-2z" />
    </svg>
  );
}
function ToolbarIcon({ type }: { type: "upload" | "download" | "delete" }) {
  if (type === "delete")
    return (
      <svg className="toolbar-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 7h16M9 7V4h6v3m-9 0 1 13h8l1-13M10 11v5m4-5v5" />
      </svg>
    );
  const arrow =
    type === "upload" ? "M12 16V4m0 0L7 9m5-5 5 5" : "M12 8v12m0 0-5-5m5 5 5-5";
  return (
    <svg className="toolbar-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d={`${arrow}M5 20h14`} />
    </svg>
  );
}
function formatBytes(value: number, directory = false) {
  if (directory) return "Folder";
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function PdfPreview({
  content,
  onError,
}: {
  content: string;
  onError: (message: string) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    let loadingTask: ReturnType<typeof pdfjsLib.getDocument> | undefined;
    let pdf: pdfjsLib.PDFDocumentProxy | undefined;
    async function render() {
      try {
        const binary = atob(content);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        loadingTask = pdfjsLib.getDocument({ data: bytes });
        pdf = await loadingTask.promise;
        const page = await pdf.getPage(1);
        if (cancelled || !canvasRef.current) return;
        const scale = Math.min(1.8, 560 / page.getViewport({ scale: 1 }).width);
        const viewport = page.getViewport({ scale });
        const canvas = canvasRef.current;
        canvas.width = viewport.width;
        canvas.height = viewport.height;
        await page.render({ canvasContext: canvas.getContext("2d")!, viewport })
          .promise;
        if (!cancelled) setLoading(false);
      } catch (error) {
        if (!cancelled)
          onError(
            error instanceof Error ? error.message : "PDF rendering failed",
          );
      }
    }
    render();
    return () => {
      cancelled = true;
      void loadingTask?.destroy();
      void pdf?.destroy();
    };
  }, [content, onError]);
  return (
    <div className="pdf-preview">
      <span className={loading ? "" : "visually-hidden"}>
        {loading ? "Rendering PDF..." : ""}
      </span>
      <canvas ref={canvasRef} />
    </div>
  );
}

function App() {
  const [adbVersion, setAdbVersion] = useState("Checking ADB");
  const [devices, setDevices] = useState<Device[]>([]);
  const [serial, setSerial] = useState("");
  const [packages, setPackages] = useState<DebugPackage[]>([]);
  const [packageName, setPackageName] = useState("");
  const [directory, setDirectory] = useState(".");
  const [entries, setEntries] = useState<DirectoryEntry[]>([]);
  const [selected, setSelected] = useState<DirectoryEntry | null>(null);
  const [preview, setPreview] = useState<FilePreview | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [packagesError, setPackagesError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<DirectoryEntry | null>(null);
  const [wifiOpen, setWifiOpen] = useState(false);
  const [wifiTab, setWifiTab] = useState<"qr" | "code">("qr");
  const [wifiOffer, setWifiOffer] = useState<WifiPairingOffer | null>(null);
  const [wifiStatus, setWifiStatus] = useState<WifiStatus | null>(null);
  const [pairDevices, setPairDevices] = useState<WifiPairingDevice[]>([]);
  const [pairSearch, setPairSearch] = useState("");
  const [pairError, setPairError] = useState("");
  const [pairNotice, setPairNotice] = useState("");
  const [codeTarget, setCodeTarget] = useState<WifiPairingDevice | null>(null);
  const [codeDigits, setCodeDigits] = useState<string[]>(["", "", "", "", "", ""]);
  const [codeError, setCodeError] = useState("");
  const [codeBusy, setCodeBusy] = useState(false);
  // Pairing-code flow is now pair+connect in one backend call, so the busy
  // label walks through both phases: "pairing" while `adb pair` runs, then
  // "connecting" while the backend polls for the _adb-tls-connect._tcp
  // address. The flip is time-based (the backend exposes no progress
  // events); pairing usually finishes within a few seconds while connect
  // polling can take up to ~30s.
  const [codePhase, setCodePhase] = useState<"pairing" | "connecting">(
    "pairing",
  );
  const codeInputs = useRef<Array<HTMLInputElement | null>>([]);
  const [mediaURL, setMediaURL] = useState("");
  const [pdfError, setPdfError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const loadRequest = useRef(0);
  const wifiConnected = useRef(false);
  const selectedDevice = useMemo(
    () => devices.find((item) => item.serial === serial),
    [devices, serial],
  );
  const root = `/data/data/${packageName}`;
  const currentPath = directory === "." ? root : `${root}/${directory}`;
  useEffect(
    () => () => {
      if (mediaURL) URL.revokeObjectURL(mediaURL);
    },
    [mediaURL],
  );
  useEffect(() => {
    DetectADB()
      .then(setAdbVersion)
      .catch(() => setAdbVersion("ADB unavailable"));
    refreshDevices();
  }, []);
  useEffect(() => {
    setPdfError("");
  }, [preview]);
  useEffect(() => {
    if (!preview || preview.kind !== "image" || !preview.content) return;
    const binary = atob(preview.content);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: preview.mime }));
    setMediaURL((old) => {
      if (old) URL.revokeObjectURL(old);
      return url;
    });
    return () => URL.revokeObjectURL(url);
  }, [preview]);
  async function openWifiPairing() {
    wifiConnected.current = false;
    setWifiOpen(true);
    setWifiTab("qr");
    setWifiOffer(null);
    setWifiStatus({ state: "waiting", message: "Preparing Wi-Fi pairing…" });
    setPairDevices([]);
    setPairSearch("");
    setPairError("");
    setPairNotice("");
    setCodeTarget(null);
    setCodeError("");
    setCodePhase("pairing");
    try {
      setWifiOffer(await StartWifiPairing());
    } catch (e) {
      setWifiStatus({ state: "failed", message: String(e) });
    }
  }
  function closeWifiPairing() {
    setWifiOpen(false);
    setWifiOffer(null);
    setWifiStatus(null);
    void StopWifiPairing();
  }
  // Shared success path for QR and pairing-code connections: refresh
  // the device list, surface a workspace-level notice, then close the modal
  // (and any nested code dialog). Closing via wifiOpen=false also stops the
  // 800ms/2s polls through their effect cleanups, so no timer outlives it.
  // preferredSerial (the just-connected _adb-tls-connect._tcp address) is
  // selected when the current selection is gone; refreshDevices already
  // falls back to the first device when nothing is selected, so a fresh
  // single-device workspace auto-selects the new connection.
  async function finishPairingSuccess(message: string, preferredSerial?: string) {
    setCodeTarget(null);
    setCodeError("");
    setCodeBusy(false);
    setCodePhase("pairing");
    setPairError("");
    setPairNotice("");
    const found = await refreshDevices();
    if (preferredSerial && found.some((d) => d.serial === preferredSerial)) {
      setSerial((old) =>
        found.some((d) => d.serial === old) ? old : preferredSerial,
      );
    }
    setNotice(message);
    closeWifiPairing();
  }
  useEffect(() => {
    if (!wifiOpen || !wifiOffer) return;
    let cancelled = false;
    async function poll() {
      try {
        const status = await WifiPairingStatus();
        if (cancelled) return;
        setWifiStatus(status);
        if (status.state === "connected" && !wifiConnected.current) {
          wifiConnected.current = true;
          const label = status.serial
            ? `Connected to ${status.serial}.`
            : "Connected over Wi-Fi.";
          await finishPairingSuccess(label);
        }
      } catch {
        /* keep the last status while the modal is open */
      }
    }
    poll();
    const timer = window.setInterval(poll, 800);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [wifiOpen, wifiOffer]);
  const filteredPairDevices = useMemo(() => {
    const query = pairSearch.trim().toLowerCase();
    if (!query) return pairDevices;
    return pairDevices.filter((device) =>
      device.name.toLowerCase().includes(query),
    );
  }, [pairDevices, pairSearch]);
  useEffect(() => {
    if (!wifiOpen || wifiTab !== "code") return;
    let cancelled = false;
    async function poll() {
      try {
        const found = await ListWifiPairingDevices();
        if (cancelled) return;
        setPairDevices(found);
        setPairError("");
      } catch (e) {
        if (!cancelled) setPairError(String(e));
      }
    }
    poll();
    const timer = window.setInterval(poll, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [wifiOpen, wifiTab]);
  function openCodeDialog(device: WifiPairingDevice) {
    setCodeTarget(device);
    setCodeDigits(["", "", "", "", "", ""]);
    setCodeError("");
  }
  function closeCodeDialog() {
    if (codeBusy) return;
    setCodeTarget(null);
    setCodeError("");
  }
  useEffect(() => {
    if (!codeTarget) return;
    const timer = window.setTimeout(() => codeInputs.current[0]?.focus(), 50);
    return () => window.clearTimeout(timer);
  }, [codeTarget]);
  function setDigit(index: number, value: string) {
    const digit = value.replace(/\D/g, "").slice(-1);
    setCodeDigits((old) => {
      const next = [...old];
      next[index] = digit;
      return next;
    });
    setCodeError("");
    if (digit && index < 5) {
      window.setTimeout(() => codeInputs.current[index + 1]?.focus(), 0);
    }
  }
  function handleDigitKeyDown(
    index: number,
    event: KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Backspace" && !codeDigits[index] && index > 0) {
      setCodeDigits((old) => {
        const next = [...old];
        next[index - 1] = "";
        return next;
      });
      codeInputs.current[index - 1]?.focus();
    }
  }
  function handleDigitPaste(event: ClipboardEvent<HTMLInputElement>) {
    const digits = event.clipboardData
      .getData("text")
      .replace(/\D/g, "")
      .slice(0, 6)
      .split("");
    if (!digits.length) return;
    event.preventDefault();
    setCodeDigits(() => {
      const next = ["", "", "", "", "", ""];
      for (let i = 0; i < 6; i++) next[i] = digits[i] ?? "";
      return next;
    });
    setCodeError("");
    const focusIndex = Math.min(digits.length, 5);
    window.setTimeout(() => codeInputs.current[focusIndex]?.focus(), 0);
  }
  async function submitCode() {
    if (!codeTarget || codeBusy) return;
    const code = codeDigits.join("");
    if (code.length !== 6) {
      setCodeError("Enter the 6 digit code shown on the device.");
      return;
    }
    setCodeBusy(true);
    setCodePhase("pairing");
    setCodeError("");
    // Pairing typically completes in a few seconds; if we are still waiting
    // past this point the backend is polling for the connect address.
    const phaseTimer = window.setTimeout(
      () => setCodePhase("connecting"),
      8000,
    );
    try {
      const target = codeTarget.address;
      const serial = await PairAndConnect(target, code);
      window.clearTimeout(phaseTimer);
      await finishPairingSuccess(
        `Paired with ${target} and connected to ${serial}.`,
        serial,
      );
    } catch (e) {
      window.clearTimeout(phaseTimer);
      setCodeError(String(e));
    } finally {
      setCodeBusy(false);
      setCodePhase("pairing");
    }
  }
  async function refreshDevices(): Promise<Device[]> {
    setBusy("devices");
    setError("");
    try {
      const found = await ListDevices();
      setDevices(found);
      setSerial((old) =>
        found.some((d) => d.serial === old) ? old : (found[0]?.serial ?? ""),
      );
      return found;
    } catch (e) {
      setError(String(e));
      return [];
    } finally {
      setBusy("");
    }
  }
  async function refreshPackages(target = serial) {
    if (!target) return;
    const request = ++loadRequest.current;
    setBusy("packages");
    setPackagesError("");
    setPackages([]);
    setPackageName("");
    setEntries([]);
    try {
      const found = await ListDebugPackages(target);
      if (request !== loadRequest.current) return;
      setPackages(found);
      const firstPackage = found[0]?.packageName ?? "";
      setPackageName(firstPackage);
      setDirectory(".");
      setSelected(null);
      setPreview(null);
      if (firstPackage) {
        setBusy("directory");
        const rootEntries = await ListPackageDirectory(
          target,
          firstPackage,
          ".",
        );
        if (request !== loadRequest.current) return;
        setEntries(rootEntries);
      }
    } catch (e) {
      if (request === loadRequest.current) setPackagesError(String(e));
    } finally {
      if (request === loadRequest.current) setBusy("");
    }
  }
  async function loadDirectory(next = directory, target = packageName) {
    if (!serial || !target) return;
    const request = ++loadRequest.current;
    setBusy("directory");
    setError("");
    setNotice("");
    try {
      const found = await ListPackageDirectory(serial, target, next);
      if (request !== loadRequest.current) return;
      setEntries(found);
      setDirectory(next);
      setSelected(null);
      setPreview(null);
    } catch (e) {
      if (request === loadRequest.current) setError(String(e));
    } finally {
      if (request === loadRequest.current) setBusy("");
    }
  }
  useEffect(() => {
    const device = devices.find((d) => d.serial === serial);
    if (device?.state === "device") refreshPackages(serial);
    else {
      setPackages([]);
      setPackageName("");
      setEntries([]);
    }
  }, [serial, devices]);
  function choosePackage(value: string) {
    ++loadRequest.current;
    setPackageName(value);
    setDirectory(".");
    setEntries([]);
    setSelected(null);
    setPreview(null);
    if (value) loadDirectory(".", value);
  }
  function goUp() {
    if (directory === ".") return;
    const parts = directory.split("/");
    parts.pop();
    loadDirectory(parts.join("/") || ".");
  }
  async function chooseEntry(entry: DirectoryEntry) {
    setSelected(entry);
    setPreview(null);
    setError("");
    setNotice("");
    if (entry.isDirectory) return;
    setBusy("preview");
    try {
      setPreview(
        await PreviewFile(
          serial,
          packageName,
          entry.relativePath,
          entry.size ?? 0,
        ),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy("");
    }
  }
  async function download() {
    if (!selected || selected.isDirectory) return;
    setBusy("download");
    setError("");
    setNotice("");
    try {
      const localPath = await SaveFile(
        serial,
        packageName,
        selected.relativePath,
      );
      setNotice(
        localPath ? `Downloaded to ${localPath}` : "Download canceled",
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy("");
    }
  }
  async function confirmDelete() {
    if (!deleteTarget) return;
    const target = deleteTarget;
    setDeleteTarget(null);
    setBusy("delete");
    setError("");
    setNotice("");
    try {
      await Delete(
        serial,
        packageName,
        target.relativePath,
        target.isDirectory,
      );
      setSelected(null);
      setPreview(null);
      await loadDirectory();
      setNotice(`Deleted ${target.name}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy("");
    }
  }
  function upload() {
    fileInput.current?.click();
  }
  async function handleUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !packageName) return;
    const target = `${directory === "." ? "" : `${directory}/`}${file.name}`;
    if (
      entries.some((item) => item.name === file.name) &&
      !window.confirm(`Overwrite ${file.name}?`)
    )
      return;
    setBusy("upload");
    setError("");
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      const chunk = 0x8000;
      for (let i = 0; i < bytes.length; i += chunk)
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
      await UploadFile(serial, packageName, target, btoa(binary), true);
      setNotice(`Uploaded ${file.name}`);
      await loadDirectory();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy("");
    }
  }
  const adbReady = adbVersion !== "ADB unavailable";
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">AI</div>
          <div>
            <strong>Android Inspector</strong>
            <span>Sandbox file manager</span>
          </div>
          <button
            className="wifi-qr-button"
            onClick={openWifiPairing}
            disabled={!adbReady}
            title="Pair device over Wi-Fi"
            aria-label="Pair device over Wi-Fi"
          >
            <QrIcon />
          </button>
        </div>
        <div className="sidebar-section connection-card">
          <div className="section-heading">
            <span>Connection</span>
            <b className={adbReady ? "" : "offline"}>
              {adbReady ? "ADB ready" : "Offline"}
            </b>
          </div>
          <label>
            Device
            <select value={serial} onChange={(e) => setSerial(e.target.value)}>
              <option value="">Select a device</option>
              {devices.map((d) => (
                <option key={d.serial} value={d.serial}>
                  {d.serial}
                  {d.model ? ` · ${d.model}` : ""}
                </option>
              ))}
            </select>
          </label>
          <button
            className="secondary full"
            onClick={refreshDevices}
            disabled={!!busy}
          >
            {busy === "devices" ? "Refreshing..." : "Refresh devices"}
          </button>
          <div className="device-card">
            <span className="device-icon" aria-hidden="true" />
            <div>
              <strong>{selectedDevice?.model || "No device selected"}</strong>
              <span>
                {selectedDevice
                  ? `${selectedDevice.serial} · ${selectedDevice.state}`
                  : "Connect an authorized device"}
              </span>
            </div>
            <i className={selectedDevice?.state === "device" ? "online" : ""} />
          </div>
          {busy === "devices" && (
            <Progress label="Scanning connected devices" />
          )}
        </div>
        <div className="sidebar-section package-section">
          <div className="section-heading">
            <span>Inspectable app</span>
            <span className="count">{packages.length}</span>
          </div>
          <label>
            Debuggable package
            <select
              value={packageName}
              onChange={(e) => choosePackage(e.target.value)}
              disabled={!serial || !!busy}
            >
              <option value="">
                {busy === "packages" ? "Finding apps..." : "Select a package"}
              </option>
              {packages.map((p) => (
                <option key={p.packageName} value={p.packageName}>
                  {p.packageName}
                </option>
              ))}
            </select>
          </label>
          <button
            className="primary full"
            onClick={() => refreshPackages()}
            disabled={!serial || selectedDevice?.state !== "device" || !!busy}
          >
            {busy === "packages" ? "Loading packages..." : "Refresh apps"}
          </button>
          {busy === "packages" && <Progress label="Checking run-as access" />}
          {packagesError && <p className="error-text">{packagesError}</p>}
        </div>
        <footer className="sidebar-footer">
          Made by Between Bytes Software {new Date().getFullYear()}
        </footer>
      </aside>
      <section className="workspace">
        <header className="workspace-header">
          <div>
            <span className="eyebrow">DEVICE WORKSPACE</span>
            <h1>Sandbox files</h1>
            <p>Browse, preview, and transfer files inside a debuggable app.</p>
          </div>
          <div className="header-status">
            <i className={adbReady ? "online" : ""} />
            {adbReady ? "Ready" : "ADB unavailable"}
          </div>
        </header>
        <section className="file-manager">
          <div className="toolbar">
            <div className="path-area">
              <button
                className="path-nav"
                onClick={goUp}
                disabled={directory === "." || !!busy}
              >
                ‹
              </button>
              <div>
                <span className="path-label">Current path</span>
                <strong title={currentPath}>{currentPath}</strong>
              </div>
            </div>
            <div className="toolbar-actions">
              <button
                className="secondary"
                onClick={upload}
                disabled
                title="Upload a file"
              >
                <ToolbarIcon type="upload" />
                <span>Upload</span>
              </button>
              <button
                className="download-button"
                onClick={download}
                disabled={!selected || selected.isDirectory || !!busy}
                title="Download selected file"
              >
                <ToolbarIcon type="download" />
                <span>Download</span>
              </button>
              <button
                className="delete-button"
                onClick={() => selected && setDeleteTarget(selected)}
                disabled={!selected || !!busy}
                title="Delete selected item"
              >
                <ToolbarIcon type="delete" />
                <span>Delete</span>
              </button>
              <input
                ref={fileInput}
                type="file"
                hidden
                onChange={handleUpload}
              />
            </div>
          </div>
          <div className="manager-body">
            <div className="list-pane">
              <div className="list-heading">
                <span>Name</span>
                <span>Type</span>
                <span>Size</span>
              </div>
              <div className="entry-list">
                {busy === "directory" && <Progress label="Loading files" />}
                {!busy && !entries.length && (
                  <div className="empty-state">
                    {packageName
                      ? "This directory is empty."
                      : "Select a debuggable package to browse files."}
                  </div>
                )}
                {entries.map((entry) => (
                  <button
                    className={`entry-row ${selected?.relativePath === entry.relativePath ? "selected" : ""}`}
                    key={entry.relativePath}
                    onClick={() => chooseEntry(entry)}
                    onDoubleClick={() =>
                      entry.isDirectory && loadDirectory(entry.relativePath)
                    }
                  >
                    <span className="entry-name">
                      <FileIcon directory={entry.isDirectory} />
                      <span title={entry.name}>{entry.name}</span>
                    </span>
                    <span>{entry.isDirectory ? "Folder" : "File"}</span>
                    <span>
                      {formatBytes(entry.size ?? 0, entry.isDirectory)}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            <div className="preview-pane">
              <div className="preview-heading">
                <span>Preview</span>
                {selected && <b>{selected.name}</b>}
              </div>
              {preview?.kind === "image" && mediaURL && (
                <img
                  className="media-preview"
                  src={mediaURL}
                  alt={preview.path}
                />
              )}
              {preview?.kind === "pdf" && preview.content && !pdfError && (
                <>
                  <PdfPreview content={preview.content} onError={setPdfError} />
                  <div className="preview-meta">
                    <span>
                      {preview.mime} · {formatBytes(preview.bytes)}
                    </span>
                  </div>
                </>
              )}
              {preview?.kind === "pdf" && pdfError && (
                <div className="download-panel">
                  <strong>{preview.type}</strong>
                  <span>
                    {preview.mime} · {formatBytes(preview.bytes)}
                  </span>
                  <p>PDF preview could not be rendered: {pdfError}</p>
                  <button
                    className="download-button"
                    onClick={download}
                    disabled={!!busy}
                  >
                    <ToolbarIcon type="download" />
                    <span>Download PDF</span>
                  </button>
                </div>
              )}
              {preview?.kind === "text" && <pre>{preview.content}</pre>}
              {preview &&
                preview.kind !== "text" &&
                preview.kind !== "image" &&
                preview.kind !== "pdf" && (
                  <div className="download-panel">
                    <strong>{preview.type}</strong>
                    <span>
                      {preview.mime} · {formatBytes(preview.bytes)}
                    </span>
                    <p>This file cannot be previewed safely.</p>
                    <button
                      className="download-button"
                      onClick={download}
                      disabled={!!busy}
                    >
                      <ToolbarIcon type="download" />
                      <span>Download file</span>
                    </button>
                  </div>
                )}
              {!preview && (
                <div className="empty-state">
                  {selected?.isDirectory
                    ? "Directory selected. Double-click to open."
                    : selected
                      ? busy === "preview"
                        ? "Loading preview..."
                        : "No preview available."
                      : "Select a file to preview it here."}
                </div>
              )}
            </div>
          </div>
        </section>
        {wifiOpen && (
          <div className="dialog-backdrop" role="presentation">
            <div
              className="wifi-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="wifi-title"
            >
              <div className="wifi-dialog-header">
                <h2 id="wifi-title">Pair devices over Wi-Fi</h2>
                <button className="wifi-close" onClick={closeWifiPairing}>
                  Close
                </button>
              </div>
              <div className="wifi-tabs" role="tablist" aria-label="Pairing method">
                <button
                  role="tab"
                  aria-selected={wifiTab === "qr"}
                  className={wifiTab === "qr" ? "wifi-tab active" : "wifi-tab"}
                  onClick={() => setWifiTab("qr")}
                >
                  Pair using QR code
                </button>
                <button
                  role="tab"
                  aria-selected={wifiTab === "code"}
                  className={wifiTab === "code" ? "wifi-tab active" : "wifi-tab"}
                  onClick={() => setWifiTab("code")}
                >
                  Pair using pairing code
                </button>
              </div>
              {wifiTab === "qr" ? (
                <>
                  <p>
                    Pair an Android 11+ device for wireless debugging. On the
                    phone open Developer options &gt; Wireless debugging &gt;
                    Pair using QR code, then scan this code.
                  </p>
                  <div className="wifi-qr-stage">
                    {wifiOffer?.qrImage ? (
                      <img
                        src={wifiOffer.qrImage}
                        alt="Wi-Fi pairing QR code"
                      />
                    ) : (
                      <Progress label="Generating QR code" />
                    )}
                  </div>
                  {wifiOffer?.host && (
                    <p className="wifi-host">{wifiOffer.host}</p>
                  )}
                  {wifiStatus?.message && (
                    <p
                      className={
                        wifiStatus.state === "failed"
                          ? "error-text"
                          : "notice-text"
                      }
                    >
                      {wifiStatus.message}
                    </p>
                  )}
                  {wifiStatus?.state === "failed" &&
                    wifiStatus.message.includes("could not connect") && (
                      <>
                        <p className="notice-text">
                          The phone paired but its connect address never
                          appeared. Close the pairing screen back to the main
                          Wireless debugging screen (keep its toggle ON), stay
                          on the same Wi-Fi, then try pairing again.
                        </p>
                        <button
                          className="secondary full"
                          onClick={() => void refreshDevices()}
                          disabled={!!busy}
                        >
                          {busy === "devices"
                            ? "Refreshing..."
                            : "Refresh devices"}
                        </button>
                      </>
                    )}
                </>
              ) : (
                <div className="wifi-code-tab" role="tabpanel">
                  <p>
                    1. Connect the phone and this computer to the same Wi-Fi
                    network.
                  </p>
                  <p>
                    2. On the phone open Developer options &gt; Wireless
                    debugging &gt; Pair with pairing code, then tap Pair next
                    to the device below and enter the 6 digit code.
                  </p>
                  <input
                    className="wifi-search"
                    type="search"
                    placeholder="Search for devices by name"
                    aria-label="Search for devices by name"
                    value={pairSearch}
                    onChange={(e) => setPairSearch(e.target.value)}
                  />
                  {/* No API-level column: `adb mdns services` output has none. */}
                  <div className="wifi-device-list">
                    <div className="wifi-device-head">
                      <span>Name</span>
                      <span>IP Address &amp; Port</span>
                      <span />
                    </div>
                    {filteredPairDevices.length === 0 && (
                      <div className="empty-state">
                        No pairing devices found. Keep the pairing screen open
                        on the phone.
                      </div>
                    )}
                    {filteredPairDevices.map((device) => (
                      <div className="wifi-device-row" key={device.address}>
                        <span className="wifi-device-name" title={device.name}>
                          {device.name}
                        </span>
                        <span
                          className="wifi-device-address"
                          title={device.address}
                        >
                          {device.address}
                        </span>
                        <button
                          className="secondary wifi-pair-button"
                          onClick={() => openCodeDialog(device)}
                        >
                          Pair
                        </button>
                      </div>
                    ))}
                  </div>
                  {pairError && <p className="error-text">{pairError}</p>}
                  {pairNotice && <p className="notice-text">{pairNotice}</p>}
                </div>
              )}
            </div>
            {codeTarget && (
              <div className="dialog-backdrop dialog-nested" role="presentation">
                <div
                  className="confirm-dialog code-dialog"
                  role="dialog"
                  aria-modal="true"
                  aria-labelledby="code-title"
                >
                  <h2 id="code-title">Enter pairing code</h2>
                  <p>
                    Enter the 6 digit code shown on the device at{" "}
                    {codeTarget.address} to pair.
                  </p>
                  <div className="code-inputs">
                    {codeDigits.map((digit, index) => (
                      <input
                        key={index}
                        ref={(el) => {
                          codeInputs.current[index] = el;
                        }}
                        value={digit}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        maxLength={1}
                        aria-label={`Digit ${index + 1}`}
                        onChange={(e) => setDigit(index, e.target.value)}
                        onKeyDown={(e) => handleDigitKeyDown(index, e)}
                        onPaste={handleDigitPaste}
                        disabled={codeBusy}
                      />
                    ))}
                  </div>
                  {codeError && <p className="error-text">{codeError}</p>}
                  {codeBusy && (
                    <Progress
                      label={
                        codePhase === "connecting"
                          ? "Connecting…"
                          : "Pairing…"
                      }
                    />
                  )}
                  <div className="dialog-actions">
                    <button
                      className="secondary"
                      onClick={closeCodeDialog}
                      disabled={codeBusy}
                    >
                      Cancel
                    </button>
                    <button
                      className="primary"
                      onClick={submitCode}
                      disabled={codeBusy || codeDigits.join("").length !== 6}
                    >
                      Pair
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
        {deleteTarget && (
          <div className="dialog-backdrop" role="presentation">
            <div
              className="confirm-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="delete-title"
            >
              <h2 id="delete-title">
                Delete {deleteTarget.isDirectory ? "directory" : "file"}?
              </h2>
              <p>
                This will permanently delete{" "}
                <strong>{deleteTarget.relativePath}</strong>.
              </p>
              <div className="dialog-actions">
                <button
                  className="secondary"
                  onClick={() => setDeleteTarget(null)}
                >
                  No
                </button>
                <button className="delete-button" onClick={confirmDelete}>
                  Yes, delete
                </button>
              </div>
            </div>
          </div>
        )}
        {error && <p className="error-text workspace-message">{error}</p>}
        {notice && <p className="notice-text workspace-message">{notice}</p>}
      </section>
    </main>
  );
}
export default App;
