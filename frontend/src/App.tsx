import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import * as pdfjsLib from "pdfjs-dist";
import pdfWorker from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import {
  Delete,
  DetectADB,
  ListDebugPackages,
  ListDevices,
  ListPackageDirectory,
  PreviewFile,
  SaveFile,
  UploadFile,
} from "../wailsjs/go/main/App";
import type { main } from "../wailsjs/go/models";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;
type Device = main.Device;
type DirectoryEntry = main.DirectoryEntry;
type DebugPackage = main.DebugPackage;
type FilePreview = main.FilePreview;

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
  const [mediaURL, setMediaURL] = useState("");
  const [pdfError, setPdfError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const loadRequest = useRef(0);
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
  async function refreshDevices() {
    setBusy("devices");
    setError("");
    try {
      const found = await ListDevices();
      setDevices(found);
      setSerial((old) =>
        found.some((d) => d.serial === old) ? old : (found[0]?.serial ?? ""),
      );
    } catch (e) {
      setError(String(e));
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
