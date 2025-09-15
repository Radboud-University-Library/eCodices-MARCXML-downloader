import os
import csv
import queue
import threading
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
import time
from typing import Iterable, List

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from bookops_worldcat import WorldcatAccessToken, MetadataSession
from requests import HTTPError

# --------------------- Configuration --------------------- #

APP_NAME = "Ecodices MARC Downloader"
DEFAULT_SCOPE = "WorldCatMetadataAPI"

# Retry/session behavior; compatible with requests/urllib3 naming
SESSION_CONFIG = {
    "retry_total": 3,
    "retry_backoff_factor": 0.3,
    "status_forcelist": [500, 502, 503, 504],
    "allowed_methods": ["GET"],
}


# --------------------- Helper Functions --------------------- #

def normalize_ocn(s: str) -> str:
    """
    Normalizes an OCLC Control Number (OCN) by stripping non-digit characters.

    Examples:
        '(OCoLC) 12345678' -> '12345678'
        ' 00123456 '       -> '00123456' (leading zeros preserved)
    """
    s = (s or "").strip()
    # keep digits only if there are any
    digits = "".join(ch for ch in s if ch.isdigit())
    return digits or s


def unique(seq: Iterable[str]) -> List[str]:
    """Returns a list of unique, non-empty strings from an iterable, preserving original order."""
    seen = set()
    out = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


# --------------------- Worker Thread --------------------- #

class Worker(threading.Thread):
    """
    Background worker fetching MARCXML for a list of OCNs and writing output.
    """

    def __init__(
            self,
            ocns,
            out_dir,
            key,
            secret,
            scope,
            log_q,
            progress_cb,
            stop_event,
            delay_ms=0,
    ):
        super().__init__(daemon=True)
        self.ocns = ocns
        self.out_dir = Path(out_dir)
        self.key = key
        self.secret = secret
        self.scope = scope
        self.log_q = log_q
        self.progress_cb = progress_cb
        self.stop_event = stop_event
        self.errors = []
        self.delay_ms = delay_ms

        # Local log buffer so we don't fight the GUI's queue consumer
        self._log_buffer = []

    def log(self, msg: str):
        """Logs a message to the GUI and an internal buffer, with a timestamp."""
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}"
        self._log_buffer.append(line)
        self.log_q.put(line)

    def fetch_marcxml(self, ocn: str, session: MetadataSession) -> str:
        """
        Fetches the MARCXML record for a given OCN.

        Args:
            ocn: The OCLC Control Number.
            session: The MetadataSession to use for the request.

        Returns:
            The MARCXML record as a string.

        Raises:
            HTTPError: If the request fails.
        """
        r = session.bib_get(ocn)
        try:
            r.raise_for_status()
        except HTTPError as e:
            raise HTTPError(f"HTTP {r.status_code} for OCN {ocn}: {r.text[:300]}") from e
        return r.content.decode("utf-8", errors="replace")

    def run(self):
        """The main entry point for the worker thread. Handles authentication, session creation, and processing of OCNs."""
        records_dir = self.out_dir / "records"
        records_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.out_dir / "run.log"

        # Acquire token once
        try:
            token = WorldcatAccessToken(key=self.key, secret=self.secret, scopes=self.scope)
            self.log("Authenticatie geslaagd (OAuth token opgehaald).")
        except Exception as e:
            self.log(f"Fout bij ophalen token: {e}")
            self._flush_log(log_path)
            return

        # Build a single MetadataSession with retry settings
        try:
            session = MetadataSession(authorization=token, **SESSION_CONFIG)
        except TypeError:
            # Fallback if the installed bookops_worldcat doesn't accept these kwargs
            session = MetadataSession(authorization=token)

        # Process OCNs
        self._process_ocns(session, records_dir)

        # Create output files
        self._create_output_files(records_dir)

        self.log("Gereed.")
        self._flush_log(log_path)

    def _process_ocns(self, session, records_dir):
        """Iterates through OCNs, fetches MARCXML for each, and saves them to individual files."""
        total = len(self.ocns)
        done = 0

        with session:
            for ocn in self.ocns:
                if self.stop_event.is_set():
                    self.log("Proces gestopt door gebruiker.")
                    break

                try:
                    xml = self.fetch_marcxml(ocn, session)
                    (records_dir / f"{ocn}.xml").write_text(xml, encoding="utf-8")
                    self.log(f"{ocn}: opgeslagen.")
                except Exception as e:
                    self.errors.append({"ocn": ocn, "error": str(e)})
                    self.log(f"{ocn}: mislukt ({e}).")

                done += 1
                try:
                    self.progress_cb(done, total)
                except Exception:
                    # GUI might have been closed; ignore
                    pass

                # polite delay if asked
                if self.delay_ms and not self.stop_event.is_set():
                    time.sleep(self.delay_ms / 1000.0)

    def _create_output_files(self, records_dir):
        """Create error log and ZIP file with records."""
        # Write errors.csv (if any)
        if self.errors:
            errp = self.out_dir / "errors.csv"
            with errp.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["ocn", "error"])
                w.writeheader()
                w.writerows(self.errors)
            self.log(f"Fouten weggeschreven naar {errp}")

        # Create zip (records + errors.csv)
        try:
            zip_path = self.out_dir / "marcxml.zip"
            with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as z:
                for p in records_dir.glob("*.xml"):
                    z.write(p, arcname=f"records/{p.name}")
                if self.errors and (self.out_dir / "errors.csv").exists():
                    z.write(self.out_dir / "errors.csv", arcname="errors.csv")
            self.log(f"Zipbestand gereed: {zip_path}")
        except Exception as e:
            self.log(f"Kon zip niet maken: {e}")

    def _flush_log(self, log_path: Path):
        """Write log buffer to file."""
        try:
            with log_path.open("a", encoding="utf-8") as lf:
                for line in self._log_buffer:
                    lf.write(line + "\n")
        except Exception:
            # If even writing the log fails, we can't do more here
            pass


# --------------------- Main Application --------------------- #

class App(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("780x600")

        # State variables
        self.key = tk.StringVar()
        self.secret = tk.StringVar()
        self.scope = tk.StringVar(value=DEFAULT_SCOPE)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = tk.StringVar()
        self.out_dir = tk.StringVar(value=str(Path.cwd() / f"output/{ts}"))
        self.delay_ms = tk.IntVar(value=0)

        self.log_q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None

        self._build_ui()
        self.after(100, self._drain_log)

    def _build_ui(self):
        """Build the complete user interface."""
        pad = {"padx": 8, "pady": 6}
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True)

        # Credentials section
        creds = ttk.LabelFrame(root, text="WorldCat API")
        creds.pack(fill="x", **pad)
        ttk.Label(creds, text="Key").grid(row=0, column=0, sticky="e", **pad)
        ttk.Entry(creds, textvariable=self.key, show="*").grid(row=0, column=1, sticky="we", **pad)
        ttk.Label(creds, text="Secret").grid(row=1, column=0, sticky="e", **pad)
        ttk.Entry(creds, textvariable=self.secret, show="*").grid(row=1, column=1, sticky="we", **pad)
        ttk.Label(creds, text="Scope").grid(row=2, column=0, sticky="e", **pad)
        ttk.Entry(creds, textvariable=self.scope).grid(row=2, column=1, sticky="we", **pad)
        creds.columnconfigure(1, weight=1)

        # Input section
        inputf = ttk.LabelFrame(root, text="OCLC-nummers (kies CSV of plak lijst)")
        inputf.pack(fill="both", **pad)

        top = ttk.Frame(inputf)
        top.pack(fill="x", **pad)
        ttk.Entry(top, textvariable=self.csv_path).pack(side="left", fill="x", expand=True)
        ttk.Button(top, text="Kies CSV…", command=self._pick_csv).pack(side="left", padx=6)
        ttk.Label(inputf, text="CSV vereist kolom: 'OCLC Number' (of 'OCLC', 'OCLCNumber', 'ocn')").pack(anchor="w",
                                                                                                         padx=8)

        ttk.Label(inputf, text="Of plak OCN's (één per regel; komma of puntkomma mag ook):").pack(anchor="w", padx=8)
        self.paste = tk.Text(inputf, height=6)
        self.paste.pack(fill="both", expand=True, padx=8, pady=6)

        # Output section
        outf = ttk.LabelFrame(root, text="Output")
        outf.pack(fill="x", **pad)
        ttk.Entry(outf, textvariable=self.out_dir).grid(row=0, column=0, sticky="we", **pad)
        ttk.Button(outf, text="Kies map…", command=self._pick_out_dir).grid(row=0, column=1, **pad)
        ttk.Button(outf, text="Open outputmap", command=self._open_out_dir).grid(row=0, column=2, **pad)
        ttk.Label(outf, text="Pauze tussen verzoeken (ms, optioneel):").grid(row=1, column=0, sticky="e", **pad)
        ttk.Spinbox(outf, from_=0, to=5000, increment=100, textvariable=self.delay_ms, width=10).grid(row=1, column=1,
                                                                                                      sticky="w", **pad)
        outf.columnconfigure(0, weight=1)

        # Controls section
        ctrls = ttk.Frame(root)
        ctrls.pack(fill="x", **pad)
        self.btn_start = ttk.Button(ctrls, text="Start downloaden", command=self._start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(ctrls, text="Stop", command=self._stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.pb = ttk.Progressbar(ctrls, mode="determinate")
        self.pb.pack(fill="x", expand=True, padx=8)

        # Log section
        logf = ttk.LabelFrame(root, text="Log")
        logf.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(logf, height=12)
        self.txt.pack(fill="both", expand=True, padx=8, pady=8)

    # ---- UI helpers
    def _pick_csv(self):
        """Open file dialog to select CSV file."""
        p = filedialog.askopenfilename(title="Kies CSV", filetypes=[("CSV", "*.csv"), ("Alle bestanden", "*.*")])
        if p:
            self.csv_path.set(p)

    def _pick_out_dir(self):
        """Open directory dialog to select output folder."""
        d = filedialog.askdirectory(title="Kies outputmap")
        if d:
            self.out_dir.set(d)

    def _open_out_dir(self):
        """Open the output directory in system file explorer."""
        path = self.out_dir.get()
        if not path:
            messagebox.showwarning(APP_NAME, "Geen outputmap ingesteld.")
            return
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(str(p))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Kon de map niet openen: {e}")

    def _log(self, msg):
        """Add message to the log display."""
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")

    def _drain_log(self):
        """Process log messages from the queue."""
        try:
            while True:
                self._log(self.log_q.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self._drain_log)

    # ---- Parsing
    def _parse_csv(self, path):
        """Parse OCNs from a CSV file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"CSV bestand niet gevonden: {path}")

        with p.open("r", encoding="utf-8-sig", newline="") as f:
            sample = f.read(4096)
            f.seek(0)
            try:
                sniff = csv.Sniffer().sniff(sample, delimiters=";,\t")
                delim = sniff.delimiter
            except Exception:
                delim = ","
            reader = csv.DictReader(f, delimiter=delim)
            if not reader.fieldnames:
                raise ValueError("CSV bestand heeft geen headers")

            # allow several header variants
            lower_map = {c.lower().strip(): c for c in reader.fieldnames}
            candidates = ["oclc number", "oclc", "oclcnumber", "ocn"]
            ocn_header = next((lower_map[c] for c in candidates if c in lower_map), None)
            if not ocn_header:
                raise ValueError("CSV mist kolom 'OCLC Number' (of 'OCLC', 'OCLCNumber', 'ocn').")

            ocns = []
            for row in reader:
                raw = (row.get(ocn_header) or "").strip()
                if raw:
                    ocns.append(normalize_ocn(raw))
            return [o for o in ocns if o]

    def _parse_pasted(self):
        """Parse OCNs from pasted text."""
        raw = self.paste.get("1.0", "end").strip()
        if not raw:
            return []
        parts = []
        for chunk in raw.replace(";", "\n").replace(",", "\n").splitlines():
            c = normalize_ocn(chunk)
            if c:
                parts.append(c)
        return unique(parts)

    # ---- Run
    def _start(self):
        """Start the download process."""
        key = self.key.get().strip()
        secret = self.secret.get().strip()
        scope = self.scope.get().strip() or DEFAULT_SCOPE

        if not key or not secret:
            messagebox.showerror(APP_NAME, "Vul Key en Secret in.")
            return

        # Collect OCNs from all sources
        ocns = []
        if self.csv_path.get():
            try:
                ocns = self._parse_csv(self.csv_path.get())
            except Exception as e:
                messagebox.showerror(APP_NAME, f"CSV-fout: {e}")
                return

        pasted = self._parse_pasted()
        ocns = unique(ocns + pasted)

        if not ocns:
            messagebox.showerror(APP_NAME, "Geen OCLC-nummers opgegeven (CSV of plakveld).")
            return

        # Prepare for download
        out_dir = Path(self.out_dir.get())
        out_dir.mkdir(parents=True, exist_ok=True)

        self.pb["value"] = 0
        self.pb["maximum"] = len(ocns)
        self.stop_event.clear()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        self._log(f"Start: {len(ocns)} OCN's → {out_dir}")

        # Create and start worker
        self.worker = Worker(
            ocns=ocns,
            out_dir=out_dir,
            key=key,
            secret=secret,
            scope=scope,
            log_q=self.log_q,
            progress_cb=lambda done, total: self.pb.config(value=done),
            stop_event=self.stop_event,
            delay_ms=self.delay_ms.get(),
        )
        self.worker.start()
        self.after(400, self._check_done)

    def _check_done(self):
        """Check if worker thread has completed."""
        if self.worker and self.worker.is_alive():
            self.after(400, self._check_done)
        else:
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")
            self._log("Proces afgerond.")

    def _stop(self):
        """Stop the download process."""
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            self._log("Stop aangevraagd door gebruiker.")


def main():
    """Application entry point."""
    app = App()
    try:
        app.mainloop()
    finally:
        # Ensure worker shuts down cleanly if app closed during run
        if app.worker and app.worker.is_alive():
            app.stop_event.set()
            app.worker.join(timeout=2.0)


if __name__ == "__main__":
    main()