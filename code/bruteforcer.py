# yes ai was used, dont kill me!!
# im not gonna do this manually
import tkinter as tk
from tkinter import messagebox
from storage import load_encrypted_object
from string import printable, digits, ascii_letters
import concurrent.futures
import multiprocessing
import time
import os
import bcrypt
from typing import Tuple

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "./db"))
DATABASE_FILE = os.path.join(DB_FOLDER, "database.db")


# ------------------------------------------------------------
# Worker function (top-level for pickling). It works on a
# range of indices for a specific phase/charset. It reports
# progress through progress_queue and reports 'found' if success.
# ------------------------------------------------------------
def check_password_chunk_phase(
    start_idx: int,
    end_idx: int,
    charset: str,
    pw_len: int,
    target_hash: bytes,
    stop_event,
    progress_queue,
    report_every: int,
    phase_id: int,
    prev_phase_chars: str,
) -> int:
    """
    Try indices in [start_idx, end_idx) for the given charset.
    - `phase_id` (0,1,2) identifies which phase we're testing.
    - `prev_phase_chars` is a string of characters that define the previous-phase alphabet:
       * For phase 1 prev_phase_chars = '' (unused).
       * For phase 2 prev_phase_chars = digits (we skip "all-digit" passwords).
       * For phase 3 prev_phase_chars = digits+letters (we skip any password that is entirely digits+letters).
    Behavior:
    - Sends ("progress", phase_id, n_checked) periodically.
    - If found, sends ("progress", phase_id, n_checked) for final chunk, then ("found", phase_id, password) and returns idx.
    - On graceful stop or normal completion returns -1.
    """
    base = len(charset)
    prev_set = set(prev_phase_chars) if prev_phase_chars else None

    def index_to_password(index: int) -> str:
        chars = []
        for _ in range(pw_len):
            index, rem = divmod(index, base)
            chars.append(charset[rem])
        return "".join(reversed(chars))

    checked_since_report = 0
    for idx in range(start_idx, end_idx):
        if stop_event.is_set():
            if checked_since_report:
                progress_queue.put(("progress", phase_id, checked_since_report))
            return -1

        pw = index_to_password(idx)

        # Skip passwords that belong entirely to previous phase(s).
        # Phase 2: skip if all chars in digits
        # Phase 3: skip if all chars in digits+letters (prev_set contains digits+letters)
        if prev_set is not None:
            all_prev = True
            for ch in pw:
                if ch not in prev_set:
                    all_prev = False
                    break
            if all_prev:
                # do not count as a check here (we already checked them in previous phase)
                continue

        # Now this is a new, unique candidate to check
        checked_since_report += 1

        if bcrypt.checkpw(pw.encode(), target_hash):
            # report progress up to and including this success
            if checked_since_report:
                progress_queue.put(("progress", phase_id, checked_since_report))
            progress_queue.put(("found", phase_id, pw))
            return idx

        if checked_since_report >= report_every:
            progress_queue.put(("progress", phase_id, checked_since_report))
            checked_since_report = 0

    # finished chunk - report any leftover
    if checked_since_report:
        progress_queue.put(("progress", phase_id, checked_since_report))
    return -1


# ------------------------------------------------------------
# Main UI and orchestration
# ------------------------------------------------------------
class BruteForceUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Brute-Forcer (phased order)")
        self.root.geometry("720x460")

        # Define charsets for phases
        self.phase_charsets = [
            digits,  # phase 0: digits only
            digits + ascii_letters,  # phase 1: digits + letters
            printable[
                :-6
            ],  # phase 2: full printable minus last 6 whitespace (as before)
        ]
        # prev_phase_chars used to skip duplicates:
        # phase0 prev = ''
        # phase1 prev = digits
        # phase2 prev = digits+letters
        self.prev_phase_chars = ["", digits, digits + ascii_letters]

        self.pw_len = 8
        # Precompute per-phase totals (unique counts per phase)
        self.phase_totals = self._compute_phase_totals()
        self.total_passwords = sum(self.phase_totals)

        # multiprocess primitives
        self.manager = None
        self.stop_event = None
        self.progress_queue = None
        self.executor = None
        self.active_futures = set()

        # runtime counters
        self.current_phase = 0
        self.next_index = 0
        self.checked_per_phase = [
            0,
            0,
            0,
        ]  # counts of actual attempted/checks per phase
        self.checked_total = 0
        self.start_time = None
        self.target_hash = None

        self.found_password = None
        self.found_phase = None

        # UI elements
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(padx=12, pady=12, fill="both", expand=True)
        self._build_ui()

    def _compute_phase_totals(self):
        # phase0_total = 10**8
        # phase1_total = (62**8) - (10**8)
        # phase2_total = (94**8) - (62**8)
        a = pow(len(self.phase_charsets[0]), self.pw_len)  # digits^8
        b = pow(len(self.phase_charsets[1]), self.pw_len)  # digits+letters ^8
        c = pow(len(self.phase_charsets[2]), self.pw_len)  # full charset ^8
        return [a, b - a, c - b]

    def _build_ui(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

        top = tk.Frame(self.main_frame)
        top.pack(fill="x", pady=(0, 8))

        tk.Label(
            top,
            text="Brute-Force (phased: digits → digits+letters → all)",
            font=("Helvetica", 14),
        ).pack(anchor="w")

        entry_row = tk.Frame(self.main_frame)
        entry_row.pack(fill="x", pady=(4, 8))
        tk.Label(entry_row, text="Target Username (local DB):").pack(side="left")
        self.username_entry = tk.Entry(entry_row)
        self.username_entry.pack(side="left", padx=8)

        controls = tk.Frame(self.main_frame)
        controls.pack(fill="x", pady=(4, 8))
        tk.Button(controls, text="Start Attack", command=self.start_attack).pack(
            side="left", padx=4
        )
        self.cancel_btn = tk.Button(
            controls, text="Cancel", state="disabled", command=self.cancel_attack
        )
        self.cancel_btn.pack(side="left", padx=4)

        cfg = tk.Frame(self.main_frame)
        cfg.pack(fill="x", pady=(4, 8))
        tk.Label(cfg, text="Workers:").pack(side="left")
        self.workers_var = tk.IntVar(value=max(1, os.cpu_count() or 1))
        tk.Entry(cfg, width=4, textvariable=self.workers_var).pack(side="left", padx=4)

        tk.Label(cfg, text="Chunk size:").pack(side="left", padx=(8, 0))
        self.chunk_var = tk.IntVar(value=5000)
        tk.Entry(cfg, width=7, textvariable=self.chunk_var).pack(side="left", padx=4)

        tk.Label(cfg, text="Report every (worker):").pack(side="left", padx=(8, 0))
        self.report_var = tk.IntVar(value=256)
        tk.Entry(cfg, width=6, textvariable=self.report_var).pack(side="left", padx=4)

        # Total progress UI
        self.total_frame = tk.Frame(self.main_frame, relief="groove", bd=1)
        self.total_frame.pack(fill="x", pady=(8, 6))
        tk.Label(
            self.total_frame, text="Total Progress", font=("Helvetica", 10, "bold")
        ).pack(anchor="w", padx=6, pady=(6, 0))
        self.total_label = tk.Label(
            self.total_frame, text=f"0 / {self.total_passwords} (0.00%)"
        )
        self.total_label.pack(anchor="w", padx=6)
        self.total_canvas = tk.Canvas(self.total_frame, height=20)
        self.total_canvas.pack(fill="x", padx=6, pady=(4, 6))
        self.total_rect_tag = "total_progress_rect"

        # Per-phase progress UI
        self.phase_frames = []
        self.phase_labels = []
        self.phase_canvases = []
        for i in range(3):
            pf = tk.Frame(self.main_frame, relief="ridge", bd=1)
            pf.pack(fill="x", pady=(4, 2))
            tk.Label(
                pf,
                text=f"Phase {i+1}: {self._phase_description(i)}",
                font=("Helvetica", 10, "bold"),
            ).pack(anchor="w", padx=6, pady=(6, 0))
            lbl = tk.Label(pf, text=f"0 / {self.phase_totals[i]} (0.00%)")
            lbl.pack(anchor="w", padx=6)
            cn = tk.Canvas(pf, height=14)
            cn.pack(fill="x", padx=6, pady=(4, 6))
            self.phase_frames.append(pf)
            self.phase_labels.append(lbl)
            self.phase_canvases.append(cn)

        # Status / speed
        self.status_label = tk.Label(
            self.main_frame, text="Status: Idle", anchor="w", justify="left"
        )
        self.status_label.pack(fill="x", pady=(8, 0))

    def _phase_description(self, i: int) -> str:
        if i == 0:
            return "Digits only (0-9)"
        if i == 1:
            return "Digits + letters (0-9, a-z, A-Z), excluding all-digits"
        return "Full printable charset (excludes previous charset-only combos)"

    # --------------------------
    # Starting / orchestrating
    # --------------------------
    def start_attack(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Missing", "Please enter a username.")
            return

        db = load_encrypted_object(DATABASE_FILE)
        stored_hash = db["users"].get(username)
        if stored_hash is None:
            messagebox.showerror(
                "User not found", f"User '{username}' does not exist in local DB."
            )
            return
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode()

        # Reset runtime state
        self.cancel_btn.config(state="normal")
        self.status_label.config(text="Brute-force started...")
        self.current_phase = 0
        self.next_index = 0
        self.checked_per_phase = [0, 0, 0]
        self.checked_total = 0
        self.start_time = time.time()
        self.target_hash = stored_hash
        self.found_password = None
        self.found_phase = None

        # Multiprocess primitives
        self.manager = multiprocessing.Manager()
        self.stop_event = self.manager.Event()
        self.progress_queue = self.manager.Queue()

        # ProcessPool
        workers = max(1, int(self.workers_var.get()))
        self.executor = concurrent.futures.ProcessPoolExecutor(max_workers=workers)

        # Submit initial work for phase 0
        self._start_phase(self.current_phase)

        # Start polling loop
        self.root.after(100, self._poll_loop)

    def _start_phase(self, phase: int):
        # prepare phase-specific parameters
        charset = self.phase_charsets[phase]
        total_indices = pow(len(charset), self.pw_len)
        self.phase_index_limit = (
            total_indices  # indices for this phase's charset (0..limit-1)
        )
        self.next_index = 0

        # active futures set
        self.active_futures = set()
        chunk_size = max(1, int(self.chunk_var.get()))
        workers = max(1, int(self.workers_var.get()))
        # Submit up to `workers` initial chunks
        for _ in range(workers):
            self._submit_chunk_for_phase(phase, chunk_size)

    def _submit_chunk_for_phase(self, phase: int, chunk_size: int):
        if self.next_index >= self.phase_index_limit or (
            self.stop_event and self.stop_event.is_set()
        ):
            return
        start = self.next_index
        end = min(self.phase_index_limit, start + chunk_size)
        fut = self.executor.submit(
            check_password_chunk_phase,
            start,
            end,
            self.phase_charsets[phase],
            self.pw_len,
            self.target_hash,
            self.stop_event,
            self.progress_queue,
            max(1, int(self.report_var.get())),
            phase,
            self.prev_phase_chars[phase],
        )
        self.active_futures.add((fut, start, end))
        self.next_index = end

    # --------------------------
    # Polling and progress update
    # --------------------------
    def _drain_progress_queue(self):
        """Process all messages in progress_queue and update counts."""
        while True:
            try:
                msg = self.progress_queue.get_nowait()
            except Exception:
                break
            if not isinstance(msg, tuple) or len(msg) < 2:
                continue
            tag = msg[0]
            if tag == "progress":
                _, phase_id, n = msg
                n = int(n)
                self.checked_per_phase[int(phase_id)] += n
                self.checked_total += n
            elif tag == "found":
                _, phase_id, pw = msg
                self.found_phase = int(phase_id)
                self.found_password = str(pw)
                # tell workers to stop
                if self.stop_event:
                    self.stop_event.set()

    def _poll_loop(self):
        # Drain queue first
        if self.progress_queue:
            self._drain_progress_queue()

        # Check active futures for completion, gather results, and refill
        finished_items = []
        for fut, s, e in list(self.active_futures):
            if fut.done():
                finished_items.append((fut, s, e))
                try:
                    res = fut.result(timeout=0)
                except Exception:
                    res = -1
                # If worker found something, it should have put ("found", ...) into queue already.
                if res is not None and res != -1:
                    # fallback: if no queue message arrived, set found here
                    if not self.found_password:
                        # compute the actual password from index using the phase charset
                        pw = self._index_to_password_phase(res, self.current_phase)
                        self.found_phase = self.current_phase
                        self.found_password = pw
                        if self.stop_event:
                            self.stop_event.set()
        # remove finished items and submit a replacement chunk (if phase still has indices)
        for item in finished_items:
            if item in self.active_futures:
                self.active_futures.remove(item)
            # submit new chunk for the freed worker
            if not (self.stop_event and self.stop_event.is_set()):
                self._submit_chunk_for_phase(
                    self.current_phase, max(1, int(self.chunk_var.get()))
                )

        # update UI elements (total and per-phase)
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        rate = self.checked_total / elapsed if elapsed > 0 else 0.0
        total_percent = (
            (self.checked_total / self.total_passwords) * 100
            if self.total_passwords
            else 0.0
        )
        self.status_label.config(
            text=f"Phase {self.current_phase+1} running. Speed: {rate:.1f} checks/s"
        )
        self.total_label.config(
            text=f"{self.checked_total} / {self.total_passwords} ({total_percent:.6f}%)"
        )
        self._draw_canvas(self.total_canvas, self.total_rect_tag, total_percent)

        # per-phase bars
        for i in range(3):
            checked = self.checked_per_phase[i]
            total = self.phase_totals[i]
            pct = (checked / total) * 100 if total else 0.0
            self.phase_labels[i].config(text=f"{checked} / {total} ({pct:.6f}%)")
            self._draw_canvas(self.phase_canvases[i], f"phase{i}_rect", pct)

        # termination checks:
        if self.found_password:
            # shutdown executor and present found UI
            try:
                if self.executor:
                    self.executor.shutdown(wait=False)
            except Exception:
                pass
            self._display_found()
            return

        # If no more active futures AND we've exhausted indices for this phase -> move to next phase
        if not self.active_futures and self.next_index >= self.phase_index_limit:
            # Phase finished. Move to next if any
            self.current_phase += 1
            if self.current_phase >= len(self.phase_charsets):
                # All phases done
                # drain any last messages
                if self.progress_queue:
                    self._drain_progress_queue()
                self.status_label.config(text="Attack finished. No match found.")
                try:
                    if self.executor:
                        self.executor.shutdown(wait=False)
                except Exception:
                    pass
                self._finalize()
                return
            else:
                # Start next phase
                self._start_phase(self.current_phase)

        # otherwise, schedule next poll
        self.root.after(100, self._poll_loop)

    def _draw_canvas(self, canvas: tk.Canvas, tag: str, percent: float):
        canvas.delete(tag)
        w = canvas.winfo_width() or 200
        fill_w = int((percent / 100.0) * w)
        if fill_w > 0:
            canvas.create_rectangle(
                0, 0, fill_w, canvas.winfo_height(), fill="green", tags=tag
            )
        canvas.create_rectangle(
            0, 0, w, canvas.winfo_height(), outline="black", tags=tag
        )

    def _index_to_password_phase(self, index: int, phase: int) -> str:
        charset = self.phase_charsets[phase]
        base = len(charset)
        chars = []
        for _ in range(self.pw_len):
            index, rem = divmod(index, base)
            chars.append(charset[rem])
        return "".join(reversed(chars))

    def cancel_attack(self):
        if self.stop_event:
            self.stop_event.set()
        self.status_label.config(text="Attack canceled by user.")
        try:
            if self.executor:
                self.executor.shutdown(wait=False)
        except Exception:
            pass
        self._finalize()

    def _display_found(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

        tk.Label(
            self.main_frame, text="Password Found!", font=("Helvetica", 14), fg="green"
        ).pack(pady=8)
        tk.Label(self.main_frame, text=f"Phase: {self.found_phase+1}").pack()
        tk.Label(
            self.main_frame,
            text=f"Password: {self.found_password}",
            font=("Courier", 12),
        ).pack(pady=6)
        tk.Button(
            self.main_frame, text="Copy to Clipboard", command=self._copy_to_clipboard
        ).pack(pady=4)
        tk.Button(self.main_frame, text="Close", command=self.root.quit).pack(pady=4)

    def _copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.found_password)
        self.root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def _finalize(self):
        try:
            self.cancel_btn.config(state="disabled")
        except Exception:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = BruteForceUI(root)
    root.mainloop()
