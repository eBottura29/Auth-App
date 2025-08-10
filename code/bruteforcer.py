# bruteforcer.py
import tkinter as tk
from tkinter import messagebox
from storage import load_encrypted_object
from string import printable
import concurrent.futures
import multiprocessing
import time
import os
import bcrypt

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "./db"))
DATABASE_FILE = os.path.join(DB_FOLDER, "database.db")


def check_password_chunk(
    start_idx: int,
    end_idx: int,
    charset: str,
    pw_len: int,
    target_hash: bytes,
    stop_event,
    progress_queue,
    report_every: int = 256,
) -> int:
    """
    Try indices in [start_idx, end_idx).
    - Periodically send progress messages to progress_queue as ('progress', n_checked).
    - If password found, send ('found', idx) and return idx.
    - On normal completion, send a final ('progress', n_remaining) and return -1.
    """
    base = len(charset)

    def index_to_password(index: int) -> str:
        chars = []
        for _ in range(pw_len):
            index, rem = divmod(index, base)
            chars.append(charset[rem])
        return "".join(reversed(chars))

    checked_since_report = 0
    total_checked = 0

    for idx in range(start_idx, end_idx):
        if stop_event.is_set():
            # send any remaining progress before exiting
            if checked_since_report:
                progress_queue.put(("progress", checked_since_report))
            return -1

        pw = index_to_password(idx)
        total_checked += 1
        checked_since_report += 1

        if bcrypt.checkpw(pw.encode(), target_hash):
            # report the checks done up to and including the found password
            if checked_since_report:
                progress_queue.put(("progress", checked_since_report))
            progress_queue.put(("found", idx))
            return idx

        # report periodically to avoid too many small messages
        if checked_since_report >= report_every:
            progress_queue.put(("progress", checked_since_report))
            checked_since_report = 0

    # send any final leftover progress
    if checked_since_report:
        progress_queue.put(("progress", checked_since_report))

    return -1


class BruteForceUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Brute-Forcer")
        self.root.geometry("560x380")

        self.stop_event = None  # multiprocessing Event for cancel
        self.progress_queue = None
        self.executor = None
        self.active_futures = set()
        self.target_hash = None

        self.found_password = None
        self.found_index = None

        self.charset = printable[:-6]
        self.password_length = 8
        self.max_index = len(self.charset) ** self.password_length

        # runtime counters
        self.next_index = 0
        self.checked = 0
        self.start_time = None

        self.main_frame = tk.Frame(root)
        self.main_frame.pack(padx=12, pady=12, fill="both", expand=True)
        self.build_ui()

    def build_ui(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

        tk.Label(
            self.main_frame, text="Brute-Force Attack Tool", font=("Helvetica", 14)
        ).pack(pady=6)
        tk.Label(self.main_frame, text="Target Username (local DB):").pack(anchor="w")
        self.username_entry = tk.Entry(self.main_frame)
        self.username_entry.pack(pady=4, fill="x")

        controls = tk.Frame(self.main_frame)
        controls.pack(pady=6, fill="x")
        tk.Button(controls, text="Start Attack", command=self.start_attack).pack(
            side="left", padx=4
        )
        self.cancel_btn = tk.Button(
            controls, text="Cancel Attack", state="disabled", command=self.cancel_attack
        )
        self.cancel_btn.pack(side="left", padx=4)

        cfg = tk.Frame(self.main_frame)
        cfg.pack(pady=6, fill="x")
        tk.Label(cfg, text="Workers:").pack(side="left")
        self.workers_var = tk.IntVar(value=max(1, os.cpu_count() or 1))
        tk.Entry(cfg, width=4, textvariable=self.workers_var).pack(side="left", padx=4)

        tk.Label(cfg, text="Chunk size:").pack(side="left", padx=(8, 0))
        self.chunk_var = tk.IntVar(value=2000)
        tk.Entry(cfg, width=7, textvariable=self.chunk_var).pack(side="left", padx=4)

        tk.Label(cfg, text="Report every (worker):").pack(side="left", padx=(8, 0))
        self.report_var = tk.IntVar(value=256)
        tk.Entry(cfg, width=6, textvariable=self.report_var).pack(side="left", padx=4)

        # progress area
        self.output_label = tk.Label(
            self.main_frame, text="Status: Idle", anchor="w", justify="left"
        )
        self.output_label.pack(pady=8, fill="x")

        self.progress_bar_frame = tk.Frame(self.main_frame)
        self.progress_bar_frame.pack(fill="x", pady=6)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_label = tk.Label(self.progress_bar_frame, text="0 / 0 (0.00%)")
        self.progress_label.pack(side="left")

        # simple progress bar using Canvas
        self.canvas = tk.Canvas(self.progress_bar_frame, height=18)
        self.canvas.pack(side="right", fill="x", expand=True, padx=(8, 0))
        self.canvas_rect = None

    def start_attack(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Missing", "Enter a username.")
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

        # reset runtime state
        self.cancel_btn.config(state="normal")
        self.output_label.config(text="Brute-force started...")
        self.found_password = None
        self.found_index = None
        self.next_index = 0
        self.checked = 0
        self.start_time = time.time()
        self.target_hash = stored_hash

        # multiprocess primitives
        mgr = multiprocessing.Manager()
        self.stop_event = mgr.Event()
        self.progress_queue = mgr.Queue()

        # executor
        workers = max(1, int(self.workers_var.get()))
        self.executor = concurrent.futures.ProcessPoolExecutor(max_workers=workers)

        # submit initial jobs (up to workers)
        chunk_size = max(1, int(self.chunk_var.get()))
        report_every = max(1, int(self.report_var.get()))
        self.chunk_size = chunk_size
        self.report_every = report_every

        self.active_futures = set()
        for _ in range(workers):
            self._submit_next_chunk()

        # start polling both futures and progress queue
        self.root.after(100, self._poll_loop)

    def _submit_next_chunk(self):
        if self.next_index >= self.max_index or (
            self.stop_event and self.stop_event.is_set()
        ):
            return
        start = self.next_index
        end = min(self.max_index, start + self.chunk_size)
        fut = self.executor.submit(
            check_password_chunk,
            start,
            end,
            self.charset,
            self.password_length,
            self.target_hash,
            self.stop_event,
            self.progress_queue,
            self.report_every,
        )
        self.active_futures.add((fut, start, end))
        self.next_index = end

    def _drain_progress_queue(self):
        """Read all queued progress/found messages and update internal counters."""
        while True:
            try:
                msg = self.progress_queue.get_nowait()
            except Exception:
                break
            if not isinstance(msg, tuple) or len(msg) < 2:
                continue
            tag, val = msg[0], msg[1]
            if tag == "progress":
                # val is number of checked passwords since last report
                self.checked += int(val)
            elif tag == "found":
                # val is index where password was found
                self.found_index = int(val)
                self.found_password = self._index_to_password(self.found_index)
                # stop everything
                if self.stop_event:
                    self.stop_event.set()
            # ignore unknown tags

    def _poll_loop(self):
        # first, drain progress messages (updates checked)
        if self.progress_queue:
            self._drain_progress_queue()

        # check futures that completed and submit more work as needed
        finished = []
        for fut, s, e in list(self.active_futures):
            if fut.done():
                finished.append((fut, s, e))
                try:
                    res = fut.result(timeout=0)
                except Exception:
                    res = -1

                # If a worker found the password, found message already handled via queue;
                # but double-check result and set found_index if needed.
                if res is not None and res != -1:
                    self.found_index = res
                    self.found_password = self._index_to_password(res)
                    if self.stop_event:
                        self.stop_event.set()

        # remove finished and submit new chunks (one per finished)
        for item in finished:
            if item in self.active_futures:
                self.active_futures.remove(item)
            # submit next chunk for this freed worker
            if not (self.stop_event and self.stop_event.is_set()):
                self._submit_next_chunk()

        # update UI status and progress bar
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        rate = self.checked / elapsed if elapsed > 0 else 0.0
        percent = (self.checked / self.max_index) * 100 if self.max_index else 0.0
        self.output_label.config(
            text=f"Checked: {self.checked} / {self.max_index} — {rate:.1f} checks/s"
        )
        self.progress_label.config(
            text=f"{self.checked} / {self.max_index} ({percent:.4f}%)"
        )

        # update canvas progress bar
        self.canvas.delete("progress_rect")
        w = self.canvas.winfo_width() or 200
        fill_w = int((percent / 100.0) * w)
        if fill_w > 0:
            self.canvas.create_rectangle(
                0, 0, fill_w, 18, fill="green", tags="progress_rect"
            )
        self.canvas.create_rectangle(0, 0, w, 18, outline="black", tags="progress_rect")

        # check termination conditions
        if self.found_password:
            # found: shutdown executor and show results
            try:
                if self.executor:
                    self.executor.shutdown(wait=False)
            except Exception:
                pass
            self._display_found()
            return

        # if no more active futures and we've sent all chunks
        if not self.active_futures and self.next_index >= self.max_index:
            # drain any last progress messages
            if self.progress_queue:
                self._drain_progress_queue()
            self.output_label.config(text="Attack finished. No match found.")
            try:
                if self.executor:
                    self.executor.shutdown(wait=False)
            except Exception:
                pass
            self._finalize()
            return

        # otherwise keep polling
        self.root.after(100, self._poll_loop)

    def _index_to_password(self, index: int) -> str:
        base = len(self.charset)
        chars = []
        for _ in range(self.password_length):
            index, rem = divmod(index, base)
            chars.append(self.charset[rem])
        return "".join(reversed(chars))

    def cancel_attack(self):
        if self.stop_event:
            self.stop_event.set()
        self.output_label.config(text="Attack canceled by user.")
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
        tk.Label(
            self.main_frame, text=f"Index: {self.found_index}", font=("Helvetica", 10)
        ).pack()
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
        # disable controls and leave the status label updated
        try:
            self.cancel_btn.config(state="disabled")
        except Exception:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = BruteForceUI(root)
    root.mainloop()
