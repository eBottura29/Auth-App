import tkinter as tk
from tkinter import messagebox
from auth import sign_in, load_encrypted_object, USER_FILE
from string import printable
from itertools import product
import threading


class BruteForceUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Brute-Forcer")
        self.root.geometry("400x300")

        self.stop_attack = False
        self.user = None
        self.found_password = None

        self.main_frame = tk.Frame(root)
        self.main_frame.pack(pady=20)

        self.build_ui()

    def build_ui(self):
        # Clear the frame before rebuilding
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        tk.Label(
            self.main_frame,
            text="Brute-Force Attack Tool",
            font=("Helvetica", 14),
        ).pack(pady=10)

        tk.Label(self.main_frame, text="Target Username:").pack()
        self.username_entry = tk.Entry(self.main_frame)
        self.username_entry.pack(pady=5)

        tk.Button(self.main_frame, text="Start Attack", command=self.start_attack).pack(
            pady=10
        )

        self.output_label = tk.Label(self.main_frame, text="Status: Idle")
        self.output_label.pack(pady=10)

    def start_attack(self):
        self.stop_attack = False
        self.output_label.config(text="Brute-force started...")

        # Add cancel button
        self.cancel_button = tk.Button(
            self.main_frame, text="Cancel Attack", command=self.cancel_attack
        )
        self.cancel_button.pack(pady=5)

        # Start brute-force in a background thread
        threading.Thread(target=self.brute_force_worker, daemon=True).start()

    def cancel_attack(self):
        self.stop_attack = True
        self.output_label.config(text="Attack canceled.")

    def brute_force_worker(self):
        username = self.username_entry.get()

        charset = printable[:-6]  # Exclude last 6 whitespace characters
        password_length = 8

        for idx, combination in enumerate(product(charset, repeat=password_length)):
            if self.stop_attack:
                return  # Stop if canceled

            password = "".join(combination)
            self.output_label.config(text=f"Trying: {password} (index {idx})")
            self.root.update_idletasks()

            code = sign_in(username, password)

            if code == 0:
                self.found_password = password
                self.user = load_encrypted_object(USER_FILE)
                self.show_success_ui()
                return

        self.output_label.config(text="Attack finished. No match found.")

    def show_success_ui(self):
        # Clear frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        tk.Label(
            self.main_frame,
            text="Password Found!",
            font=("Helvetica", 14),
            fg="green",
        ).pack(pady=10)

        tk.Label(
            self.main_frame,
            text=f"Password: {self.found_password}",
            font=("Courier", 12),
        ).pack(pady=5)

        tk.Button(
            self.main_frame,
            text="Copy to Clipboard",
            command=lambda: self.copy_to_clipboard(self.found_password),
        ).pack(pady=5)

        tk.Button(self.main_frame, text="Exit", command=self.root.quit).pack(pady=5)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", "Password copied to clipboard!")


if __name__ == "__main__":
    root = tk.Tk()
    app = BruteForceUI(root)
    root.mainloop()
