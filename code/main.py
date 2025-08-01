import tkinter as tk
from tkinter import messagebox
from auth import init_files, sign_in, sign_up, log_out, remove_account
from crypto_utils import generate_key
from storage import load_encrypted_object
import os

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "./db"))

USER_FILE = os.path.join(DB_FOLDER, "user.db")
DATABASE_FILE = os.path.join(DB_FOLDER, "database.db")
KEY_PATH = os.path.join(DB_FOLDER, "secret.key")


class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Login System")
        self.root.geometry("400x300")

        generate_key()
        init_files()
        self.user = load_encrypted_object(USER_FILE)

        self.main_frame = tk.Frame(root)
        self.main_frame.pack(pady=20)

        self.build_main_ui()

    def build_main_ui(self):
        self.clear_frame()

        if not self.user["logged_in"]:
            tk.Label(self.main_frame, text="Username").pack()
            self.username_entry = tk.Entry(self.main_frame)
            self.username_entry.pack()

            tk.Label(self.main_frame, text="Password").pack()
            self.password_entry = tk.Entry(self.main_frame, show="*")
            self.password_entry.pack()

            tk.Label(self.main_frame, text="Password must be 8 characters.").pack()

            tk.Button(
                self.main_frame, text="Sign In", command=self.handle_sign_in
            ).pack(pady=5)
            tk.Button(
                self.main_frame, text="Sign Up", command=self.handle_sign_up
            ).pack(pady=5)
        else:
            tk.Label(
                self.main_frame, text=f"Logged in as: {self.user['username']}"
            ).pack(pady=10)
            tk.Button(
                self.main_frame, text="Log Out", command=self.handle_log_out
            ).pack(pady=5)
            tk.Button(
                self.main_frame,
                text="Remove Account",
                command=self.handle_remove_account,
                fg="red",
            ).pack(pady=5)

    def handle_sign_in(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        code = sign_in(username, password)
        if code == 0:
            self.user = load_encrypted_object(USER_FILE)
            self.build_main_ui()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def handle_sign_up(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        code = sign_up(username, password)

        if code == 0:
            messagebox.showinfo("Success", "Account created. Please sign in.")
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
        elif code == 2:
            messagebox.showwarning(
                "Already Registered", "This username is already taken."
            )
        elif code == 3:
            messagebox.showerror(
                "Invalid Password", "Password must be exactly 8 characters."
            )

    def handle_log_out(self):
        log_out()
        self.user = load_encrypted_object(USER_FILE)
        self.build_main_ui()

    def handle_remove_account(self):
        confirm = messagebox.askyesno(
            "Confirm Deletion", "Are you sure you want to delete your account forever?"
        )
        if confirm:
            code = remove_account()
            if code == 0:
                self.user = load_encrypted_object(USER_FILE)  # Reload session info
                messagebox.showinfo(
                    "Removed", "Your account has been permanently deleted."
                )
                self.build_main_ui()
            else:
                messagebox.showerror("Error", "Failed to remove the account.")

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AuthApp(root)
        root.mainloop()
    except Exception as e:
        print("An unexpected error occurred:", e)
        print("Exit Code: -1")
