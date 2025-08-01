import tkinter as tk
from tkinter import messagebox


class BruteForceUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Brute-Forcer")
        self.root.geometry("400x300")

        self.main_frame = tk.Frame(root)
        self.main_frame.pack(pady=20)

        self.build_ui()

    def build_ui(self):
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
        self.output_label.pack(pady=20)

    def start_attack(self):
        # This does nothing — placeholder for future logic
        self.output_label.config(
            text="Simulated brute-force started... (not functional)"
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = BruteForceUI(root)
    root.mainloop()
