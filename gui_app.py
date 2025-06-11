import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinter import Text, Scrollbar, RIGHT, LEFT, Y, END
from scanner import classify_url

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class PhishingScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🔎 Phishing Link Scanner")
        self.geometry("850x620")
        self.resizable(False, False)

        # Entry Label
        self.url_label = ctk.CTkLabel(self, text="Enter URL to scan:", font=ctk.CTkFont(size=14, weight="bold"))
        self.url_label.pack(pady=(20, 0))

        # URL Entry Box
        self.url_entry = ctk.CTkEntry(self, width=600, placeholder_text="https://example.com")
        self.url_entry.pack(pady=10)

        # Buttons
        self.scan_button = ctk.CTkButton(self, text="Scan URL", command=self.scan_url)
        self.scan_button.pack(pady=(5, 10))

        self.scan_file_button = ctk.CTkButton(self, text="Scan from File", command=self.scan_from_file)
        self.scan_file_button.pack(pady=5)

        self.save_button = ctk.CTkButton(self, text="Export Report", command=self.save_report)
        self.save_button.pack(pady=(5, 20))

        # Frame for Scrollable Textbox
        self.text_frame = ctk.CTkFrame(self)
        self.text_frame.pack(pady=10, fill="both", expand=True)

        # Tkinter Text (for tag support)
        self.result_textbox = Text(self.text_frame, wrap="word", bg="#2a2d2e", fg="white", insertbackground="white",
                                   font=("Consolas", 12), height=18, width=100)
        self.result_textbox.pack(side=LEFT, fill="both", expand=True)

        # Scrollbar
        self.scrollbar = Scrollbar(self.text_frame, command=self.result_textbox.yview)
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.result_textbox.config(yscrollcommand=self.scrollbar.set)

        # Configure Tags
        self.result_textbox.tag_configure("green", foreground="#00ff00")
        self.result_textbox.tag_configure("orange", foreground="#ffaa00")
        self.result_textbox.tag_configure("red", foreground="#ff4444")

        # Store results
        self.scan_results = []

    def scan_url(self):
        url = self.url_entry.get().strip()
        if url:
            result = classify_url(url)
            self.scan_results.append(result)
            self.display_result(result)
        else:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")

    def scan_from_file(self):
        file_path = filedialog.askopenfilename(title="Select URL File", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            if not urls:
                messagebox.showwarning("Empty File", "The selected file has no URLs.")
                return
            for url in urls:
                result = classify_url(url)
                self.scan_results.append(result)
                self.display_result(result)
        except Exception as e:
            messagebox.showerror("File Error", f"An error occurred:\n{e}")

    def save_report(self):
        if not self.scan_results:
            messagebox.showinfo("No Results", "No scan results to save.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Report",
                                                 filetypes=[("Text Files", "*.txt")])
        if save_path:
            try:
                with open(save_path, "w") as f:
                    f.write("🔎 PHISHING LINK SCANNER RESULTS\n\n")
                    for result in self.scan_results:
                        f.write(f"{result['original_url']} ➜ {result}\n\n")
                messagebox.showinfo("Success", f"Report saved to {save_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Could not save file:\n{e}")

    def display_result(self, result):
        original = result.get("original_url", "N/A")
        real_url = result.get("unshortened_url", "N/A")
        status = result.get("status", "Unknown")
        score = result.get("score", "N/A")
        vt = result.get("virustotal", "Unknown")
        urlscan = result.get("urlscan", {}).get("status", "Unknown")

        # Decide color tag
        if "Safe" in status:
            tag = "green"
        elif "Suspicious" in status:
            tag = "orange"
        else:
            tag = "red"

        self.result_textbox.insert(END, f"\n[URL] {original}\n")
        self.result_textbox.insert(END, f"[Unshortened] {real_url}\n")
        self.result_textbox.insert(END, f"[Status] {status} | Score: {score}\n", tag)
        self.result_textbox.insert(END, f"[VirusTotal] {vt}\n", tag)
        self.result_textbox.insert(END, f"[URLScan.io] {urlscan}\n", tag)
        self.result_textbox.insert(END, "-" * 60 + "\n")


if __name__ == "__main__":
    app = PhishingScannerApp()
    app.mainloop()
