# MetaSpy

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import re
import whois
import fitz  
from docx import Document
from PIL import Image
from PIL.ExifTags import TAGS

THEME_BG = "#7f0909"   
THEME_FG = "gold"      

class MetaSpyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MetaSpy — Metadata Extraction Toolkit")
        self.root.geometry("800x600")
        self.root.configure(bg=THEME_BG)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=THEME_BG)
        style.configure("TNotebook.Tab", background=THEME_BG, foreground=THEME_FG, padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", THEME_FG)], foreground=[("selected", THEME_BG)])

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True)

        self.create_image_tab()
        self.create_pdf_tab()
        self.create_docx_tab()
        self.create_url_tab()
        self.create_help_tab()

    def create_image_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="🖼️ Image Metadata")

        tk.Label(tab, text="Select an image file (.jpg/.png)", fg=THEME_FG, bg=THEME_BG, font=("Georgia", 12)).pack(pady=10)
        tk.Button(tab, text="Browse", command=self.extract_image_metadata, bg="gold").pack()

        self.image_text = tk.Text(tab, height=25, width=100)
        self.image_text.pack(pady=10)

    def create_pdf_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="📄 PDF Metadata")

        tk.Label(tab, text="Select a PDF file", fg=THEME_FG, bg=THEME_BG, font=("Georgia", 12)).pack(pady=10)
        tk.Button(tab, text="Browse", command=self.extract_pdf_metadata, bg="gold").pack()

        self.pdf_text = tk.Text(tab, height=25, width=100)
        self.pdf_text.pack(pady=10)

    def create_docx_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="📃 DOCX Metadata")

        tk.Label(tab, text="Select a DOCX file", fg=THEME_FG, bg=THEME_BG, font=("Georgia", 12)).pack(pady=10)
        tk.Button(tab, text="Browse", command=self.extract_docx_metadata, bg="gold").pack()

        self.docx_text = tk.Text(tab, height=25, width=100)
        self.docx_text.pack(pady=10)

    def create_url_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="🌐 URL & WHOIS")

        tk.Label(tab, text="Select any file to scan for URLs/domains", fg=THEME_FG, bg=THEME_BG, font=("Georgia", 12)).pack(pady=10)
        tk.Button(tab, text="Browse", command=self.extract_urls, bg="gold").pack()

        self.url_text = tk.Text(tab, height=15, width=100)
        self.url_text.pack(pady=10)

        tk.Label(tab, text="Optional: Enter a domain or IP for WHOIS lookup", fg=THEME_FG, bg=THEME_BG).pack()
        self.whois_entry = tk.Entry(tab, width=40)
        self.whois_entry.pack(pady=5)
        tk.Button(tab, text="🔍 WHOIS Lookup", command=self.perform_whois_lookup, bg="gold").pack()
        self.whois_text = tk.Text(tab, height=10, width=100)
        self.whois_text.pack(pady=10)

    def create_help_tab(self):
        tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(tab, text="📖 How to Use")

        help_text = """
📚 MetaSpy — Metadata Extraction Toolkit

🖼️ Image Metadata Tab:
- Upload JPG or PNG files
- Extracts EXIF data: Camera, Date, GPS, Software used

📄 PDF Metadata Tab:
- Upload PDF files
- Shows author, creation date, modification, producer, etc.

📃 DOCX Metadata Tab:
- Upload Word .docx files
- Displays author, revision count, timestamps

🌐 URL & WHOIS Tab:
- Extracts any URLs/domains/IPs hidden inside any file
- Optional WHOIS lookup to trace origin


⚠️ All scanning is offline & safe. WHOIS is optional.
        """
        tk.Label(tab, text=help_text, justify="left", wraplength=750, fg=THEME_FG, bg=THEME_BG, font=("Georgia", 11)).pack(padx=10, pady=10)

    def extract_image_metadata(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.jpeg *.png *.tiff")])
        if not path:
            return
        try:
            img = Image.open(path)
            exifdata = img._getexif()
            output = ""
            if exifdata:
                for tag_id, value in exifdata.items():
                    tag = TAGS.get(tag_id, tag_id)
                    output += f"{tag:25}: {value}\n"
            else:
                output = "No EXIF metadata found."
            self.image_text.delete(1.0, tk.END)
            self.image_text.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_pdf_metadata(self):
        path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if not path:
            return
        try:
            doc = fitz.open(path)
            meta = doc.metadata
            output = ""
            for key, value in meta.items():
                output += f"{key:15}: {value}\n"
            self.pdf_text.delete(1.0, tk.END)
            self.pdf_text.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_docx_metadata(self):
        path = filedialog.askopenfilename(filetypes=[("Word Files", "*.docx")])
        if not path:
            return
        try:
            doc = Document(path)
            core_props = doc.core_properties
            output = f"""
Title:         {core_props.title}
Author:        {core_props.author}
Last Modified: {core_props.last_modified_by}
Created:       {core_props.created}
Modified:      {core_props.modified}
Revision:      {core_props.revision}
"""
            self.docx_text.delete(1.0, tk.END)
            self.docx_text.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_urls(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            with open(path, "rb") as f:
                content = f.read().decode(errors="ignore")
            urls = re.findall(r"https?://[^\s'\"]+", content)
            domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", content)
            ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", content)
            combined = set(urls + domains + ips)

            if combined:
                output = "🕵️ Found URLs/Domains/IPs:\n\n" + "\n".join(combined)
            else:
                output = "✅ No URLs or IPs found."
            self.url_text.delete(1.0, tk.END)
            self.url_text.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def perform_whois_lookup(self):
        domain = self.whois_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Needed", "Please enter a domain or IP.")
            return
        try:
            info = whois.whois(domain)
            output = "\n".join(f"{k}: {v}" for k, v in info.items() if v)
            self.whois_text.delete(1.0, tk.END)
            self.whois_text.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("WHOIS Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = MetaSpyApp(root)
    root.mainloop()
