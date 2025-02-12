import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import json
import shutil
from datetime import datetime

SETTINGS_FILE = "settings.json"


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    else:
        return {}


def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)


class ScrollableFrame(ttk.Frame):
    """A scrollable frame that holds widgets inside a fixed-height canvas."""

    def __init__(self, container, height=300, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, height=height, borderwidth=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.inner_frame = ttk.Frame(self.canvas)
        self.inner_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)


class FamilyFileMover(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Family File Mover")
        self.geometry("900x750")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.settings = load_settings()
        self.file_check_vars = {}  # Dictionary to hold each file's BooleanVar
        self.select_all_var = tk.BooleanVar(value=False)

        # Main container with grid layout
        self.container = ttk.Frame(self, padding="10")
        self.container.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # ---------------- Folder Settings Frame ----------------
        self.folder_frame = ttk.LabelFrame(self.container, text="Folder Settings", padding="10")
        self.folder_frame.grid(row=0, column=0, sticky="ew", pady=5)
        self.folder_frame.columnconfigure(1, weight=1)

        ttk.Label(self.folder_frame, text="Source Folder:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.source_entry = ttk.Entry(self.folder_frame, width=50)
        self.source_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(self.folder_frame, text="Browse", command=self.browse_source).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(self.folder_frame, text="Destination Folder:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.dest_entry = ttk.Entry(self.folder_frame, width=50)
        self.dest_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(self.folder_frame, text="Browse", command=self.browse_dest).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(self.folder_frame, text="Base Folder (subfolder):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.base_entry = ttk.Entry(self.folder_frame, width=50)
        self.base_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        # ---------------- File Type Selection Frame ----------------
        self.file_types_frame = ttk.LabelFrame(self.container, text="File Type Selection", padding="10")
        self.file_types_frame.grid(row=1, column=0, sticky="ew", pady=5)
        self.file_types_frame.columnconfigure(0, weight=1)

        self.all_files_var = tk.BooleanVar(value=True)
        self.images_var = tk.BooleanVar(value=False)
        self.videos_var = tk.BooleanVar(value=False)
        self.documents_var = tk.BooleanVar(value=False)
        self.music_var = tk.BooleanVar(value=False)

        self.all_files_cb = ttk.Checkbutton(self.file_types_frame, text="All Files",
                                            variable=self.all_files_var, command=self.toggle_file_types)
        self.all_files_cb.grid(row=0, column=0, padx=5, pady=5)
        self.images_cb = ttk.Checkbutton(self.file_types_frame, text="Images",
                                         variable=self.images_var, command=self.refresh_file_list)
        self.images_cb.grid(row=0, column=1, padx=5, pady=5)
        self.videos_cb = ttk.Checkbutton(self.file_types_frame, text="Videos",
                                         variable=self.videos_var, command=self.refresh_file_list)
        self.videos_cb.grid(row=0, column=2, padx=5, pady=5)
        self.documents_cb = ttk.Checkbutton(self.file_types_frame, text="Documents",
                                            variable=self.documents_var, command=self.refresh_file_list)
        self.documents_cb.grid(row=0, column=3, padx=5, pady=5)
        self.music_cb = ttk.Checkbutton(self.file_types_frame, text="Music",
                                        variable=self.music_var, command=self.refresh_file_list)
        self.music_cb.grid(row=0, column=4, padx=5, pady=5)
        self.toggle_file_types()  # This refreshes the list if needed

        # ---------------- File List Selection Frame ----------------
        self.file_list_frame = ttk.LabelFrame(self.container, text="Select Files to Move", padding="10")
        self.file_list_frame.grid(row=2, column=0, sticky="nsew", pady=5)
        self.container.rowconfigure(2, weight=1)

        self.select_all_cb = ttk.Checkbutton(self.file_list_frame, text="Select All",
                                             variable=self.select_all_var, command=self.toggle_select_all)
        self.select_all_cb.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.scrollable_file_frame = ScrollableFrame(self.file_list_frame, height=300)
        self.scrollable_file_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.file_list_frame.rowconfigure(1, weight=1)
        self.file_list_frame.columnconfigure(0, weight=1)

        self.refresh_button = ttk.Button(self.file_list_frame, text="Refresh File List", command=self.refresh_file_list)
        self.refresh_button.grid(row=2, column=0, sticky="e", padx=5, pady=5)

        # ---------------- Transfer Controls Frame ----------------
        self.transfer_frame = ttk.Frame(self.container, padding="10")
        self.transfer_frame.grid(row=3, column=0, sticky="ew", pady=5)
        self.transfer_frame.columnconfigure(1, weight=1)

        self.transfer_button = ttk.Button(self.transfer_frame, text="Transfer Files", command=self.transfer_files)
        self.transfer_button.grid(row=0, column=0, padx=5, pady=5)
        self.progress = ttk.Progressbar(self.transfer_frame, orient="horizontal", mode="determinate", length=300)
        self.progress.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.populate_fields()
        self.refresh_file_list()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def populate_fields(self):
        if "source_folder" in self.settings:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, self.settings["source_folder"])
        if "destination_folder" in self.settings:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, self.settings["destination_folder"])
        if "base_folder" in self.settings and self.settings["base_folder"].strip():
            self.base_entry.delete(0, tk.END)
            self.base_entry.insert(0, self.settings["base_folder"])
        else:
            self.base_entry.delete(0, tk.END)
            self.base_entry.insert(0, "FamilyMedia")
        if "file_types" in self.settings:
            ft = self.settings["file_types"]
            self.all_files_var.set(ft.get("all", True))
            self.images_var.set(ft.get("images", False))
            self.videos_var.set(ft.get("videos", False))
            self.documents_var.set(ft.get("documents", False))
            self.music_var.set(ft.get("music", False))
            self.toggle_file_types()

    def browse_source(self):
        folder = filedialog.askdirectory(title="Select Source Folder")
        if folder:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, folder)
            self.refresh_file_list()

    def browse_dest(self):
        folder = filedialog.askdirectory(title="Select Destination Folder")
        if folder:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, folder)

    def toggle_file_types(self):
        if self.all_files_var.get():
            self.images_cb.state(["disabled"])
            self.videos_cb.state(["disabled"])
            self.documents_cb.state(["disabled"])
            self.music_cb.state(["disabled"])
        else:
            self.images_cb.state(["!disabled"])
            self.videos_cb.state(["!disabled"])
            self.documents_cb.state(["!disabled"])
            self.music_cb.state(["!disabled"])
        if hasattr(self, "scrollable_file_frame"):
            self.refresh_file_list()

    def toggle_select_all(self):
        new_value = self.select_all_var.get()
        for var in self.file_check_vars.values():
            var.set(new_value)

    def refresh_file_list(self):
        for widget in self.scrollable_file_frame.inner_frame.winfo_children():
            widget.destroy()
        self.file_check_vars = {}
        source_dir = self.source_entry.get().strip()
        if not source_dir or not os.path.isdir(source_dir):
            return
        allowed_extensions = None
        if not self.all_files_var.get():
            allowed_extensions = []
            if self.images_var.get():
                allowed_extensions.extend([".jpg", ".jpeg", ".png", ".gif", ".bmp"])
            if self.videos_var.get():
                allowed_extensions.extend([".mp4", ".avi", ".mkv", ".mov"])
            if self.documents_var.get():
                allowed_extensions.extend([".pdf", ".doc", ".docx", ".txt"])
            if self.music_var.get():
                allowed_extensions.extend([".mp3", ".wav", ".flac"])
            allowed_extensions = list(set(allowed_extensions))
        try:
            files = os.listdir(source_dir)
            for file in files:
                if allowed_extensions is not None:
                    _, ext = os.path.splitext(file)
                    if ext.lower() not in allowed_extensions:
                        continue
                # Create the checkbox variable with initial value matching "Select All"
                var = tk.BooleanVar(value=self.select_all_var.get())
                chk = ttk.Checkbutton(self.scrollable_file_frame.inner_frame, text=file, variable=var)
                chk.pack(anchor="w", padx=5, pady=2)
                self.file_check_vars[file] = var
        except Exception as e:
            messagebox.showerror("Error", f"Error reading source directory:\n{e}")

    def get_unique_filename(self, directory, filename):
        base, ext = os.path.splitext(filename)
        candidate = filename
        counter = 2
        while os.path.exists(os.path.join(directory, candidate)):
            candidate = f"{base}({counter}){ext}"
            counter += 1
        return candidate

    def transfer_files(self):
        source = self.source_entry.get().strip()
        dest = self.dest_entry.get().strip()
        base_folder = self.base_entry.get().strip() or "FamilyMedia"
        if not source or not os.path.isdir(source):
            messagebox.showerror("Error", "Please select a valid source folder.")
            return
        if not dest or not os.path.isdir(dest):
            messagebox.showerror("Error", "Please select a valid destination folder.")
            return
        selected_files = [file for file, var in self.file_check_vars.items() if var.get()]
        if not selected_files:
            messagebox.showinfo("Info", "No files selected for transfer.")
            return
        total_files = len(selected_files)
        self.progress['value'] = 0
        for i, file in enumerate(selected_files):
            src_path = os.path.join(source, file)
            try:
                ctime = os.path.getctime(src_path)
                dt = datetime.fromtimestamp(ctime)
            except Exception:
                dt = datetime.now()
            year = dt.strftime("%Y")
            month = dt.strftime("%m")
            day = dt.strftime("%d")
            target_dir = os.path.join(dest, base_folder, year, month, day)
            if not os.path.exists(target_dir):
                try:
                    os.makedirs(target_dir)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to create directory {target_dir}:\n{e}")
                    continue
            new_file = self.get_unique_filename(target_dir, file)
            dest_path = os.path.join(target_dir, new_file)
            try:
                shutil.move(src_path, dest_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to move file '{file}': {e}")
                continue
            self.progress['value'] = ((i + 1) / total_files) * 100
            self.update_idletasks()
        messagebox.showinfo("Info", "File transfer complete!")
        self.progress['value'] = 0
        self.refresh_file_list()

    def on_close(self):
        self.settings["source_folder"] = self.source_entry.get().strip()
        self.settings["destination_folder"] = self.dest_entry.get().strip()
        self.settings["base_folder"] = self.base_entry.get().strip() or "FamilyMedia"
        self.settings["file_types"] = {
            "all": self.all_files_var.get(),
            "images": self.images_var.get(),
            "videos": self.videos_var.get(),
            "documents": self.documents_var.get(),
            "music": self.music_var.get()
        }
        save_settings(self.settings)
        self.destroy()


if __name__ == "__main__":
    app = FamilyFileMover()
    app.mainloop()
