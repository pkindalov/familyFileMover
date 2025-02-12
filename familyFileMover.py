import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import json
import shutil
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

SETTINGS_FILE = "settings.json"


def load_settings():
    """Load settings from a JSON file if it exists."""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                settings = json.load(f)
        except json.JSONDecodeError:
            settings = {}
    else:
        settings = {}
    return settings


def save_settings(settings):
    """Save settings to a JSON file."""
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)


class FamilyFileMover(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Family File Mover")
        self.geometry("800x600")

        self.settings = load_settings()

        # --- Source Folder Section (Row 0) ---
        tk.Label(self, text="Source Folder:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.source_entry = tk.Entry(self, width=50)
        self.source_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self, text="Browse", command=self.browse_source).grid(row=0, column=2, padx=10, pady=10)

        # --- Destination Folder Section (Row 1) ---
        tk.Label(self, text="Destination Folder:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.dest_entry = tk.Entry(self, width=50)
        self.dest_entry.grid(row=1, column=1, padx=10, pady=10)
        tk.Button(self, text="Browse", command=self.browse_dest).grid(row=1, column=2, padx=10, pady=10)
        tk.Button(self, text="Select External Device", command=self.select_external_drive) \
            .grid(row=1, column=3, padx=10, pady=10)

        # --- Base Folder Section (Row 2) ---
        tk.Label(self, text="Base Folder (destination subfolder):").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.base_entry = tk.Entry(self, width=50)
        self.base_entry.grid(row=2, column=1, padx=10, pady=10)

        # --- File Types Selection Section (Row 3) ---
        self.file_types_frame = tk.LabelFrame(self, text="Select File Types")
        self.file_types_frame.grid(row=3, column=0, columnspan=4, padx=10, pady=10, sticky="w")

        # Variables for file type checkbuttons
        self.all_files_var = tk.BooleanVar(value=True)
        self.images_var = tk.BooleanVar(value=False)
        self.videos_var = tk.BooleanVar(value=False)
        self.documents_var = tk.BooleanVar(value=False)
        self.music_var = tk.BooleanVar(value=False)

        self.all_files_cb = tk.Checkbutton(self.file_types_frame, text="All Files",
                                           variable=self.all_files_var, command=self.toggle_file_types)
        self.all_files_cb.grid(row=0, column=0, padx=5, pady=5)

        self.images_cb = tk.Checkbutton(self.file_types_frame, text="Images", variable=self.images_var)
        self.images_cb.grid(row=0, column=1, padx=5, pady=5)

        self.videos_cb = tk.Checkbutton(self.file_types_frame, text="Videos", variable=self.videos_var)
        self.videos_cb.grid(row=0, column=2, padx=5, pady=5)

        self.documents_cb = tk.Checkbutton(self.file_types_frame, text="Documents", variable=self.documents_var)
        self.documents_cb.grid(row=0, column=3, padx=5, pady=5)

        self.music_cb = tk.Checkbutton(self.file_types_frame, text="Music", variable=self.music_var)
        self.music_cb.grid(row=0, column=4, padx=5, pady=5)

        # Disable specific options if "All Files" is checked.
        self.toggle_file_types()

        # --- Files List Section (Row 4) ---
        tk.Label(self, text="Files to Move:").grid(row=4, column=0, padx=10, pady=10, sticky="nw")
        self.file_listbox = tk.Listbox(self, width=60, height=10)
        self.file_listbox.grid(row=4, column=1, padx=10, pady=10)
        tk.Button(self, text="Refresh Files", command=self.refresh_file_list) \
            .grid(row=4, column=2, padx=10, pady=10)

        # --- Transfer Button (Row 5) ---
        tk.Button(self, text="Transfer Files", command=self.transfer_files) \
            .grid(row=5, column=1, padx=10, pady=10)

        # --- Progress Bar (Row 6) ---
        self.progress = ttk.Progressbar(self, orient="horizontal", length=300, mode="determinate")
        self.progress.grid(row=6, column=1, padx=10, pady=10)

        self.populate_fields()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def populate_fields(self):
        """Populate fields from saved settings, if available."""
        if "source_folder" in self.settings:
            self.source_entry.insert(0, self.settings["source_folder"])
        if "destination_folder" in self.settings:
            self.dest_entry.insert(0, self.settings["destination_folder"])
        # Use the saved base folder if available; otherwise default to "FamilyMedia"
        if "base_folder" in self.settings and self.settings["base_folder"].strip():
            self.base_entry.insert(0, self.settings["base_folder"])
        else:
            self.base_entry.insert(0, "FamilyMedia")
        if "file_types" in self.settings:
            ft = self.settings["file_types"]
            self.all_files_var.set(ft.get("all", True))
            self.images_var.set(ft.get("images", False))
            self.videos_var.set(ft.get("videos", False))
            self.documents_var.set(ft.get("documents", False))
            self.music_var.set(ft.get("music", False))
            self.toggle_file_types()
        self.refresh_file_list()

    def browse_source(self):
        """Select the source folder."""
        folder = filedialog.askdirectory(title="Select Source Folder")
        if folder:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, folder)
            self.refresh_file_list()

    def browse_dest(self):
        """Select the destination folder."""
        folder = filedialog.askdirectory(title="Select Destination Folder")
        if folder:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, folder)

    def select_external_drive(self):
        """Select an external device (removable drive) as the destination."""
        if psutil is None:
            messagebox.showerror("Error",
                                 "psutil module is required for selecting external devices.\nPlease install it using 'pip install psutil'.")
            return
        drives = self.get_removable_drives()
        if not drives:
            messagebox.showinfo("Info", "No external removable drives found.")
            return
        if len(drives) == 1:
            drive = drives[0]
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, drive)
        else:
            self.choose_drive_dialog(drives)

    def get_removable_drives(self):
        """Return a list of removable drive device names."""
        drives = []
        for partition in psutil.disk_partitions():
            if "removable" in partition.opts.lower():
                drives.append(partition.device)
        return drives

    def choose_drive_dialog(self, drives):
        """Display a dialog to let the user choose from multiple external drives."""
        dialog = tk.Toplevel(self)
        dialog.title("Select External Drive")
        tk.Label(dialog, text="Select an external drive:").pack(padx=10, pady=10)

        listbox = tk.Listbox(dialog, listvariable=tk.StringVar(value=drives), height=len(drives))
        listbox.pack(padx=10, pady=10)
        listbox.select_set(0)

        def on_select():
            selection = listbox.curselection()
            if selection:
                selected_drive = drives[selection[0]]
                self.dest_entry.delete(0, tk.END)
                self.dest_entry.insert(0, selected_drive)
            dialog.destroy()

        tk.Button(dialog, text="Select", command=on_select).pack(padx=10, pady=10)

    def toggle_file_types(self):
        """If 'All Files' is checked, disable other file type checkbuttons; otherwise, enable them."""
        if self.all_files_var.get():
            self.images_cb.config(state="disabled")
            self.videos_cb.config(state="disabled")
            self.documents_cb.config(state="disabled")
            self.music_cb.config(state="disabled")
        else:
            self.images_cb.config(state="normal")
            self.videos_cb.config(state="normal")
            self.documents_cb.config(state="normal")
            self.music_cb.config(state="normal")

    def refresh_file_list(self):
        """Populate the file list from the source directory, filtering by the selected file types."""
        self.file_listbox.delete(0, tk.END)
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
            for file in os.listdir(source_dir):
                if allowed_extensions is not None:
                    _, ext = os.path.splitext(file)
                    if ext.lower() not in allowed_extensions:
                        continue
                self.file_listbox.insert(tk.END, file)
        except Exception as e:
            messagebox.showerror("Error", f"Error reading source directory:\n{e}")

    def get_unique_filename(self, directory, filename):
        """If a file with the given name exists in the directory, append a counter to the base name."""
        base, ext = os.path.splitext(filename)
        candidate = filename
        counter = 2
        while os.path.exists(os.path.join(directory, candidate)):
            candidate = f"{base}({counter}){ext}"
            counter += 1
        return candidate

    def transfer_files(self):
        """
        Transfer files from source to destination.
        For each file, organize it in the base folder under year/month/day folders (based on the file's creation date).
        If creation date is unavailable, the current date is used.
        If a file with the same name exists, a counter is appended.
        """
        source = self.source_entry.get().strip()
        dest = self.dest_entry.get().strip()
        base_folder = self.base_entry.get().strip() or "FamilyMedia"

        if not source or not os.path.isdir(source):
            messagebox.showerror("Error", "Please select a valid source folder.")
            return
        if not dest or not os.path.isdir(dest):
            messagebox.showerror("Error", "Please select a valid destination folder.")
            return

        files = self.file_listbox.get(0, tk.END)
        if not files:
            messagebox.showinfo("Info", "No files to transfer.")
            return

        # Reset progress bar
        self.progress['value'] = 0
        total_files = len(files)

        for i, file in enumerate(files):
            src_path = os.path.join(source, file)

            # Try to get the file's creation date; if unavailable, use the current date.
            try:
                ctime = os.path.getctime(src_path)
                dt = datetime.fromtimestamp(ctime)
            except Exception:
                dt = datetime.now()

            year = dt.strftime("%Y")
            month = dt.strftime("%m")
            day = dt.strftime("%d")

            # Construct the target directory path: destination / base folder / year / month / day
            target_dir = os.path.join(dest, base_folder, year, month, day)
            if not os.path.exists(target_dir):
                try:
                    os.makedirs(target_dir)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to create directory {target_dir}:\n{e}")
                    continue

            # Ensure the file name is unique in the target directory
            new_file = self.get_unique_filename(target_dir, file)
            dest_path = os.path.join(target_dir, new_file)

            try:
                shutil.move(src_path, dest_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to move file '{file}': {e}")
                continue

            # Update progress bar
            self.progress['value'] = ((i + 1) / total_files) * 100
            self.update_idletasks()

        messagebox.showinfo("Info", "File transfer complete!")
        self.refresh_file_list()

    def on_close(self):
        """Save current settings and then close the application."""
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
