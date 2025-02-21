from ttkthemes import ThemedTk
import threading
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinter as tk
import os, sys, json, shutil
from datetime import datetime, timedelta
import zipfile, xml.etree.ElementTree as ET

# Optional libraries
try:
    import pillow_heif

    pillow_heif.register_heif_opener()
except ImportError:
    print("pillow-heif not installed")
try:
    import exifread
except ImportError:
    exifread = None
try:
    from pymediainfo import MediaInfo
except ImportError:
    MediaInfo = None
try:
    from PIL import Image, ExifTags
except ImportError:
    Image = None

SETTINGS_FILE = "settings.json"


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)


# Redirect stderr output to a widget.
class ErrorLogger:
    def __init__(self, widget):
        self.widget = widget

    def write(self, message):
        if message.strip():
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.widget.configure(state="normal")
            self.widget.insert(tk.END, f"[{timestamp}] {message}")
            self.widget.see(tk.END)
            self.widget.configure(state="disabled")

    def flush(self):
        pass


def get_date_taken(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    document_extensions = {".doc", ".docx", ".txt"}
    if ext in document_extensions:
        if ext == ".docx":
            try:
                with zipfile.ZipFile(file_path, "r") as z:
                    core_xml = z.read("docProps/core.xml")
                root = ET.fromstring(core_xml)
                ns = {"dcterms": "http://purl.org/dc/terms/"}
                created_elem = root.find("dcterms:created", ns)
                if created_elem is not None and created_elem.text:
                    date_str = created_elem.text.strip()
                    if date_str.endswith("Z"):
                        date_str = date_str[:-1]
                    try:
                        return datetime.fromisoformat(date_str)
                    except Exception:
                        return datetime.fromisoformat(date_str.rstrip("Z"))
            except Exception as e:
                sys.stderr.write(f"Error extracting docx metadata from '{file_path}': {e}\n")
                return None
        else:
            return None
    video_extensions = {".mov", ".mp4", ".avi", ".mkv", ".wmv"}
    if ext in video_extensions:
        try:
            mod_time = os.path.getmtime(file_path)
            return datetime.fromtimestamp(mod_time)
        except Exception:
            pass
        if MediaInfo is not None:
            try:
                media_info = MediaInfo.parse(file_path)
                for track in media_info.tracks:
                    if track.track_type == "General":
                        date_str = (track.tagged_date or track.encoded_date or
                                    getattr(track, "media_created", None) or getattr(track, "file_created_date", None))
                        if date_str:
                            if date_str.endswith("UTC"):
                                date_str = date_str[:-3].strip()
                            try:
                                return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                            except Exception as e:
                                try:
                                    return datetime.strptime(date_str, "%Y:%m:%d %H:%M:%S")
                                except Exception as e2:
                                    sys.stderr.write(f"Error parsing video date for '{file_path}': {e2}\n")
            except Exception as e:
                sys.stderr.write(f"Error extracting video metadata from '{file_path}': {e}\n")
        return datetime.now()
    if file_path.lower().endswith('.heic'):
        if Image is not None:
            try:
                img = Image.open(file_path)
                if hasattr(img, "getexif"):
                    exif_data = img.getexif()
                    if exif_data:
                        for tag, value in exif_data.items():
                            decoded = ExifTags.TAGS.get(tag, tag)
                            if decoded in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
                                return datetime.strptime(value, "%Y:%m:%d %H:%M:%S")
            except Exception:
                pass
        return None
    if exifread is not None:
        try:
            with open(file_path, "rb") as f:
                try:
                    tags = exifread.process_file(f, stop_tag="EXIF DateTimeOriginal", details=False)
                except Exception as e:
                    sys.stderr.write(f"exifread error for '{file_path}': {e}\n")
                    tags = {}
                date_tag = tags.get("EXIF DateTimeOriginal")
                if date_tag:
                    date_str = str(date_tag)
                    return datetime.strptime(date_str, "%Y:%m:%d %H:%M:%S")
        except Exception as e:
            sys.stderr.write(f"Error reading '{file_path}' with exifread: {e}\n")
    if Image is not None:
        try:
            img = Image.open(file_path)
            exif_data = img.getexif() if hasattr(img, "getexif") else (
                img._getexif() if hasattr(img, "_getexif") else None)
            if exif_data:
                date_str = None
                if isinstance(exif_data, dict):
                    exif = {ExifTags.TAGS.get(tag, tag): value for tag, value in exif_data.items()}
                    date_str = exif.get("DateTimeOriginal") or exif.get("DateTimeDigitized") or exif.get("DateTime")
                else:
                    for tag, value in exif_data.items():
                        decoded = ExifTags.TAGS.get(tag, tag)
                        if decoded in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
                            date_str = value
                            break
                if date_str:
                    return datetime.strptime(date_str, "%Y:%m:%d %H:%M:%S")
        except Exception as e:
            sys.stderr.write(f"Error extracting EXIF with Pillow for '{file_path}': {e}\n")
    return None


# A ScrollableFrame whose inner frame width always matches the container.
class ScrollableFrame(ttk.Frame):
    def __init__(self, parent, height=300, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, height=height)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner_frame = ttk.Frame(self.canvas)
        self.inner_frame_id = self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")
        self.inner_frame.bind("<Configure>", lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.bind("<Configure>", self.on_container_configure)

    def on_container_configure(self, event):
        self.canvas.itemconfig(self.inner_frame_id, width=event.width)


# Custom file copy with per-file progress and cleanup.
def copy_file_with_progress(src, dest, progress_callback, chunk_size=1024 * 1024):
    total_size = os.path.getsize(src)
    copied = 0
    try:
        with open(src, "rb") as fsrc, open(dest, "wb") as fdst:
            while True:
                chunk = fsrc.read(chunk_size)
                if not chunk:
                    break
                fdst.write(chunk)
                copied += len(chunk)
                progress_callback(copied / total_size * 100)
    except Exception as e:
        if os.path.exists(dest):
            os.remove(dest)
        raise e
    os.remove(src)


class FamilyFileMover(ThemedTk):
    def __init__(self):
        super().__init__(theme="arc")
        self.title("Family File Mover")
        self.geometry("600x700")
        self.resizable(False, False)

        # Initialize variables.
        self.settings = load_settings()
        self.file_check_vars = {}
        self.select_all_var = tk.BooleanVar(value=False)
        self.cancel_transfer = False  # For cancelling transfers

        self.style = ttk.Style(self)
        self.style.configure("TLabelFrame", font=("Segoe UI", 11, "bold"), padding=10)
        self.style.configure("TButton", font=("Segoe UI", 10), padding=5)
        self.style.configure("TLabel", font=("Segoe UI", 10))

        # Create Notebook with Main and Logs tabs.
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.main_tab = ttk.Frame(self.notebook)
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Main")
        self.notebook.add(self.log_tab, text="Logs")

        self.setup_main_tab()
        self.setup_log_tab()

        self.populate_fields()
        self.refresh_file_list()
        sys.stderr = ErrorLogger(self.error_log)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_main_tab(self):
        # Folder Settings
        self.folder_frame = ttk.LabelFrame(self.main_tab, text="Folder Settings")
        self.folder_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
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

        # File Type Selection
        self.file_types_frame = ttk.LabelFrame(self.main_tab, text="File Type Selection")
        self.file_types_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        self.all_files_var = tk.BooleanVar(value=True)
        self.images_var = tk.BooleanVar(value=False)
        self.videos_var = tk.BooleanVar(value=False)
        self.documents_var = tk.BooleanVar(value=False)
        self.music_var = tk.BooleanVar(value=False)
        self.all_files_cb = ttk.Checkbutton(self.file_types_frame, text="All Files", variable=self.all_files_var,
                                            command=self.toggle_file_types)
        self.all_files_cb.grid(row=0, column=0, padx=5, pady=5)
        self.images_cb = ttk.Checkbutton(self.file_types_frame, text="Images", variable=self.images_var,
                                         command=self.refresh_file_list)
        self.images_cb.grid(row=0, column=1, padx=5, pady=5)
        self.videos_cb = ttk.Checkbutton(self.file_types_frame, text="Videos", variable=self.videos_var,
                                         command=self.refresh_file_list)
        self.videos_cb.grid(row=0, column=2, padx=5, pady=5)
        self.documents_cb = ttk.Checkbutton(self.file_types_frame, text="Documents", variable=self.documents_var,
                                            command=self.refresh_file_list)
        self.documents_cb.grid(row=0, column=3, padx=5, pady=5)
        self.music_cb = ttk.Checkbutton(self.file_types_frame, text="Music", variable=self.music_var,
                                        command=self.refresh_file_list)
        self.music_cb.grid(row=0, column=4, padx=5, pady=5)

        # Conversion Settings
        self.conversion_frame = ttk.LabelFrame(self.main_tab, text="Conversion Settings")
        self.conversion_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        ttk.Label(self.conversion_frame, text="Convert Input Format:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.convert_input = tk.StringVar(value="None")
        self.input_combo = ttk.Combobox(self.conversion_frame, textvariable=self.convert_input, state="readonly",
                                        values=["None", "heic", "jpg", "png", "gif", "bmp"])
        self.input_combo.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(self.conversion_frame, text="To Output Format:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.convert_output = tk.StringVar(value="None")
        self.output_combo = ttk.Combobox(self.conversion_frame, textvariable=self.convert_output, state="readonly",
                                         values=["None", "jpg", "png", "gif", "bmp"])
        self.output_combo.grid(row=0, column=3, padx=5, pady=5)
        ttk.Label(self.conversion_frame, text="JPEG Quality:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.jpeg_quality = tk.IntVar(value=85)
        self.jpeg_quality_spinbox = tk.Spinbox(self.conversion_frame, from_=10, to=100, increment=5,
                                               textvariable=self.jpeg_quality, width=5)
        self.jpeg_quality_spinbox.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.convert_button = ttk.Button(self.conversion_frame, text="Convert", command=self.convert_files)
        self.convert_button.grid(row=1, column=3, padx=5, pady=5)

        # File List Selection with Search and "Select Next" feature.
        self.file_list_frame = ttk.LabelFrame(self.main_tab, text="Select Files to Move")
        self.file_list_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        self.file_list_frame.columnconfigure(0, weight=1)
        # Search area.
        search_frame = ttk.Frame(self.file_list_frame)
        search_frame.grid(row=0, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=5, pady=5)
        self.search_entry = ttk.Entry(search_frame, width=20)
        self.search_entry.grid(row=0, column=1, padx=5, pady=5)
        self.search_button = ttk.Button(search_frame, text="Search", command=self.refresh_file_list)
        self.search_button.grid(row=0, column=2, padx=5, pady=5)
        self.clear_search_button = ttk.Button(search_frame, text="Clear", command=self.clear_search)
        self.clear_search_button.grid(row=0, column=3, padx=5, pady=5)

        # Selection row.
        self.select_all_cb = ttk.Checkbutton(self.file_list_frame, text="Select All", variable=self.select_all_var,
                                             command=self.toggle_select_all)
        self.select_all_cb.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.selection_count_label = ttk.Label(self.file_list_frame, text="Selected: 0 / 0")
        self.selection_count_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.select_next_entry = ttk.Entry(self.file_list_frame, width=5)
        self.select_next_entry.grid(row=1, column=2, sticky="w", padx=5, pady=5)
        self.select_next_button = ttk.Button(self.file_list_frame, text="Select Next", command=self.select_next_files)
        self.select_next_button.grid(row=1, column=3, sticky="w", padx=5, pady=5)

        self.scrollable_file_frame = ScrollableFrame(self.file_list_frame, height=300)
        self.scrollable_file_frame.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
        self.refresh_button = ttk.Button(self.file_list_frame, text="Refresh File List", command=self.refresh_file_list)
        self.refresh_button.grid(row=3, column=0, columnspan=4, sticky="e", padx=5, pady=5)

        # Operations area: overall progress, current file progress, estimated time.
        self.operations_frame = ttk.Frame(self.main_tab)
        self.operations_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=5)
        self.operations_frame.columnconfigure(0, weight=1)
        self.transfer_button = ttk.Button(self.operations_frame, text="Transfer Files", command=self.start_transfer)
        self.transfer_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.cancel_button = ttk.Button(self.operations_frame, text="Cancel Transfer",
                                        command=self.cancel_transfer_func)
        self.cancel_button.grid(row=0, column=1, padx=5, pady=5, sticky="e")
        self.cancel_button.config(state="disabled")
        self.current_file_label = ttk.Label(self.operations_frame, text="Current file: None")
        self.current_file_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.current_progress = ttk.Progressbar(self.operations_frame, orient="horizontal", mode="determinate")
        self.current_progress.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.progress = ttk.Progressbar(self.operations_frame, orient="horizontal", mode="determinate")
        self.progress.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        self.progress_label = ttk.Label(self.operations_frame, text="0%")
        self.progress_label.grid(row=2, column=2, padx=5, pady=5, sticky="e")
        self.estimated_label = ttk.Label(self.operations_frame, text="Estimated time remaining: --:--:--")
        self.estimated_label.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        self.main_tab.rowconfigure(3, weight=1)

    def setup_log_tab(self):
        self.error_log = scrolledtext.ScrolledText(self.log_tab, height=20, state="disabled", wrap="word")
        self.error_log.pack(fill="both", expand=True, padx=10, pady=10)
        self.clear_log_button = ttk.Button(self.log_tab, text="Clear Log",
                                           command=lambda: (self.error_log.configure(state="normal"),
                                                            self.error_log.delete("1.0", tk.END),
                                                            self.error_log.configure(state="disabled")))
        self.clear_log_button.pack(pady=5)

    def clear_search(self):
        self.search_entry.delete(0, tk.END)
        self.refresh_file_list()

    def update_selection_count(self):
        total = len(self.file_check_vars)
        selected = sum(var.get() for var in self.file_check_vars.values())
        self.selection_count_label.config(text=f"Selected: {selected} / {total}")

    def log_error(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.error_log.configure(state="normal")
        self.error_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.error_log.see(tk.END)
        self.error_log.configure(state="disabled")

    def show_and_log_error(self, title, message):
        messagebox.showerror(title, message)
        self.log_error(message)

    def populate_fields(self):
        settings = load_settings()
        if "source_folder" in settings:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, settings["source_folder"])
        if "destination_folder" in settings:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, settings["destination_folder"])
        if "base_folder" in settings and settings["base_folder"].strip():
            self.base_entry.delete(0, tk.END)
            self.base_entry.insert(0, settings["base_folder"])
        else:
            self.base_entry.delete(0, tk.END)
            self.base_entry.insert(0, "FamilyMedia")
        if "file_types" in settings:
            ft = settings["file_types"]
            self.all_files_var.set(ft.get("all", True))
            self.images_var.set(ft.get("images", False))
            self.videos_var.set(ft.get("videos", False))
            self.documents_var.set(ft.get("documents", False))
            self.music_var.set(ft.get("music", False))

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
        self.refresh_file_list()

    def toggle_select_all(self):
        new_value = self.select_all_var.get()
        for var in self.file_check_vars.values():
            var.set(new_value)
        self.update_selection_count()

    def refresh_file_list(self):
        for widget in self.scrollable_file_frame.inner_frame.winfo_children():
            widget.destroy()
        self.file_check_vars = {}
        source_dir = self.source_entry.get().strip()
        if not source_dir or not os.path.isdir(source_dir):
            self.update_selection_count()
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
        search_term = self.search_entry.get().strip().lower() if hasattr(self, "search_entry") else ""
        try:
            for file in os.listdir(source_dir):
                if allowed_extensions is not None:
                    _, ext = os.path.splitext(file)
                    if ext.lower() not in allowed_extensions:
                        continue
                if search_term and search_term not in file.lower():
                    continue
                var = tk.BooleanVar(value=self.select_all_var.get())
                var.trace_add("write", lambda *args: self.update_selection_count())
                chk = ttk.Checkbutton(self.scrollable_file_frame.inner_frame, text=file, variable=var)
                chk.pack(anchor="w", padx=5, pady=2)
                self.file_check_vars[file] = var
            self.update_selection_count()
            self.scrollable_file_frame.canvas.yview_moveto(0)
        except Exception as e:
            self.show_and_log_error("Error", f"Error reading source directory:\n{e}")
            self.update_selection_count()

    def get_unique_filename(self, directory, filename):
        base, ext = os.path.splitext(filename)
        candidate = filename
        counter = 2
        while os.path.exists(os.path.join(directory, candidate)):
            candidate = f"{base}({counter}){ext}"
            counter += 1
        return candidate

    # --- Method to automatically select next N unselected files ---
    def select_next_files(self):
        try:
            n = int(self.select_next_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")
            return
        count = 0
        for file, var in self.file_check_vars.items():
            if not var.get():
                var.set(True)
                count += 1
                if count >= n:
                    break
        self.update_selection_count()

    # --- Custom file copy with per-file progress and cleanup ---
    def copy_file_with_progress(self, src, dest, progress_callback, chunk_size=1024 * 1024):
        total_size = os.path.getsize(src)
        copied = 0
        try:
            with open(src, "rb") as fsrc, open(dest, "wb") as fdst:
                while True:
                    chunk = fsrc.read(chunk_size)
                    if not chunk:
                        break
                    fdst.write(chunk)
                    copied += len(chunk)
                    progress_callback(copied / total_size * 100)
        except Exception as e:
            if os.path.exists(dest):
                os.remove(dest)
            raise e
        os.remove(src)

    # --- Threaded transfer with cancellation, estimated time, and individual file progress ---
    def start_transfer(self):
        selected_files = [f for f, var in self.file_check_vars.items() if var.get()]
        if not selected_files:
            messagebox.showinfo("No Files Selected", "Please select at least one file to transfer.")
            return
        self.cancel_transfer = False
        self.transfer_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.transfer_start_time = datetime.now()
        threading.Thread(target=self.transfer_files_thread, daemon=True).start()

    def transfer_files_thread(self):
        source = self.source_entry.get().strip()
        dest = self.dest_entry.get().strip()
        base_folder = self.base_entry.get().strip() or "FamilyMedia"
        selected_files = [f for f, var in self.file_check_vars.items() if var.get()]
        total_files = len(selected_files)
        for i, file in enumerate(selected_files):
            if self.cancel_transfer:
                self.after(0, lambda: self.progress.config(value=0))
                self.after(0, lambda: self.progress_label.config(text="0%"))
                self.after(0, lambda: self.estimated_label.config(text="Estimated time remaining: --:--:--"))
                self.after(0, lambda: self.current_progress.config(value=0))
                # Do not reset current_file_label so that the failed file is still shown.
                self.after(0, lambda: messagebox.showinfo("Cancelled", "Transfer cancelled by user."))
                break
            self.after(0, lambda f=file: self.current_file_label.config(text=f"Current file: {f}"))
            src_path = os.path.join(source, file)
            # Check free space before copying.
            file_size = os.path.getsize(src_path)
            if shutil.disk_usage(dest).free < file_size:
                self.after(0,
                           lambda f=file: self.log_error(f"Insufficient disk space for file '{f}'. Transfer aborted."))
                self.after(0, lambda f=file: messagebox.showerror("Error",
                                                                  f"Insufficient disk space while transferring '{f}'. Transfer aborted."))
                break
            dt = get_date_taken(src_path)
            if dt is None:
                try:
                    dt = datetime.fromtimestamp(os.path.getmtime(src_path))
                except Exception:
                    dt = datetime.now()
            year, month, day = dt.strftime("%Y"), dt.strftime("%B"), dt.strftime("%d")
            target_dir = os.path.join(dest, base_folder, year, month, day)
            if not os.path.exists(target_dir):
                try:
                    os.makedirs(target_dir)
                except Exception as e:
                    self.after(0, lambda e=e, f=file: self.show_and_log_error("Error",
                                                                              f"Failed to create directory {target_dir} for '{f}':\n{e}"))
                    continue
            new_file = self.get_unique_filename(target_dir, file)
            dest_path = os.path.join(target_dir, new_file)
            self.after(0, lambda: self.current_progress.config(value=0))
            try:
                self.copy_file_with_progress(src_path, dest_path,
                                             lambda percent: self.current_progress.config(value=percent))
            except Exception as e:
                self.after(0, lambda e=e, f=file: self.show_and_log_error("Error", f"Failed to move '{f}': {e}"))
                continue
            progress_value = ((i + 1) / total_files) * 100
            self.after(0, lambda value=progress_value: self.progress.config(value=value))
            self.after(0, lambda value=progress_value: self.progress_label.config(text=f"{int(value)}%"))
            elapsed = datetime.now() - self.transfer_start_time
            avg = elapsed / (i + 1)
            remaining = avg * (total_files - (i + 1))
            remaining_str = str(remaining).split('.')[0]
            self.after(0, lambda rs=remaining_str: self.estimated_label.config(text=f"Estimated time remaining: {rs}"))
            self.after(0, self.update_idletasks)
        self.after(0, lambda: self.transfer_button.config(state="normal"))
        self.after(0, lambda: self.cancel_button.config(state="disabled"))
        self.after(0, lambda: self.progress.config(value=0))
        self.after(0, lambda: self.progress_label.config(text="0%"))
        self.after(0, lambda: self.estimated_label.config(text="Estimated time remaining: --:--:--"))
        self.after(0, lambda: self.current_file_label.config(text="Current file: None"))
        self.after(0, self.refresh_file_list)
        self.after(0, lambda: self.scrollable_file_frame.canvas.yview_moveto(0))

    def cancel_transfer_func(self):
        response = messagebox.askyesno("Cancel Transfer", "Are you sure you want to stop transferring?")
        if response:
            self.cancel_transfer = True
        self.refresh_file_list()

    def transfer_files(self):
        pass  # Not used; start_transfer() is used.

    def convert_files(self):
        self.error_log.configure(state="normal")
        self.error_log.delete("1.0", tk.END)
        self.error_log.configure(state="disabled")
        conv_in = self.convert_input.get().lower()
        conv_out = self.convert_output.get().lower()
        if conv_in == "none" or conv_out == "none":
            messagebox.showinfo("Conversion", "Conversion not enabled. Please select both input and output formats.")
            return
        source = self.source_entry.get().strip()
        if not source or not os.path.isdir(source):
            self.show_and_log_error("Error", "Please select a valid source folder.")
            return
        selected_files = [f for f, var in self.file_check_vars.items() if var.get()]
        if not selected_files:
            messagebox.showinfo("Info", "No files selected for conversion.")
            return
        total_files = len(selected_files)
        self.progress['value'] = 0
        for i, file in enumerate(selected_files):
            src_path = os.path.join(source, file)
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext == "." + conv_in:
                try:
                    im = Image.open(src_path)
                    format_mapping = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG", "gif": "GIF", "bmp": "BMP"}
                    out_format = format_mapping.get(conv_out, conv_out.upper())
                    new_file = os.path.splitext(file)[0] + "." + conv_out
                    target_dir = os.path.dirname(src_path)
                    dest_path = os.path.join(target_dir, new_file)
                    if out_format in ("JPEG", "JPG"):
                        im.convert("RGB").save(dest_path, out_format, quality=self.jpeg_quality.get())
                    else:
                        im.save(dest_path, out_format)
                except Exception as e:
                    self.show_and_log_error("Error", f"Failed to convert '{file}': {e}")
            progress_value = ((i + 1) / total_files) * 100
            self.progress['value'] = progress_value
            self.progress_label.config(text=f"{int(progress_value)}%")
            self.update_idletasks()
        messagebox.showinfo("Info", "Conversion complete!")
        self.progress['value'] = 0
        self.progress_label.config(text="0%")
        self.refresh_file_list()
        self.convert_input.set("None")
        self.convert_output.set("None")
        self.jpeg_quality.set(85)

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
