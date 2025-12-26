import os
import socket
import struct
import tempfile
import threading
import time
import zlib
import tkinter
from tkinter import filedialog, messagebox
import customtkinter as ctk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =========================================================================
# KONSTANTA GLOBAL
# =========================================================================

DEFAULT_PORT = 5000
SOCKET_TIMEOUT = 120
CHUNK = 64 * 1024

TYPE_KEY = b'K'
TYPE_META = b'M'
TYPE_ACK = b'A'
TYPE_END = b'E'

IP_PLACEHOLDER = "Masukkan IP Address Penerima "
DEFAULT_IP = "127.0.0.1"

SUCCESS_COLOR = "#4CAF50"
FAIL_COLOR = "#F44336"
DEFAULT_PROGRESS_COLOR = "#3b8ed0"
ctk.set_appearance_mode("system")
ctk.set_default_color_theme("blue")

# --- BATAS MAKSIMUM UKURAN FILE (3 GB) ---
# Batas ini hanya akan digunakan jika security_level_bits == 256
MAX_FILE_SIZE_GB = 3
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_GB * 1024 * 1024 * 1024

SECURITY_LEVELS = {
    "Level 1 (128-bit)": 128, # 16 bytes
    "Level 2 (192-bit)": 192, # 24 bytes
    "Level 3 (256-bit)": 256, # 32 bytes (LEVEL YANG DIBATASI UKURAN)
}
DEFAULT_SECURITY_LEVEL = "Level 1 (128-bit)"

# =========================================================================
# CUSTOM WIDGETS & HELPER FUNCTIONS
# =========================================================================

class MyProgressBar(ctk.CTkProgressBar):
    def _get_widget_color(self, name):
        current_mode = ctk.get_appearance_mode().lower()
        
        TEXT_COLOR = 'white' if current_mode == 'dark' else 'black'
        
        if name == 'text_gray':
            return TEXT_COLOR if current_mode == 'dark' else '#333333'
        if name == 'text':
            return TEXT_COLOR
        return "white"

    def __init__(self, master=None, **kwargs):
        self._variable = ctk.DoubleVar(value=0)
        kwargs['variable'] = self._variable
        if 'variable' in kwargs:
            del kwargs['variable']
        super().__init__(master, **kwargs)
        # Menghindari crash jika canvas belum siap
        if self._canvas:
            self._canvas.create_text(0, 0, text="0.00%",
                                      fill="white",
                                      font=('Arial', 10, 'bold'), anchor="c", tags="progress_text")
        self.set_value_and_text(0, "0.00%", running=False, success=False)

    def _update_dimensions_event(self, event):
        super()._update_dimensions_event(event)
        if self._canvas:
            self._canvas.coords("progress_text", event.width/2, event.height/2)
            new_font_size = max(8, int(event.height * 0.5))
            self._canvas.itemconfigure("progress_text", font=('Arial', new_font_size, 'bold'))

    def set_value_and_text(self, percent: float, text: str, running: bool, success: bool):
        value_float = percent / 100.0
        super().set(value_float)

        if self._canvas:
            if success and not running and percent == 100:
                self.configure(progress_color=SUCCESS_COLOR)
                self._canvas.itemconfigure("progress_text", fill="white")
            elif not running and percent == 0:
                if "GAGAL" in text or "ERROR" in text:
                    self.configure(progress_color=FAIL_COLOR)
                    self._canvas.itemconfigure("progress_text", fill="white")
                else:
                    self.configure(progress_color=self._fg_color)
                    self._canvas.itemconfigure("progress_text", fill=self._get_widget_color('text_gray'))
            elif running:
                self.configure(progress_color=DEFAULT_PROGRESS_COLOR)
                if value_float < 0.15:
                    self._canvas.itemconfigure("progress_text", fill=self._get_widget_color('text'))
                else:
                    self._canvas.itemconfigure("progress_text", fill="white")

            self._canvas.itemconfigure("progress_text", text=text)

def send_frame(sock, t: bytes, payload: bytes):
    if not isinstance(t, (bytes, bytearray)) or len(t) != 1:
        raise ValueError("type must be single byte")
    # Header 5 byte: 1 byte Type + 4 byte Length (<I, little-endian)
    header = t + struct.pack('<I', len(payload))
    sock.sendall(header + payload)

def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("socket closed while reading")
        data.extend(part)
    return bytes(data)

def recv_frame_header(sock):
    # Header 5 byte: 1 byte Type + 4 byte Length (<I, little-endian)
    hdr = recv_exact(sock, 5)
    return hdr[0:1], struct.unpack('<I', hdr[1:5])[0]

def build_metadata_bytes(filename: str, orig_size: int, enc_size: int, crc32: int, nonce: bytes):
    # Format metadata: [H:FName_Len] [FName] [Q:OrigSize] [Q:EncSize] [I:CRC32] [B:NonceLen] [Nonce (12)]
    
    fname_b = filename.encode('utf-8')
    fname_len = len(fname_b)
    meta = struct.pack('<H', fname_len) + fname_b
    meta += struct.pack('<Q', orig_size) # 8 bytes for original size
    meta += struct.pack('<Q', enc_size)  # 8 bytes for encrypted size
    meta += struct.pack('<I', crc32 & 0xffffffff)
    meta += struct.pack('<B', len(nonce)) + nonce
    return meta

def encrypt_file_to_temp_gcm(in_path: str, key: bytes, key_bits: int, chunk_size=CHUNK):
    orig_size = os.path.getsize(in_path)
    
    # --- BLOK PENGECEKAN UKURAN FILE ---
    if key_bits == 256 and orig_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File terlalu besar ({orig_size / (1024**3):.2f} GB). "
            f"Level Keamanan 3 (256-bit) dibatasi maksimum {MAX_FILE_SIZE_GB} GB."
        )
    
    # Kunci 128/192/256 bit untuk AES, Nonce 96-bit (12 bytes)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    crc = 0
    total_written = 0
    tmpf = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = tmpf.name

    try:
        with open(in_path, 'rb') as fr:
            while True:
                chunk = fr.read(chunk_size)
                if not chunk: break
                # CRC dari data asli (plaintext)
                crc = zlib.crc32(chunk, crc)
                ct = encryptor.update(chunk)
                if ct: tmpf.write(ct); total_written += len(ct)

            # Finalisasi dan tag
            ct_final = encryptor.finalize()
            if ct_final: tmpf.write(ct_final); total_written += len(ct_final)
            tag = encryptor.tag
            tmpf.write(tag); total_written += len(tag)
    finally: tmpf.close()

    return tmp_path, orig_size, total_written, crc & 0xffffffff, nonce


# =========================================================================
# SENDER GUI CLASS
# =========================================================================

class SenderGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Pengirim - AES-GCM Multi-File (3 Level Key)")
        self.geometry("600x650")
        self.sock = None

        self.session_key_aes = None
        self.raw_session_key = None
        self.connected = False
        self.selected_files = []
        self.key_bits = None 

        self.security_level_var = ctk.StringVar(value=DEFAULT_SECURITY_LEVEL)

        self._build_ui()


    def _add_placeholder(self, entry, placeholder):
        def on_focusin(event):
            if entry.get() == placeholder:
                entry.delete(0, ctk.END)
                entry.configure(text_color=self._get_widget_color('text'))

        def on_focusout(event):
            if entry.get() == "":
                entry.insert(0, placeholder)
                entry.configure(text_color='gray')

        entry.insert(0, placeholder)
        entry.configure(text_color='gray')
        entry.bind('<FocusIn>', on_focusin)
        entry.bind('<FocusOut>', on_focusout)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)

        conn = ctk.CTkFrame(self)
        conn.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        conn.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(conn, text="IP/Host:").grid(row=0, column=0, padx=(10, 5), pady=10)
        self.host_entry = ctk.CTkEntry(conn, width=200)
        self._add_placeholder(self.host_entry, IP_PLACEHOLDER)
        self.host_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        ctk.CTkLabel(conn, text="Port:").grid(row=0, column=2, padx=(10, 5))
        self.port_var = ctk.IntVar(value=DEFAULT_PORT)
        ctk.CTkEntry(conn, textvariable=self.port_var, width=70).grid(row=0, column=3, padx=5)

        self.connect_btn = ctk.CTkButton(conn, text="Connect", command=self.toggle_connect, width=100)
        self.connect_btn.grid(row=0, column=4, padx=10, pady=10)
        
        # --- FRAME INFORMASI BATAS UKURAN ---
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="ew")
        
        self.limit_label = ctk.CTkLabel(info_frame, 
                                         text=f"⚠️ Batas Pada Level 3: Maksimal Ukuran FIle {MAX_FILE_SIZE_GB} GB. Lainnya: TIDAK DIBATASI.", 
                                         text_color="#FFA000", 
                                         font=ctk.CTkFont(weight="bold"))
        self.limit_label.pack(side="left", padx=5)
        # ---

        files_frame = ctk.CTkFrame(self)
        files_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        files_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(files_frame, text="LOG FILES", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")

        self.listbox = tkinter.Listbox(files_frame, height=6,
                                           bg=self._get_widget_color('frame'),
                                           fg=self._get_widget_color('text'),
                                           selectbackground=self._get_widget_color('selected_bg'),
                                           selectforeground=self._get_widget_color('selected_fg'),
                                           highlightthickness=0, bd=0)
        self.listbox.grid(row=1, column=0, padx=(10, 5), pady=(0, 10), sticky="nsew")

        btns = ctk.CTkFrame(files_frame)
        btns.grid(row=1, column=1, padx=(0, 10), pady=(0, 10), sticky="n")

        ctk.CTkButton(btns, text="Add Files", command=self.add_files).pack(fill='x', pady=5)
        ctk.CTkButton(btns, text="Remove Files", command=self.remove_selected).pack(fill='x', pady=5)

        clear_btn = ctk.CTkButton(btns, text="Clear Files", command=self.clear_files)
        clear_btn.pack(fill='x', pady=5)

        security_options = list(SECURITY_LEVELS.keys())

        security_container = ctk.CTkFrame(files_frame, fg_color="transparent")
        security_container.grid(row=2, column=1, padx=(0, 10), pady=(10, 20), sticky="ne")

        ctk.CTkLabel(security_container, text="Security Level").pack(side="top", anchor="w", padx=(5, 0))

        self.security_dropdown = ctk.CTkOptionMenu(security_container,
                                                   values=security_options,
                                                   variable=self.security_level_var,
                                                   width=150)
        self.security_dropdown.pack(side="top", anchor="w")

        progress_container = ctk.CTkFrame(self)
        progress_container.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        progress_container.grid_columnconfigure(0, weight=1)

        self.progress = MyProgressBar(progress_container,
                                          height=25,
                                          progress_color=DEFAULT_PROGRESS_COLOR,
                                          fg_color=self._get_widget_color('trough_bg'))
        self.progress.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.progress.set_value_and_text(0, "0.00%", running=False, success=False)

        self.send_btn = ctk.CTkButton(progress_container, text="SEND FILES", command=self.start_send, state='disabled', width=100)
        self.send_btn.grid(row=0, column=1, padx=(0, 10), pady=10)

        log_frame = ctk.CTkFrame(self)
        log_frame.grid(row=4, column=0, padx=10, pady=(5, 10), sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(log_frame, text="LOG MESSAGE", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")

        self.log = ctk.CTkTextbox(log_frame, height=150)
        self.log.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="nsew")
        self.log.configure(state='disabled')

        self.clear_log_btn = ctk.CTkButton(log_frame, text="Clear Log", command=self.clear_log, width=80)
        self.clear_log_btn.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="se")

        self.grid_rowconfigure(4, weight=1)

    
    def _get_widget_color(self, name):
        current_mode = ctk.get_appearance_mode().lower()

        if current_mode == 'dark':
            FRAME_BG = '#2b2b2b'
            TEXT_COLOR = 'white'
            SELECTED_BG = '#3a7ebf'
            TROUGH_BG = '#555555'
        else:
            FRAME_BG = '#EBEBEB'
            TEXT_COLOR = 'black'
            SELECTED_BG = '#3b8ed0'
            TROUGH_BG = '#CCCCCC'

        if name == 'frame': return FRAME_BG
        if name == 'text': return TEXT_COLOR
        if name == 'selected_bg': return SELECTED_BG
        if name == 'selected_fg': return "white"
        if name == 'trough_bg': return TROUGH_BG
        return "white"


    def log_message(self, msg):
        msg = msg.strip()
        self.log.configure(state='normal')
        self.log.insert('end', msg + "\n")
        self.log.see('end')
        self.log.configure(state='disabled')

    def clear_log(self):
        self.log.configure(state='normal')
        self.log.delete("1.0", ctk.END)
        self.log.configure(state='disabled')
        self.log_message("[INFO] Log cleared.")

    def toggle_connect(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        host = self.host_entry.get().strip()
        if not host or host == IP_PLACEHOLDER:
            host = DEFAULT_IP
        try:
            port = int(self.port_var.get())
        except ValueError:
            self.log_message("[ERROR] Invalid port number.")
            return

        self.log_message(f"[INFO] Connecting to {host}:{port} ...")
        t = threading.Thread(target=self._do_connect, args=(host, port), daemon=True)
        t.start()

    def _do_connect(self, host, port):
        # Reset kunci sebelum koneksi baru
        self.raw_session_key = None
        self.session_key_aes = None
        self.key_bits = None # Reset key_bits

        try:
            level_str = self.security_level_var.get()
            key_bits = SECURITY_LEVELS.get(level_str, 256)
            
            # SIMPAN key_bits ke instance class SENDER
            self.key_bits = key_bits 

            key_bytes = key_bits // 8

            raw_session_key = os.urandom(key_bytes)
            self.raw_session_key = raw_session_key
            self.session_key_aes = raw_session_key
            self.log_message(f"[KEY] Menggunakan kunci {key_bits}-bit untuk Sesi dan Enkripsi AES-GCM.")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((host, port))
            self.sock = s

            # Mengirim KUNCI MENTAH (RAW KEY) ke Penerima
            send_frame(self.sock, TYPE_KEY, self.raw_session_key)

            t, L = recv_frame_header(self.sock)
            if t != TYPE_ACK: 
                # Coba baca sisa payload jika ada, lalu raise error
                try: recv_exact(self.sock, L) 
                except: pass
                raise ConnectionError("No ACK for KEY")
            
            ack_payload = recv_exact(self.sock, L).decode('utf-8', errors='replace')
            if not ack_payload.startswith("OK"):
                raise ConnectionError("Server rejected key: " + ack_payload)

            self.connected = True
            self.after(0, lambda: [
                self.log_message("[INFO] Connected and key accepted. AES Key size for encryption: " + str(len(self.session_key_aes) * 8) + "-bit."),
                self.connect_btn.configure(text="Disconnect"),
                self.send_btn.configure(state='normal' if self.selected_files else 'disabled')
            ])
        except Exception as e:
            self.after(0, lambda: self.log_message("[ERROR] Connect failed: " + str(e)))
            self.after(0, lambda: messagebox.showerror("Koneksi GAGAL", f"Gagal terkoneksi: {e}"))
            self.after(0, self.disconnect) # Pastikan disconnect jika gagal

    def disconnect(self):
        try:
            if self.sock and self.connected:
                # Memberi tahu penerima bahwa sesi berakhir
                send_frame(self.sock, TYPE_END, b'')
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.raw_session_key = None
        self.session_key_aes = None
        self.connected = False
        self.key_bits = None 
        self.connect_btn.configure(text="Connect")
        self.send_btn.configure(state='disabled')
        self.log_message("[INFO] Disconnected")

    def add_files(self):
        paths = filedialog.askopenfilenames(title='Select files to send')
        for p in paths:
            if p not in self.selected_files:
                self.selected_files.append(p)
                self.listbox.insert('end', os.path.basename(p))
        self.send_btn.configure(state='normal' if self.connected and self.selected_files else 'disabled')

    def remove_selected(self):
        sel = list(self.listbox.curselection())
        for i in reversed(sel):
            self.listbox.delete(i)
            self.selected_files.pop(i)
        self.send_btn.configure(state='normal' if self.connected and self.selected_files else 'disabled')

    def clear_files(self):
        self.listbox.delete(0, 'end')
        self.selected_files = []
        self.send_btn.configure(state='disabled')
        
    def _update_listbox(self):
        # Memperbarui tampilan listbox agar sinkron dengan self.selected_files
        self.listbox.delete(0, 'end')
        for p in self.selected_files:
            self.listbox.insert('end', os.path.basename(p))

    def start_send(self):
        if not self.connected or not self.sock:
            messagebox.showerror("Error", "Not connected.")
            return
        if not self.selected_files:
            messagebox.showerror("Error", "No files selected.")
            return
        if self.key_bits is None:
            messagebox.showerror("Error", "Key bits belum diinisialisasi. Coba 'Connect' lagi.")
            return
            
        self.send_btn.configure(state='disabled')
        threading.Thread(target=self._send_files_thread, daemon=True).start()

    def _send_files_thread(self):
        # Menggunakan self.selected_files[:] untuk iterasi agar bisa menghapus item dari listbox tanpa konflik
        files_to_send = self.selected_files[:]
        
        # --- LOGIKA BARU: HITUNG SUKSES/GAGAL ---
        files_success = 0
        files_failed = 0
        total_processed = len(files_to_send)
        # ---------------------------------------
        
        try:
            
            files_removed_due_to_error = []
            
            current_key_bits = self.key_bits 
            
            # Mendapatkan indeks file asli di listbox sebelum loop
            original_file_indices = {path: i for i, path in enumerate(self.selected_files)}

            for idx, path in enumerate(files_to_send, start=1):
                fname = os.path.basename(path)
                self.log_message(f"\n--- START TRANSFER {idx}/{total_processed}: {fname} ---")

                self.after(0, lambda i=idx, t=total_processed: self.progress.set_value_and_text(0, f"0.00% (File {i}/{t})", running=True, success=False))

                tmp_path = None
                orig_crc32 = 0 # Inisialisasi CRC
                
                try:
                    # 1. Enkripsi file ke file sementara
                    # Melewatkan current_key_bits ke fungsi enkripsi
                    tmp_path, orig_size, enc_size, orig_crc32, nonce = encrypt_file_to_temp_gcm(path, self.session_key_aes, current_key_bits) 
                    
                    self.log_message(f"[META] Original Size: {orig_size} B | Encrypted Size: {enc_size} B | CRC Pengirim: {orig_crc32:08X}")
                    meta = build_metadata_bytes(fname, orig_size, enc_size, orig_crc32, nonce)

                    # 2. Kirim Frame Metadata
                    send_frame(self.sock, TYPE_META, meta)

                    t, L = recv_frame_header(self.sock)
                    if t != TYPE_ACK: 
                        # Coba baca sisa payload jika ada, lalu raise error
                        try: recv_exact(self.sock, L) 
                        except: pass
                        raise ConnectionError("Expected ACK after metadata")
                        
                    ack = recv_exact(self.sock, L).decode('utf-8', errors='replace')
                    if not ack.startswith("OK"): 
                        raise ConnectionError("Server rejected metadata: " + ack)

                    self.log_message("[INFO] Server ACK metadata. Streaming encrypted data...")
                    sent = 0
                    with open(tmp_path, 'rb') as f:
                        while True:
                            chunk = f.read(CHUNK)
                            if not chunk: break

                            # 3. Kirim Data Terenkripsi (Streaming)
                            self.sock.sendall(chunk)
                            sent += len(chunk)

                            pct_float = (sent / enc_size) * 100 if enc_size > 0 else 100.00
                            pct_int = int(pct_float)
                            text_display = f"{pct_float:.2f}% (File {idx}/{total_processed})"

                            self.after(0, lambda p=pct_int, i=idx, t=total_processed, txt=text_display: self.progress.set_value_and_text(p, txt, running=True, success=False))

                    # 4. Terima ACK Selesai
                    t, L = recv_frame_header(self.sock)
                    if t != TYPE_ACK: 
                        # Coba baca sisa payload jika ada, lalu raise error
                        try: recv_exact(self.sock, L) 
                        except: pass
                        raise ConnectionError("Expected final ACK from server")
                        
                    final = recv_exact(self.sock, L).decode('utf-8', errors='replace')
                    status = final[:4]
                    recv_crc = final[4:]
                    self.log_message(f"[CRC] CRC Penerima: {recv_crc}") # Selalu tampil

                    if status == "DONE":
                        self.log_message("[CRC OK] File valid, transfer SUKSES.")
                        self.after(0, lambda i=idx, t=total_processed: self.progress.set_value_and_text(100, f"100.00% (SUKSES: {i}/{t})", running=False, success=True))
                        # Berhasil
                        files_success += 1
                        files_removed_due_to_error.append(path) 
                    else:
                        # Status FAIL (Kegagalan CRC)
                        self.log_message(f"[CRC FAIL] CRC TIDAK COCOK. Pengirim={orig_crc32:08X}, Penerima={recv_crc}. Transfer GAGAL.")
                        self.after(0, lambda i=idx, t=total_processed: self.progress.set_value_and_text(0, f"GAGAL (File {i}/{t})", running=False, success=False))
                        # Gagal
                        files_failed += 1
                        files_removed_due_to_error.append(path)
                        # Tampilkan Pop-up Error
                        self.after(0, lambda: messagebox.showerror("Transfer GAGAL (CRC)", f"File '{fname}' gagal diverifikasi Penerima.\n\nCRC Pengirim: {orig_crc32:08X}\nCRC Penerima: {recv_crc}"))
                        raise ConnectionError("Server reported CRC failure: " + final)

                except ValueError as ve:
                    # Penanganan Error Ukuran File (Langkah 1)
                    error_msg = f"[ERROR] File '{fname}' GAGAL dienkripsi/diverifikasi: {ve}"
                    self.log_message(error_msg)
                    self.log_message(f"[CRC] CRC Pengirim: {orig_crc32:08X}") # Tampilkan CRC (mungkin 0 jika gagal dienkripsi)
                    self.after(0, lambda: self.progress.set_value_and_text(0, f"Gagal (Ukuran/VE)", running=False, success=False))
                    self.after(0, lambda: messagebox.showerror("Transfer GAGAL (File Error)", f"File '{fname}' gagal diproses:\n{ve}\n\nCRC Pengirim: {orig_crc32:08X}"))
                    # Gagal
                    files_failed += 1
                    files_removed_due_to_error.append(path)
                    
                except ConnectionError as ce:
                    # Penanganan Error Koneksi/ACK (Setelah Langkah 1)
                    error_msg = f"[ERROR] Koneksi/ACK GAGAL untuk '{fname}': {ce}"
                    self.log_message(error_msg)
                    self.log_message(f"[CRC] CRC Pengirim: {orig_crc32:08X}") # Tampilkan CRC
                    self.after(0, lambda: self.progress.set_value_and_text(0, f"GAGAL (Conn)", running=False, success=False))
                    self.after(0, lambda: messagebox.showerror("Transfer GAGAL (Koneksi)", f"File '{fname}' gagal dikirim karena masalah koneksi/ACK.\n\nCRC Pengirim: {orig_crc32:08X}\nError: {ce}"))
                    # Gagal
                    files_failed += 1
                    files_removed_due_to_error.append(path)
                
                except Exception as e:
                    # Penanganan Error Lainnya
                    error_msg = f"[FATAL] Error tak terduga untuk '{fname}': {e}"
                    self.log_message(error_msg)
                    self.log_message(f"[CRC] CRC Pengirim: {orig_crc32:08X}") # Tampilkan CRC
                    self.after(0, lambda: self.progress.set_value_and_text(0, f"GAGAL (Fatal)", running=False, success=False))
                    self.after(0, lambda: messagebox.showerror("Transfer GAGAL (Fatal)", f"File '{fname}' gagal dikirim karena error tak terduga.\n\nCRC Pengirim: {orig_crc32:08X}\nError: {e}"))
                    # Gagal
                    files_failed += 1
                    files_removed_due_to_error.append(path)
                    
                finally:
                    # Cleanup file sementara terenkripsi
                    if tmp_path and os.path.exists(tmp_path):
                        try: os.remove(tmp_path)
                        except Exception: pass
            
            # Bersihkan list selected_files (hanya item yang berhasil/gagal diproses)
            self.after(0, lambda: self._remove_processed_files(files_removed_due_to_error))

            # --- LOGIKA BARU: NOTIFIKASI AKHIR YANG SPESIFIK ---
            if files_success == total_processed and total_processed > 0:
                self.after(0, lambda: messagebox.showinfo("Transfer Done! ✅", f"SEMUA file ({total_processed}) telah berhasil dikirim dan diverifikasi!"))
            elif files_failed == total_processed and total_processed > 0:
                self.after(0, lambda: messagebox.showerror("Transfer GAGAL Total ❌", f"SEMUA file ({total_processed}) gagal diproses/dikirim. Total {total_processed} file."))
            elif files_success > 0 and files_failed > 0:
                self.after(0, lambda: messagebox.showwarning("Transfer Selesai ⚠️", f"Transfer selesai dengan hasil campuran: \n\n✅ Sukses: {files_success} file\n❌ Gagal: {files_failed} file\n\nCek Log untuk detail file yang gagal."))
            elif total_processed == 0 and len(self.selected_files) == 0:
                self.after(0, lambda: messagebox.showinfo("Transfer Done!", "Antrian kosong. Tidak ada file untuk dikirim."))
            # ---------------------------------------------------


        except Exception as e:
            # Fatal error (di luar loop file - biasanya masalah koneksi awal)
            self.after(0, lambda: self.progress.set_value_and_text(0, f"ERROR!", running=False, success=False))
            self.after(0, lambda: [self.log_message(f"[FATAL ERROR] Sending failed: {e}"), messagebox.showerror("Koneksi Fatal Error", str(e))])

        finally:
            self.after(0, lambda: self.send_btn.configure(state='normal' if self.connected and self.selected_files else 'disabled'))
            self.after(0, lambda: self.progress.set_value_and_text(0, "0.00%", running=False, success=False))
            
    def _remove_processed_files(self, paths_to_remove):
        # Dipanggil di main thread untuk memanipulasi GUI
        new_list = [p for p in self.selected_files if p not in paths_to_remove]
        self.selected_files = new_list
        self._update_listbox()
        self.send_btn.configure(state='normal' if self.connected and self.selected_files else 'disabled')


if __name__ == '__main__':
    app = SenderGUI()
    app.mainloop()