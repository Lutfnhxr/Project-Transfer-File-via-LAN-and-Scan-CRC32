import os
import socket
import struct
import tempfile
import threading
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time # Tambahkan import time untuk timeout

# =========================================================================
# KONSTANTA GLOBAL
# =========================================================================

HOST = ''
PORT = 5000
CHUNK = 64 * 1024
SOCKET_TIMEOUT = 120 # Timeout untuk operasi socket

TYPE_KEY = b'K'
TYPE_META = b'M'
TYPE_ACK = b'A'
TYPE_END = b'E'

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# =========================================================================
# HELPER FUNCTIONS
# =========================================================================

def send_frame(sock, t: bytes, payload: bytes):
    if not isinstance(t, (bytes, bytearray)) or len(t) != 1:
        raise ValueError("type must be single byte")
    
    # Header format yang sinkron dengan Pengirim (little-endian '<I')
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
    # Header 5 byte: 1 byte Type + 4 byte Length (<I) - SINKRON
    hdr = recv_exact(sock, 5)
    return hdr[0:1], struct.unpack('<I', hdr[1:5])[0]

def parse_metadata_sync(meta: bytes):
    # Format metadata (Sinkron dengan Pengirim): 
    # [H:FName_Len] [FName] [Q:OrigSize] [Q:EncSize] [I:CRC32] [B:NonceLen] [Nonce (12)]
    
    # Nonce (12 byte) + Nonce Len (1 byte)
    NONCE_LEN = 12
    nonce = meta[len(meta)-NONCE_LEN:]
    nonce_len_byte = meta[len(meta)-NONCE_LEN-1:len(meta)-NONCE_LEN]
    nonce_len = struct.unpack('<B', nonce_len_byte)[0]

    if nonce_len != NONCE_LEN:
          raise ValueError(f"Nonce length mismatch (expected {NONCE_LEN}, got {nonce_len})")
    
    # CRC32 (4 byte - I)
    crc32_bytes = meta[len(meta)-NONCE_LEN-1-4:len(meta)-NONCE_LEN-1]
    crc32 = struct.unpack('<I', crc32_bytes)[0]
    
    # Enc Size (8 byte - Q): UKURAN TERENKRIPSI
    enc_size_bytes = meta[len(meta)-NONCE_LEN-1-4-8:len(meta)-NONCE_LEN-1-4]
    enc_size = struct.unpack('<Q', enc_size_bytes)[0]
    
    # Orig Size (8 byte - Q): UKURAN ASLI
    orig_size_bytes = meta[len(meta)-NONCE_LEN-1-4-8-8:len(meta)-NONCE_LEN-1-4-8]
    orig_size = struct.unpack('<Q', orig_size_bytes)[0]
    
    # --- Pembacaan dari Depan (Nama File) ---
    # File Name Length (2 byte - H)
    fname_len = struct.unpack('<H', meta[0:2])[0]
    fname_start_idx = 2
    fname_bytes = meta[fname_start_idx:fname_start_idx+fname_len]
    fname = fname_bytes.decode('utf-8', errors='replace')
    
    # Pengecekan Total Panjang - SINKRON
    expected_len = 2 + fname_len + 8 + 8 + 4 + 1 + NONCE_LEN
    if len(meta) != expected_len:
        raise ValueError(f"Metadata length mismatch (expected {expected_len}, got {len(meta)})")
        
    return {'filename':fname, 'orig_size':orig_size, 'enc_size':enc_size, 'crc32':crc32, 'nonce':nonce}


def decrypt_and_verify_gcm(tmp_path: str, key: bytes, nonce: bytes, out_path: str):
    tag_len = 16 # GCM Tag selalu 16 byte
    stat = os.stat(tmp_path)
    if stat.st_size < tag_len:
        raise ValueError("Encrypted payload too small (missing GCM tag)")
        
    ciphertext_len = stat.st_size - tag_len
    
    # 1. Baca GCM Tag dari akhir file terenkripsi
    with open(tmp_path, 'rb') as f:
        f.seek(ciphertext_len)
        tag = f.read(tag_len)
        
    # 2. Inisialisasi Decryptor dengan Tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    calc_crc = 0
    
    try:
        # 3. Baca dan Dekripsi Ciphertext
        with open(tmp_path, 'rb') as cf, open(out_path, 'wb') as outf:
            to_read = ciphertext_len
            cf.seek(0)
            
            while to_read > 0:
                chunk = cf.read(min(CHUNK, to_read))
                if not chunk:
                    raise ConnectionError("File stream ended unexpectedly during decryption.")
                
                pt = decryptor.update(chunk)
                if pt:
                    outf.write(pt)
                    # Hitung CRC dari data DEKRIPSI (plaintext) - SINKRON
                    calc_crc = zlib.crc32(pt, calc_crc) 
                to_read -= len(chunk)
                
            pt_final = decryptor.finalize()
            if pt_final:
                outf.write(pt_final)
                calc_crc = zlib.crc32(pt_final, calc_crc)
                
    except Exception as e:
        # Hapus file output jika dekripsi/verifikasi gagal
        try:
            os.remove(out_path)
        except Exception:
            pass
        # Jika gagal di sini, kemungkinan MAC Tag tidak valid (Authentication Failure)
        if "Tag mismatch" in str(e):
            raise ValueError(f"AES-GCM Authentication Failed (Tag mismatch): Data tidak valid/rusak.") from e
        raise e
        
    # Pastikan CRC dikonversi ke format 32-bit unsigned
    calc_crc &= 0xffffffff
    return calc_crc

# =========================================================================
# GUI & SERVER LOGIC
# =========================================================================

class ReceiverGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Penerima - AES-GCM Multi-File")
        self.geometry("600x450")
        self.server = None
        self.running = False
        self.save_dir = os.path.abspath('received_files')
        os.makedirs(self.save_dir, exist_ok=True)
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _get_ctk_color(self, name):
        current_mode = ctk.get_appearance_mode().lower()
        
        try:
            if current_mode == 'dark' or current_mode == 'system':
                TEXTBOX_BG = ctk.ThemeManager.theme["CTk"]["fg_color"][1]
                TEXTBOX_TEXT = ctk.ThemeManager.theme["CTk"]["text_color"][1]
            else:
                TEXTBOX_BG = ctk.ThemeManager.theme["CTk"]["fg_color"][0]
                TEXTBOX_TEXT = ctk.ThemeManager.theme["CTk"]["text_color"][0]

        except KeyError:
            TEXTBOX_BG = '#242424' if current_mode == 'dark' else '#F0F0F0'
            TEXTBOX_TEXT = 'white' if current_mode == 'dark' else 'black'

        if name == 'textbox_fg':
            return TEXTBOX_BG
        if name == 'textbox_text':
            return TEXTBOX_TEXT
        if name == 'cursor_color':
            return TEXTBOX_TEXT 
        return "white"

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1) 

        top = ctk.CTkFrame(self)
        top.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        top.grid_columnconfigure(3, weight=1) 
        
        ctk.CTkLabel(top, text="Port:").grid(row=0, column=0, padx=(10, 5), pady=10)
        self.port_var = tk.IntVar(value=PORT)
        ctk.CTkEntry(top, textvariable=self.port_var, width=80).grid(row=0, column=1, padx=5, pady=10)
        
        self.start_btn = ctk.CTkButton(top, text="Start Server", command=self.start_server, width=100)
        self.start_btn.grid(row=0, column=2, padx=(10, 5), pady=10)
        
        self.stop_btn = ctk.CTkButton(top, text="Stop Server", command=self.stop_server, state='disabled', width=100)
        self.stop_btn.grid(row=0, column=3, padx=5, pady=10, sticky="w")
        
        folder_frame = ctk.CTkFrame(self, fg_color="transparent")
        folder_frame.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="ew")
        
        folder_frame.grid_columnconfigure(1, weight=1) 
        
        ctk.CTkLabel(folder_frame, text="Save Dir:").grid(row=0, column=0, padx=(10, 5), pady=5, sticky="w")
        
        self.folder_label = ctk.CTkLabel(folder_frame, text=self.save_dir, wraplength=400, anchor="w", justify="left")
        self.folder_label.grid(row=0, column=1, padx=(5, 10), pady=5, sticky="ew")
        
        self.folder_btn = ctk.CTkButton(folder_frame, text="Ubah Folder", command=self.choose_folder, width=100)
        self.folder_btn.grid(row=0, column=2, padx=(0, 10), pady=5, sticky="e") 

        log_container = ctk.CTkFrame(self)
        log_container.grid(row=2, column=0, padx=10, pady=(5, 5), sticky="nsew")
        log_container.grid_columnconfigure(0, weight=1)
        log_container.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(log_container, text="LOG MESSAGE", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=(5, 0), sticky="w")

        self.log = tk.Text(log_container, height=18, state='disabled',
                            bg=self._get_ctk_color('textbox_fg'), 
                            fg=self._get_ctk_color('textbox_text'),
                            insertbackground=self._get_ctk_color('cursor_color'), 
                            highlightthickness=0, bd=0)
        self.log.grid(row=1, column=0, padx=10, pady=(5, 5), sticky="nsew")
        
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="ew")
        bottom.grid_columnconfigure(0, weight=1)
        self.clear_btn = ctk.CTkButton(bottom, text="Clear Log", command=self.clear_log, width=80)
        self.clear_btn.pack(side='right', padx=10, pady=5)
        
        self.grid_rowconfigure(2, weight=1)

    def log_message(self, msg):
        self.after(0, self._insert_log, msg)

    def _insert_log(self, msg):
        self.log.config(state='normal')
        self.log.insert('end', msg + "\n")
        self.log.see('end')
        self.log.config(state='disabled')

    def clear_log(self):
        self.log.config(state='normal')
        self.log.delete('1.0', tk.END)
        self.log.config(state='disabled')
        self.log_message("[INFO] Log cleared")

    def choose_folder(self):
        d = filedialog.askdirectory(initialdir=self.save_dir, title='Select folder')
        if d:
            self.save_dir = d
            self.folder_label.configure(text=self.save_dir)

    def start_server(self):
        if self.running:
            return
        try:
            port = int(self.port_var.get())
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', port))
            s.listen(5)
            self.server = s
            self.running = True
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
            threading.Thread(target=self._accept_loop, daemon=True).start()
            self.log_message(f"[INFO] Server listening on port {port}")
        except Exception as e:
            messagebox.showerror("Server Error", f"Could not start server: {e}")
            self.log_message(f"[FATAL] Failed to start server: {e}")
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')

    def stop_server(self):
        if not self.running:
            return
        self.running = False
        try:
            # Connect to self to unblock server.accept()
            temp_socket = socket.socket()
            temp_socket.connect(('127.0.0.1', int(self.port_var.get())))
            temp_socket.close()
        except Exception:
            pass
        try:
            if self.server:
                self.server.close()
        except Exception:
            pass
        self.start_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        self.log_message("[INFO] Server stopped")
        
    def _on_closing(self):
        if self.running:
            self.stop_server()
        self.destroy()

    def _accept_loop(self):
        while self.running:
            try:
                # Mengatur timeout agar loop bisa dicek
                self.server.settimeout(0.5) 
                conn, addr = self.server.accept()
                conn.settimeout(SOCKET_TIMEOUT)
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log_message(f"[ERROR] Accept loop: {e}")
                break
        
        self.after(0, lambda: self.start_btn.configure(state='normal'))
        self.after(0, lambda: self.stop_btn.configure(state='disabled'))

    def _handle_client(self, conn, addr):
        addr_str = f"{addr[0]}:{addr[1]}"
        self.log_message(f"[CONNECTED] New client: {addr_str}")
        
        client_key_raw_recv = None
        client_session_key = None 
        tmp_path = None
        
        try:
            # 1. Menerima Kunci Sesi (Key Frame)
            t, L = recv_frame_header(conn)
            if t != TYPE_KEY:
                self.log_message(f"[ERROR] Expected session key frame (K), got {t.decode()}. L={L}")
                send_frame(conn, TYPE_ACK, b"FAIL:ExpectedKey")
                if L > 0: recv_exact(conn, L) 
                raise ConnectionError("Expected session key frame")
            
            client_key_raw_recv = recv_exact(conn, L)
            raw_key_len = len(client_key_raw_recv)
            
            # Logika Kunci AES (Sinkron dengan Pengirim: 16, 24, 32 bytes)
            if raw_key_len == 16:
                client_session_key = client_key_raw_recv
                self.log_message(f"[KEY] Session key AES-128 (16 bytes) diterima.")
            elif raw_key_len == 24:
                client_session_key = client_key_raw_recv
                self.log_message(f"[KEY] Session key AES-192 (24 bytes) diterima.")
            elif raw_key_len == 32:
                client_session_key = client_key_raw_recv
                self.log_message(f"[KEY] Session key AES-256 (32 bytes) diterima.")
            else:
                self.log_message(f"[FATAL] Invalid key length {raw_key_len} bytes. Expected 16, 24, or 32 bytes. Connection closed.")
                send_frame(conn, TYPE_ACK, b"FAIL:InvalidKeyLength")
                raise ConnectionError(f"Invalid key length {raw_key_len} bytes")

            send_frame(conn, TYPE_ACK, b"OK")
            self.log_message(f"[KEY] Connected and key accepted. AES Key size for encryption: {len(client_session_key)*8}-bit.")


            # 2. Loop Menerima File (Metadata dan Data Stream)
            while True:
                t, L = recv_frame_header(conn)
                
                if t == TYPE_END:
                    if L: _ = recv_exact(conn, L)
                    self.log_message("[INFO] End of session by sender")
                    break
                    
                if t != TYPE_META:
                    self.log_message(f"[ERROR] Expected metadata frame (M) or End (E), got {t.decode()}. L={L}. Closing connection.")
                    send_frame(conn, TYPE_ACK, b"FAIL:ExpectedMeta")
                    if L > 0: recv_exact(conn, L) 
                    raise ConnectionError("Expected metadata frame")
                
                # Menerima Metadata
                meta = recv_exact(conn, L)
                # Panggilan ke fungsi sinkronisasi metadata
                info = parse_metadata_sync(meta) 
                
                fname = info['filename']
                crc_expected = info['crc32']
                enc_size_expected = info['enc_size']
                client_session_nonce = info['nonce'] 
                
                self.log_message(f"\n--- START TRANSFER 1/N: {fname} ---")
                self.log_message(f"[INFO] Original size: {info['orig_size']} B | Enc size: {enc_size_expected} B | Expected CRC: {crc_expected:08X}")

                # Kirim ACK untuk Metadata
                send_frame(conn, TYPE_ACK, b"OK")
                
                # Menerima Data Stream
                tmpf = tempfile.NamedTemporaryFile(delete=False)
                tmp_path = tmpf.name
                
                bytes_to_read = enc_size_expected
                bytes_received = 0
                
                try:
                    conn.settimeout(SOCKET_TIMEOUT)
                    while bytes_received < bytes_to_read:
                        remaining = bytes_to_read - bytes_received
                        # Coba baca maksimal CHUNK, tapi tidak lebih dari sisa
                        chunk = conn.recv(min(CHUNK, remaining)) 
                        if not chunk:
                            if bytes_received < bytes_to_read:
                                raise ConnectionError(f"Connection lost unexpectedly during data stream. Received {bytes_received}/{bytes_to_read} bytes.")
                            break
                            
                        tmpf.write(chunk)
                        bytes_received += len(chunk)

                    if bytes_received != bytes_to_read:
                        raise ConnectionError(f"Expected {bytes_to_read} bytes, received {bytes_received} bytes.")
                        
                    tmpf.close()
                    
                    # 3. Dekripsi dan Verifikasi
                    out_path = os.path.join(self.save_dir, fname)
                    
                    # Logika Verifikasi
                    is_valid = False
                    
                    try:
                        # Panggilan ke fungsi dekripsi dan verifikasi GCM
                        calc_crc = decrypt_and_verify_gcm(
                            tmp_path, 
                            client_session_key, 
                            client_session_nonce, 
                            out_path
                        )
                        
                        # VERIFIKASI CRC
                        if calc_crc == crc_expected:
                            is_valid = True
                        
                    except ValueError as ve:
                        # Tangkap Tag Mismatch GCM/Error dekripsi/CRC
                        self.log_message(f"[ERROR] Dekripsi/Otentikasi GAGAL: {ve}")
                        # Jika dekripsi gagal, CRC tidak dapat dihitung dengan benar. Set CRC ke 0 untuk laporan.
                        calc_crc = 0 
                    except Exception as e:
                        # Tangkap error lain (I/O, dll)
                        self.log_message(f"[FATAL] Error saat dekripsi: {e}")
                        calc_crc = 0
                        
                    # Log CRC (Selalu tampil)
                    self.log_message(f"[CRC] CRC Pengirim: {crc_expected:08X}")
                    self.log_message(f"[CRC] CRC Penerima: {calc_crc:08X}")

                    if is_valid:
                        # Format balasan: DONE + CRC Penerima (8 digit hex) - SINKRON
                        response = f"DONE{calc_crc:08X}".encode('utf-8')
                        self.log_message("[CRC OK] Dekripsi & CRC VALID ✅ → File tersimpan dengan benar")
                        self.after(0, lambda f=fname: messagebox.showinfo("Transfer Done!", f"File '{f}' berhasil diterima dan diverifikasi!"))
                    else:
                        # Format balasan: FAIL + CRC Penerima (8 digit hex) - SINKRON
                        response = f"FAIL{calc_crc:08X}".encode('utf-8')
                        # Hapus file yang gagal jika masih ada
                        if os.path.exists(out_path):
                            try: os.remove(out_path)
                            except Exception: pass
                        self.log_message("[CRC FAIL] CRC TIDAK COCOK ❌. File output dihapus.")

                    # Kirim ACK Final
                    send_frame(conn, TYPE_ACK, response)

                except ConnectionError as e:
                    self.log_message(f"[ERROR] Connection lost during data stream: {e}")
                    raise 
                except ValueError as e:
                    self.log_message(f"[ERROR] Data processing failed (Metadata/Stream/GCM): {e}")
                    # Kirim balasan gagal (CRC 0) karena tidak dapat memproses file sepenuhnya
                    send_frame(conn, TYPE_ACK, b"FAIL00000000") 
                except Exception as e:
                    self.log_message(f"[ERROR] Unexpected error during file processing: {e}")
                    send_frame(conn, TYPE_ACK, b"FAIL00000000")
                finally:
                    # Hapus file terenkripsi sementara
                    if tmp_path and os.path.exists(tmp_path):
                        try: os.remove(tmp_path)
                        except Exception: pass
                    tmp_path = None
                    
        except ConnectionError as e:
            self.log_message(f"[DISCONNECTED] {addr_str}: {e}")
        except Exception as e:
            self.log_message(f"[FATAL] Client handler {addr_str}: " + str(e))
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self.log_message(f"[DISCONNECTED] {addr_str}")

if __name__ == '__main__':
    app = ReceiverGUI()
    app.mainloop()