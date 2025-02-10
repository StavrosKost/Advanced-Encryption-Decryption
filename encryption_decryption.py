import os
import threading
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
#creation date 10/02/2025
# Constants
SALT_SIZE = 16  # Salt size for PBKDF2
KEY_SIZE = 32   # 256-bit key for AES-256
IV_SIZE = 16    # 128-bit IV for AES

# Derive a key from a password using PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,  # Adjust iterations for security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file
def encrypt_file(input_file: str, output_file: str, password: str, algorithm="AES", mode="CBC", progress_callback=None) -> bool:
    try:
        # Generate a random salt and IV
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)

        # Derive the key from the password
        key = derive_key(password, salt)

        # Read the input file
        with open(input_file, "rb") as f:
            plaintext = f.read()

        # Pad the plaintext to match block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Choose encryption algorithm and mode
        if algorithm == "AES":
            if mode == "CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            elif mode == "GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            else:
                raise ValueError("Unsupported mode for AES.")
        elif algorithm == "ChaCha20":
            cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
        else:
            raise ValueError("Unsupported encryption algorithm.")

        # Encrypt the data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Write the salt, IV, and ciphertext to the output file
        with open(output_file, "wb") as f:
            f.write(salt + iv + ciphertext)

        if progress_callback:
            progress_callback(100)  # Complete
        return True
    except Exception as e:
        print(f"Encryption error: {e}")
        if progress_callback:
            progress_callback(0)  # Reset on error
        return False

# Decrypt a file
def decrypt_file(input_file: str, output_file: str, password: str, algorithm="AES", mode="CBC", progress_callback=None) -> bool:
    try:
        # Read the input file
        with open(input_file, "rb") as f:
            data = f.read()

        # Extract the salt, IV, and ciphertext
        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        ciphertext = data[SALT_SIZE + IV_SIZE:]

        # Derive the key from the password
        key = derive_key(password, salt)

        # Choose decryption algorithm and mode
        if algorithm == "AES":
            if mode == "CBC":
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            elif mode == "GCM":
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            else:
                raise ValueError("Unsupported mode for AES.")
        elif algorithm == "ChaCha20":
            cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
        else:
            raise ValueError("Unsupported encryption algorithm.")

        # Decrypt the data
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Write the decrypted data to the output file
        with open(output_file, "wb") as f:
            f.write(plaintext)

        if progress_callback:
            progress_callback(100)  # Complete
        return True
    except InvalidKey:
        print("Decryption error: Invalid password.")
        if progress_callback:
            progress_callback(0)  # Reset on error
        return False
    except Exception as e:
        print(f"Decryption error: {e}")
        if progress_callback:
            progress_callback(0)  # Reset on error
        return False

# Compute the hash of a file
def compute_file_hash(file_path: str) -> str:
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.finalize().hex()

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Sign a file
def sign_file(file_path: str, private_key) -> bytes:
    with open(file_path, "rb") as f:
        data = f.read()
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify a file's signature
def verify_signature(file_path: str, signature: bytes, public_key) -> bool:
    with open(file_path, "rb") as f:
        data = f.read()
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("800x1100")
        self.root.resizable(True, True)

        # Dark mode toggle
        self.dark_mode = False
        self.theme = {
            "bg": "#f0f0f0",
            "fg": "#000000",
            "button_bg": "#e0e0e0",
            "text_bg": "#ffffff",
            "text_fg": "#000000",
            "progress_bg": "#0078d7",
        }

        # Initialize ttk styles
        self.style = ttk.Style()
        self.style.configure("TFrame", background=self.theme["bg"])
        self.style.configure("TLabel", background=self.theme["bg"], foreground=self.theme["fg"])
        self.style.configure("TButton", background=self.theme["button_bg"], foreground=self.theme["fg"])
        self.style.configure("TEntry", background=self.theme["text_bg"], foreground=self.theme["text_fg"])
        self.style.configure("Horizontal.TProgressbar", background=self.theme["progress_bg"])

        # Main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky="nsew")

        # Dark mode button
        self.dark_mode_button = ttk.Button(self.main_frame, text="Dark Mode", command=self.toggle_dark_mode)
        self.dark_mode_button.grid(row=0, column=2, padx=10, pady=10, sticky="e")

        # Input file
        self.input_file_label = ttk.Label(self.main_frame, text="Input File:")
        self.input_file_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.input_file_entry = ttk.Entry(self.main_frame, width=40)
        self.input_file_entry.grid(row=1, column=1, padx=10, pady=10)
        self.input_file_button = ttk.Button(self.main_frame, text="Browse", command=self.browse_input_file)
        self.input_file_button.grid(row=1, column=2, padx=10, pady=10)

        # Output file
        self.output_file_label = ttk.Label(self.main_frame, text="Output File:")
        self.output_file_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.output_file_entry = ttk.Entry(self.main_frame, width=40)
        self.output_file_entry.grid(row=2, column=1, padx=10, pady=10)
        self.output_file_button = ttk.Button(self.main_frame, text="Browse", command=self.browse_output_file)
        self.output_file_button.grid(row=2, column=2, padx=10, pady=10)

        # Password
        self.password_label = ttk.Label(self.main_frame, text="Password:")
        self.password_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.password_entry = ttk.Entry(self.main_frame, show="*", width=40)
        self.password_entry.grid(row=3, column=1, padx=10, pady=10)

        # Encryption options
        self.algorithm_label = ttk.Label(self.main_frame, text="Algorithm:")
        self.algorithm_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.algorithm_var = tk.StringVar(value="AES")
        self.algorithm_menu = ttk.Combobox(self.main_frame, textvariable=self.algorithm_var, values=["AES", "ChaCha20"])
        self.algorithm_menu.grid(row=4, column=1, padx=10, pady=10)

        self.mode_label = ttk.Label(self.main_frame, text="Mode:")
        self.mode_label.grid(row=5, column=0, padx=10, pady=10, sticky="w")
        self.mode_var = tk.StringVar(value="CBC")
        self.mode_menu = ttk.Combobox(self.main_frame, textvariable=self.mode_var, values=["CBC", "GCM"])
        self.mode_menu.grid(row=5, column=1, padx=10, pady=10)

        # Buttons
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=6, column=0, columnspan=3, pady=20)
        self.encrypt_button = ttk.Button(self.button_frame, text="Encrypt", command=self.start_encryption)
        self.encrypt_button.grid(row=0, column=0, padx=10)
        self.decrypt_button = ttk.Button(self.button_frame, text="Decrypt", command=self.start_decryption)
        self.decrypt_button.grid(row=0, column=1, padx=10)
        self.clear_button = ttk.Button(self.button_frame, text="Clear", command=self.clear_fields)
        self.clear_button.grid(row=0, column=2, padx=10)

        # Progress bar
        self.progress = ttk.Progressbar(self.main_frame, orient="horizontal", length=500, mode="determinate")
        self.progress.grid(row=7, column=0, columnspan=3, pady=10)

        # Status bar
        self.status_label = ttk.Label(self.main_frame, text="Ready", font=("Arial", 10), foreground="blue")
        self.status_label.grid(row=8, column=0, columnspan=3, pady=10)

        # File preview
        self.preview_label = ttk.Label(self.main_frame, text="File Preview:", font=("Arial", 10))
        self.preview_label.grid(row=9, column=0, padx=10, pady=10, sticky="w")
        self.preview_text = tk.Text(self.main_frame, height=10, width=60, wrap="word")
        self.preview_text.grid(row=10, column=0, columnspan=3, padx=10, pady=10)
        self.load_more_button = ttk.Button(self.main_frame, text="Load More", command=self.load_more_preview)
        self.load_more_button.grid(row=11, column=0, columnspan=3, pady=10)

        # File hash
        self.hash_label = ttk.Label(self.main_frame, text="File Hash (SHA-256):", font=("Arial", 10))
        self.hash_label.grid(row=12, column=0, padx=10, pady=10, sticky="w")
        self.hash_entry = ttk.Entry(self.main_frame, width=70, state="readonly")
        self.hash_entry.grid(row=12, column=1, columnspan=2, padx=10, pady=10)
        self.compute_hash_button = ttk.Button(self.main_frame, text="Compute Hash", command=self.compute_hash)
        self.compute_hash_button.grid(row=13, column=0, columnspan=3, pady=10)

        # File integrity verification
        self.compare_hash_label = ttk.Label(self.main_frame, text="Compare File Hash:", font=("Arial", 10))
        self.compare_hash_label.grid(row=14, column=0, padx=10, pady=10, sticky="w")
        self.compare_hash_entry = ttk.Entry(self.main_frame, width=70)
        self.compare_hash_entry.grid(row=14, column=1, columnspan=2, padx=10, pady=10)
        self.compare_hash_button = ttk.Button(self.main_frame, text="Compare Hash", command=self.compare_hash)
        self.compare_hash_button.grid(row=15, column=0, columnspan=3, pady=10)

        # Digital signature
        self.signature_label = ttk.Label(self.main_frame, text="Digital Signature:", font=("Arial", 10))
        self.signature_label.grid(row=16, column=0, padx=10, pady=10, sticky="w")
        self.signature_entry = ttk.Entry(self.main_frame, width=70, state="readonly")
        self.signature_entry.grid(row=16, column=1, columnspan=2, padx=10, pady=10)
        self.sign_button = ttk.Button(self.main_frame, text="Sign File", command=self.sign_file)
        self.sign_button.grid(row=17, column=0, padx=10, pady=10)
        self.verify_button = ttk.Button(self.main_frame, text="Verify Signature", command=self.verify_signature)
        self.verify_button.grid(row=17, column=1, padx=10, pady=10)

        # Key management
        self.key_management_label = ttk.Label(self.main_frame, text="Key Management:", font=("Arial", 10))
        self.key_management_label.grid(row=18, column=0, padx=10, pady=10, sticky="w")
        self.generate_keys_button = ttk.Button(self.main_frame, text="Generate Keys", command=self.generate_keys)
        self.generate_keys_button.grid(row=18, column=1, padx=10, pady=10)
        self.export_keys_button = ttk.Button(self.main_frame, text="Export Keys", command=self.export_keys)
        self.export_keys_button.grid(row=18, column=2, padx=10, pady=10)
        self.import_keys_button = ttk.Button(self.main_frame, text="Import Keys", command=self.import_keys)
        self.import_keys_button.grid(row=19, column=1, padx=10, pady=10)

        # Multi-file support
        self.multi_file_label = ttk.Label(self.main_frame, text="Multi-File Support:", font=("Arial", 10))
        self.multi_file_label.grid(row=20, column=0, padx=10, pady=10, sticky="w")
        self.batch_encrypt_button = ttk.Button(self.main_frame, text="Batch Encrypt", command=self.start_batch_encryption)
        self.batch_encrypt_button.grid(row=20, column=1, padx=10, pady=10)
        self.batch_decrypt_button = ttk.Button(self.main_frame, text="Batch Decrypt", command=self.start_batch_decryption)
        self.batch_decrypt_button.grid(row=20, column=2, padx=10, pady=10)

        # Tooltips
        self.add_tooltips()

        # RSA key pair
        self.private_key, self.public_key = generate_rsa_key_pair()

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.theme = {
                "bg": "#2d2d2d",  # Dark gray background
                "fg": "#000000",  # White text
                "button_bg": "#3d3d3d",  # Slightly lighter gray for buttons
                "text_bg": "#808080",  # Darker gray for text area
                "text_fg": "#000000",  # White text in text area
                "progress_bg": "#0078d7",  # Blue progress bar
            }
        else:
            self.theme = {
                "bg": "#f0f0f0",  # Light gray background
                "fg": "#000000",  # Black text
                "button_bg": "#e0e0e0",  # Light gray for buttons
                "text_bg": "#ffffff",  # White background for text area
                "text_fg": "#000000",  # Black text in text area
                "progress_bg": "#0078d7",  # Blue progress bar
            }
        self.apply_theme()

    def apply_theme(self):
        # Update ttk styles
        self.style.configure("TFrame", background=self.theme["bg"])
        self.style.configure("TLabel", background=self.theme["bg"], foreground=self.theme["fg"])
        self.style.configure("TButton", background=self.theme["button_bg"], foreground=self.theme["fg"])
        self.style.configure("TEntry", background=self.theme["text_bg"], foreground=self.theme["text_fg"])
        self.style.configure("Horizontal.TProgressbar", background=self.theme["progress_bg"])

        # Update non-ttk widgets
        self.root.configure(bg=self.theme["bg"])
        self.preview_text.configure(bg=self.theme["text_bg"], fg=self.theme["text_fg"])

        # Update status label color
        self.status_label.configure(foreground="blue" if not self.dark_mode else "cyan")

    def browse_input_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_file_entry.delete(0, tk.END)
            self.input_file_entry.insert(0, file_path)
            self.preview_file(file_path)

    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename()
        if file_path:
            self.output_file_entry.delete(0, tk.END)
            self.output_file_entry.insert(0, file_path)

    def preview_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read(500)  # Preview first 500 bytes
                self.preview_text.delete(1.0, tk.END)
                self.preview_text.insert(tk.END, content.decode("utf-8", errors="replace"))
        except Exception as e:
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, "Unable to preview file.")

    def load_more_preview(self):
        file_path = self.input_file_entry.get()
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    f.seek(self.preview_text.index(tk.END).split(".")[0])
                    content = f.read(500)  # Load next 500 bytes
                    self.preview_text.insert(tk.END, content.decode("utf-8", errors="replace"))
            except Exception as e:
                self.preview_text.insert(tk.END, "\nUnable to load more content.")

    def compute_hash(self):
        file_path = self.input_file_entry.get()
        if file_path:
            file_hash = compute_file_hash(file_path)
            self.hash_entry.configure(state="normal")
            self.hash_entry.delete(0, tk.END)
            self.hash_entry.insert(0, file_hash)
            self.hash_entry.configure(state="readonly")
            self.status_label.config(text="File hash computed.", foreground="green")
        else:
            self.status_label.config(text="Please select a file.", foreground="red")

    def compare_hash(self):
        file_path = self.input_file_entry.get()
        compare_hash = self.compare_hash_entry.get()
        if file_path and compare_hash:
            file_hash = compute_file_hash(file_path)
            if file_hash == compare_hash:
                self.status_label.config(text="Hashes match!", foreground="green")
            else:
                self.status_label.config(text="Hashes do not match.", foreground="red")
        else:
            self.status_label.config(text="Please select a file and provide a hash.", foreground="red")

    def sign_file(self):
        file_path = self.input_file_entry.get()
        if file_path:
            signature = sign_file(file_path, self.private_key)
            self.signature_entry.configure(state="normal")
            self.signature_entry.delete(0, tk.END)
            self.signature_entry.insert(0, signature.hex())
            self.signature_entry.configure(state="readonly")
            self.status_label.config(text="File signed successfully.", foreground="green")
        else:
            self.status_label.config(text="Please select a file.", foreground="red")

    def verify_signature(self):
        file_path = self.input_file_entry.get()
        signature_hex = self.signature_entry.get()
        if file_path and signature_hex:
            signature = bytes.fromhex(signature_hex)
            if verify_signature(file_path, signature, self.public_key):
                self.status_label.config(text="Signature is valid.", foreground="green")
            else:
                self.status_label.config(text="Signature is invalid.", foreground="red")
        else:
            self.status_label.config(text="Please select a file and provide a signature.", foreground="red")

    def generate_keys(self):
        self.private_key, self.public_key = generate_rsa_key_pair()
        messagebox.showinfo("Key Generation", "New RSA key pair generated successfully.")

    def export_keys(self):
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_file = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        if private_key_file:
            with open(private_key_file, "wb") as f:
                f.write(private_key_pem)
        public_key_file = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        if public_key_file:
            with open(public_key_file, "wb") as f:
                f.write(public_key_pem)
        messagebox.showinfo("Export Keys", "Keys exported successfully.")

    def import_keys(self):
        private_key_file = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if private_key_file:
            with open(private_key_file, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        public_key_file = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if public_key_file:
            with open(public_key_file, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        messagebox.showinfo("Import Keys", "Keys imported successfully.")

    def start_batch_encryption(self):
        files = filedialog.askopenfilenames()
        if files:
            output_dir = filedialog.askdirectory()
            if output_dir:
                threading.Thread(target=self.batch_encrypt, args=(files, self.password_entry.get(), output_dir), daemon=True).start()

    def batch_encrypt(self, files, password, output_dir):
        for file in files:
            output_file = os.path.join(output_dir, os.path.basename(file) + ".enc")
            if encrypt_file(file, output_file, password, self.algorithm_var.get(), self.mode_var.get()):
                self.status_label.config(text=f"Encrypted {os.path.basename(file)}", foreground="green")
            else:
                self.status_label.config(text=f"Failed to encrypt {os.path.basename(file)}", foreground="red")
        self.status_label.config(text="Batch encryption complete.", foreground="blue")

    def start_batch_decryption(self):
        files = filedialog.askopenfilenames()
        if files:
            output_dir = filedialog.askdirectory()
            if output_dir:
                threading.Thread(target=self.batch_decrypt, args=(files, self.password_entry.get(), output_dir), daemon=True).start()

    def batch_decrypt(self, files, password, output_dir):
        for file in files:
            output_file = os.path.join(output_dir, os.path.basename(file).replace(".enc", ""))
            if decrypt_file(file, output_file, password, self.algorithm_var.get(), self.mode_var.get()):
                self.status_label.config(text=f"Decrypted {os.path.basename(file)}", foreground="green")
            else:
                self.status_label.config(text=f"Failed to decrypt {os.path.basename(file)}", foreground="red")
        self.status_label.config(text="Batch decryption complete.", foreground="blue")

    def start_encryption(self):
        input_file = self.input_file_entry.get()
        output_file = self.output_file_entry.get()
        password = self.password_entry.get()

        if not input_file or not output_file or not password:
            self.status_label.config(text="Please fill all fields.", foreground="red")
            return

        self.progress["value"] = 0
        self.status_label.config(text="Encrypting...", foreground="blue")
        self.root.update_idletasks()

        def progress_callback(value):
            self.progress["value"] = value
            self.root.update_idletasks()

        if encrypt_file(input_file, output_file, password, self.algorithm_var.get(), self.mode_var.get(), progress_callback):
            self.status_label.config(text="Encryption successful!", foreground="green")
        else:
            self.status_label.config(text="Encryption failed. Check the input file and password.", foreground="red")

    def start_decryption(self):
        input_file = self.input_file_entry.get()
        output_file = self.output_file_entry.get()
        password = self.password_entry.get()

        if not input_file or not output_file or not password:
            self.status_label.config(text="Please fill all fields.", foreground="red")
            return

        self.progress["value"] = 0
        self.status_label.config(text="Decrypting...", foreground="blue")
        self.root.update_idletasks()

        def progress_callback(value):
            self.progress["value"] = value
            self.root.update_idletasks()

        if decrypt_file(input_file, output_file, password, self.algorithm_var.get(), self.mode_var.get(), progress_callback):
            self.status_label.config(text="Decryption successful!", foreground="green")
        else:
            self.status_label.config(text="Decryption failed. Invalid password or file.", foreground="red")

    def clear_fields(self):
        self.input_file_entry.delete(0, tk.END)
        self.output_file_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.preview_text.delete(1.0, tk.END)
        self.hash_entry.configure(state="normal")
        self.hash_entry.delete(0, tk.END)
        self.hash_entry.configure(state="readonly")
        self.signature_entry.configure(state="normal")
        self.signature_entry.delete(0, tk.END)
        self.signature_entry.configure(state="readonly")
        self.compare_hash_entry.delete(0, tk.END)
        self.progress["value"] = 0
        self.status_label.config(text="Ready", foreground="blue")

    def add_tooltips(self):
        tooltips = {
            self.input_file_button: "Select the input file to encrypt/decrypt.",
            self.output_file_button: "Specify the output file path.",
            self.password_entry: "Enter a strong password for encryption/decryption.",
            self.encrypt_button: "Encrypt the selected file.",
            self.decrypt_button: "Decrypt the selected file.",
            self.clear_button: "Clear all input fields.",
            self.load_more_button: "Load more content from the file.",
            self.compute_hash_button: "Compute the SHA-256 hash of the selected file.",
            self.compare_hash_button: "Compare the hash of the selected file with another hash.",
            self.sign_button: "Sign the selected file using RSA.",
            self.verify_button: "Verify the digital signature of the selected file.",
            self.generate_keys_button: "Generate a new RSA key pair.",
            self.export_keys_button: "Export the current RSA key pair to files.",
            self.import_keys_button: "Import an RSA key pair from files.",
            self.batch_encrypt_button: "Encrypt multiple files at once.",
            self.batch_decrypt_button: "Decrypt multiple files at once.",
        }
        for widget, text in tooltips.items():
            self.create_tooltip(widget, text)

    def create_tooltip(self, widget, text):
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry("+0+0")
        label = ttk.Label(tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack()

        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            tooltip.wm_geometry(f"+{x}+{y}")
            tooltip.deiconify()

        def leave(event):
            tooltip.withdraw()

        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
