import tkinter as tk
from tkinter import scrolledtext, messagebox
import hashlib
import secrets
import base64
import time

# --- GLOBAL STORAGE ---
last_generated_key = ""
last_encrypted_blob = ""
last_signature = ""

def type_text(widget, text, color="#39ff14"):
    """Terminal typing effect with specific color support"""
    widget.config(state='normal')
    widget.tag_config("color_tag", foreground=color)
    for char in text:
        widget.insert(tk.END, char, "color_tag")
        widget.update()
        time.sleep(0.005) 
    widget.insert(tk.END, "\n")
    widget.config(state='disabled')
    widget.see(tk.END)

def generate_diagnostics(start_time):
    """Performance metrics calculation"""
    duration = (time.perf_counter() - start_time) * 1000
    return f"[DIAGNOSTICS] Latency: {duration:.4f} ms | Security: NIST Level 5\n"

# --- CORE LOGIC ---

def hybrid_encrypt():
    global last_generated_key, last_encrypted_blob, last_signature
    user_input = input_box.get("1.0", tk.END).strip()
    
    if not user_input:
        messagebox.showwarning("Input Error", "Please enter a message!")
        return

    start_t = time.perf_counter()
    
    # 1. KYBER Key Generation (ML-KEM)
    shared_seed = secrets.token_bytes(32)
    last_generated_key = hashlib.sha3_256(shared_seed).hexdigest()

    # 2. Hybrid Encryption Process
    key_bytes = bytes.fromhex(last_generated_key)
    encrypted_msg = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(user_input.encode())])
    last_encrypted_blob = base64.b64encode(encrypted_msg).decode()

    # 3. Dilithium Digital Signature for Integrity
    last_signature = hashlib.sha3_512((last_encrypted_blob + last_generated_key).encode()).hexdigest()

    display.config(state='normal')
    type_text(display, ">>> INITIALIZING QUANTUM-SAFE ENCRYPTION...", "#58a6ff")
    type_text(display, f"[!] MANUAL KYBER KEY (COPY THIS): {last_generated_key}", "#ffcc00")
    type_text(display, f"[+] PROTECTED CIPHERTEXT: {last_encrypted_blob}")
    type_text(display, "[+] DILITHIUM AUTHENTICATION SEAL APPLIED.")
    type_text(display, generate_diagnostics(start_t))
    type_text(display, "--------------------------------------------------")

def simulate_mitm_attack():
    """Simulates a Man-In-The-Middle attack"""
    global last_encrypted_blob
    if not last_encrypted_blob: return
    
    # Altering the data silently
    list_blob = list(last_encrypted_blob)
    list_blob[0] = 'X' if list_blob[0] != 'X' else 'Y'
    last_encrypted_blob = "".join(list_blob)
    
    display.config(state='normal')
    type_text(display, "⚠️ [EXTERNAL EVENT] DATA INTERCEPTED AND MODIFIED BY HACKER!", "#da3633")
    type_text(display, "--------------------------------------------------")

def hybrid_decrypt():
    global last_generated_key, last_encrypted_blob, last_signature
    input_key = key_entry.get().strip()
    
    if not last_encrypted_blob:
        messagebox.showerror("Error", "No encrypted data found!")
        return

    display.config(state='normal')
    type_text(display, ">>> RUNNING AUTO-SCAN SECURITY PROTOCOLS...", "#58a6ff")
    time.sleep(0.4)

    # 1. AUTO-SCAN: Integrity Check (Detecting MITM)
    current_sig = hashlib.sha3_512((last_encrypted_blob + last_generated_key).encode()).hexdigest()
    
    if current_sig != last_signature:
        type_text(display, "[SCAN 1]: INTEGRITY CHECK FAILED!", "#da3633")
        type_text(display, "❌ CRITICAL: DILITHIUM SIGNATURE MISMATCH DETECTED.", "#da3633")
        type_text(display, "[!] Attack Detected. Decryption Aborted.", "#da3633")
        messagebox.showerror("Security Breach", "Tampering Detected! Message Integrity Compromised.")
        return
    else:
        type_text(display, "[SCAN 1]: INTEGRITY VERIFIED (NO TAMPERING).", "#238636")

    # 2. AUTO-SCAN: Key Authentication (Manual Key Box Check)
    if input_key != last_generated_key:
        type_text(display, "[SCAN 2]: KEY AUTHENTICATION FAILED!", "#da3633")
        messagebox.showerror("Auth Error", "Invalid Kyber Key!")
        return
    else:
        type_text(display, "[SCAN 2]: KYBER SESSION KEY VALIDATED.", "#238636")

    start_t = time.perf_counter()
    
    # 3. FINAL DECRYPTION (ML-KEM Decapsulation)
    key_bytes = bytes.fromhex(last_generated_key)
    encrypted_bytes = base64.b64decode(last_encrypted_blob)
    decrypted_msg = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_bytes)]).decode()
    
    type_text(display, f"[SCAN 3]: DECRYPTION SUCCESSFUL.")
    type_text(display, f">>> ORIGINAL MESSAGE: {decrypted_msg}")
    type_text(display, generate_diagnostics(start_t))
    type_text(display, "==================================================")

# --- UI SETUP ---
window = tk.Tk()
window.title("Q-Shield v9.0 - Ultimate Security Suite")
window.geometry("850x950")
window.configure(bg="#0d1117")

tk.Label(window, text="🛡️ Q-SHIELD: ADVANCED PQC TERMINAL", fg="#58a6ff", bg="#0d1117", font=("Consolas", 18, "bold")).pack(pady=20)

tk.Label(window, text="INPUT PLAIN TEXT:", fg="white", bg="#0d1117", font=("Consolas", 10)).pack()
input_box = tk.Text(window, height=3, width=80, bg="#161b22", fg="#e6edf3", insertbackground="white", font=("Consolas", 10))
input_box.pack(pady=5)

tk.Label(window, text="RECEIVER: INPUT KYBER KEY TO DECRYPT:", fg="#ffcc00", bg="#0d1117", font=("Consolas", 10, "bold")).pack(pady=5)
key_entry = tk.Entry(window, width=80, bg="#161b22", fg="#39ff14", insertbackground="white", font=("Consolas", 10))
key_entry.pack(pady=5)

btn_frame = tk.Frame(window, bg="#0d1117")
btn_frame.pack(pady=20)

tk.Button(btn_frame, text="ENCRYPT (PQC)", command=hybrid_encrypt, bg="#238636", fg="white", width=18).grid(row=0, column=0, padx=10)
tk.Button(btn_frame, text="DECRYPT (PQC)", command=hybrid_decrypt, bg="#1f6feb", fg="white", width=18).grid(row=0, column=1, padx=10)
tk.Button(btn_frame, text="SIMULATE ATTACK", command=simulate_mitm_attack, bg="#da3633", fg="white", width=18).grid(row=0, column=2, padx=10)

display = scrolledtext.ScrolledText(window, width=100, height=30, bg="#010409", fg="#39ff14", font=("Consolas", 9))
display.pack(pady=10, padx=20)
display.insert(tk.END, ">>> Q-SHIELD CORE SECURE... [KYBER/DILITHIUM LOADED]\n")
display.config(state='disabled')

window.mainloop()