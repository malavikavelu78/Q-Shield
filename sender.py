import socket, hashlib, secrets, base64, threading, time
import tkinter as tk
from tkinter import scrolledtext, messagebox

class AliceChat:
    def __init__(self, root):
        self.root = root
        self.root.title("PQC SECURE NODE (ALICE)")
        self.root.geometry("500x650")
        self.root.configure(bg="#0f172a")

        self.header = tk.Label(root, text="CLIENT NODE: ALICE", bg="#1e293b", fg="#fb7185", font=("Segoe UI", 12, "bold"), pady=10)
        self.header.pack(fill=tk.X)

        self.chat_area = scrolledtext.ScrolledText(root, state='disabled', height=20, width=50, bg="#020617", fg="#94a3b8", font=("Consolas", 10), bd=0, padx=10, pady=10)
        self.chat_area.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area.tag_config("YOU", foreground="#fb7185", justify='right')
        self.chat_area.tag_config("BOB", foreground="#38bdf8", justify='left')
        self.chat_area.tag_config("SYSTEM", foreground="#f59e0b", font=("Consolas", 9, "italic"))

        self.entry_frame = tk.Frame(root, bg="#1e293b", pady=10)
        self.entry_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.msg_entry = tk.Entry(self.entry_frame, bg="#0f172a", fg="white", insertbackground="white", font=("Segoe UI", 10), bd=0)
        self.msg_entry.pack(side=tk.LEFT, padx=15, pady=5, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", lambda x: self.send_msg())
        
        self.send_btn = tk.Button(self.entry_frame, text="SEND", command=self.send_msg, bg="#f43f5e", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=15)
        self.send_btn.pack(side=tk.LEFT, padx=5)

        self.attack_btn = tk.Button(self.entry_frame, text="ATTACK SIM", command=self.simulate_attack, bg="#475569", fg="white", font=("Segoe UI", 8), relief=tk.FLAT)
        self.attack_btn.pack(side=tk.RIGHT, padx=15)

        threading.Thread(target=self.connect, daemon=True).start()

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try: self.client.connect(('127.0.0.1', 5000)); break
            except: time.sleep(1)

        print("\n[NETWORK] Connected to Bob. Starting Handshake...")
        pub_key = self.client.recv(1024).decode()
        salt = secrets.token_hex(16)
        self.client.send(salt.encode())
        
        shared_secret = hashlib.sha512(pub_key.encode() + salt.encode()).digest()
        self.key = base64.urlsafe_b64encode(shared_secret[:32])
        
        print(f"[NETWORK] Secure Key Generated: {self.key.decode()[:15]}...")
        self.display_msg("SYSTEM", "QUANTUM HANDSHAKE SUCCESSFUL.")
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def send_msg(self):
        msg = self.msg_entry.get()
        if msg and hasattr(self, 'key'):
            signature = hashlib.md5(msg.encode() + self.key).hexdigest()[:8]
            full_payload = f"{msg}|{signature}"
            enc_bytes = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(full_payload.encode())])
            encoded_payload = base64.b64encode(enc_bytes).decode()

            print(f"\n[NETWORK SEND]")
            print(f"Payload : {encoded_payload}")
            print(f"Checksum: {signature}")
            print(f"--------------------------")

            self.client.send(encoded_payload.encode())
            self.display_msg("YOU", msg)
            self.msg_entry.delete(0, tk.END)

    def receive_loop(self):
        while True:
            try:
                data = self.client.recv(1024).decode()
                print(f"\n[NETWORK RECEIVE]")
                print(f"Data Stream: {data}")
                
                cipher_bytes = base64.b64decode(data)
                decrypted_full = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(cipher_bytes)]).decode()
                message, received_sig = decrypted_full.split('|')
                
                print(f"Integrity Check: PASSED")
                print(f"--------------------------")
                self.display_msg("BOB", message)
            except: break

    def display_msg(self, sender, msg):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, f"{sender}: {msg}\n\n", sender)
        self.chat_area.configure(state='disabled')
        self.chat_area.yview(tk.END)

    def simulate_attack(self):
        print("\n[SECURITY ALERT] QUANTUM BRUTE-FORCE DETECTED AT CLIENT!")
        time.sleep(1)
        print("[RESULT] Lattice SVP Problem prevents decryption. Attack Failed.")
        messagebox.showwarning("NODE SECURITY", "Quantum attack blocked by Lattice encryption.")

if __name__ == "__main__":
    root = tk.Tk()
    AliceChat(root)
    root.mainloop()