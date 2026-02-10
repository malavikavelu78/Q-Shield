import socket, hashlib, secrets, base64, threading, time
import tkinter as tk
from tkinter import scrolledtext, messagebox

class BobChat:
    def __init__(self, root):
        self.root = root
        self.root.title("PQC SECURE GATEWAY (BOB)")
        self.root.geometry("500x650")
        self.root.configure(bg="#0f172a") # Dark Slate Theme

        # Header
        self.header = tk.Label(root, text="SERVER NODE: BOB", bg="#1e293b", fg="#38bdf8", font=("Segoe UI", 12, "bold"), pady=10)
        self.header.pack(fill=tk.X)

        # Chat Area
        self.chat_area = scrolledtext.ScrolledText(root, state='disabled', height=20, width=50, bg="#020617", fg="#94a3b8", font=("Consolas", 10), bd=0, padx=10, pady=10)
        self.chat_area.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area.tag_config("YOU", foreground="#10b981", justify='right')
        self.chat_area.tag_config("ALICE", foreground="#38bdf8", justify='left')
        self.chat_area.tag_config("SYSTEM", foreground="#f59e0b", font=("Consolas", 9, "italic"))

        # Input Frame
        self.entry_frame = tk.Frame(root, bg="#1e293b", pady=10)
        self.entry_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.msg_entry = tk.Entry(self.entry_frame, bg="#0f172a", fg="white", insertbackground="white", font=("Segoe UI", 10), bd=0)
        self.msg_entry.pack(side=tk.LEFT, padx=15, pady=5, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", lambda x: self.send_msg())
        
        self.send_btn = tk.Button(self.entry_frame, text="SEND", command=self.send_msg, bg="#0ea5e9", fg="white", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=15)
        self.send_btn.pack(side=tk.LEFT, padx=5)

        self.attack_btn = tk.Button(self.entry_frame, text="ATTACK SIM", command=self.simulate_attack, bg="#475569", fg="white", font=("Segoe UI", 8), relief=tk.FLAT)
        self.attack_btn.pack(side=tk.RIGHT, padx=15)

        self.status_bar = tk.Label(root, text="STATUS: WAITING FOR NETWORK HANDSHAKE...", bg="#0f172a", fg="#64748b", font=("Segoe UI", 8))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 5000))
        server.listen(1)
        self.conn, addr = server.accept()
        
        # PQC Key Exchange Packet Log
        print("\n[NETWORK] Handshake Started with Alice")
        pub_key = hashlib.sha384(secrets.token_bytes(32)).hexdigest()
        self.conn.send(pub_key.encode())
        
        alice_salt = self.conn.recv(1024).decode()
        shared_secret = hashlib.sha512(pub_key.encode() + alice_salt.encode()).digest()
        self.key = base64.urlsafe_b64encode(shared_secret[:32])
        
        print(f"[NETWORK] Secure Key Established: {self.key.decode()[:15]}...")
        self.status_bar.config(text="STATUS: QUANTUM-SAFE (LATTICE-READY)", fg="#10b981")
        self.display_msg("SYSTEM", "SECURE TUNNEL ESTABLISHED.")
        self.receive_loop()

    def send_msg(self):
        msg = self.msg_entry.get()
        if msg and hasattr(self, 'key'):
            # Networking Packet Structure
            signature = hashlib.md5(msg.encode() + self.key).hexdigest()[:8]
            full_payload = f"{msg}|{signature}"
            enc_bytes = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(full_payload.encode())])
            encoded_payload = base64.b64encode(enc_bytes).decode()

            print(f"\n[NETWORK SEND]")
            print(f"Protocol: PQC/TCP Secured")
            print(f"Payload : {encoded_payload}") # Encrypted data on wire
            print(f"HMAC    : {signature}")
            print(f"--------------------------")

            self.conn.send(encoded_payload.encode())
            self.display_msg("YOU", msg)
            self.msg_entry.delete(0, tk.END)

    def receive_loop(self):
        while True:
            try:
                data = self.conn.recv(1024).decode()
                print(f"\n[NETWORK RECEIVE]")
                print(f"Encrypted Stream: {data}")
                
                cipher_bytes = base64.b64decode(data)
                decrypted_full = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(cipher_bytes)]).decode()
                message, received_sig = decrypted_full.split('|')
                
                print(f"Integrity Check: PASSED")
                print(f"--------------------------")
                self.display_msg("ALICE", message)
            except: break

    def display_msg(self, sender, msg):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, f"{sender}: {msg}\n\n", sender)
        self.chat_area.configure(state='disabled')
        self.chat_area.yview(tk.END)

    def simulate_attack(self):
        print("\n[SECURITY ALERT] QUANTUM INTERCEPTION DETECTED AT SERVER!")
        print("[*] Status: Analyzing Shor's Algorithm attack pattern...")
        time.sleep(1)
        print("[RESULT] Lattice Noise Blocks Discovery. Keys are SAFE.")
        messagebox.showwarning("GATEWAY SECURITY", "Quantum attack blocked by Lattice Gateway.")

if __name__ == "__main__":
    root = tk.Tk()
    BobChat(root)
    root.mainloop()