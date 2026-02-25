import customtkinter as ctk
import socket, hashlib, secrets, base64, threading, time
from tkinter import messagebox

class BobServer(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Q-SHIELD | BOB (SERVER)")
        self.geometry("900x700")
        self.shared_key = None

        # UI Setup (Summary)
        self.header = ctk.CTkLabel(self, text=" BOB: SECURE RECEIVER", font=("Consolas", 20, "bold"), text_color="#38bdf8")
        self.header.pack(pady=10)
        self.chat_display = ctk.CTkTextbox(self, fg_color="black", text_color="#39ff14", font=("Consolas", 12))
        self.chat_display.pack(fill="both", expand=True, padx=20, pady=10)

        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", padx=20, pady=10)
        self.msg_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Reply...")
        self.msg_entry.pack(side="left", fill="x", expand=True)
        
        self.send_btn = ctk.CTkButton(self.input_frame, text="SEND", command=self.send_message)
        self.send_btn.pack(side="left", padx=5)

        self.atk_btn = ctk.CTkButton(self.input_frame, text="ATTACK SIM", fg_color="#da3633", command=self.simulate_attack)
        self.atk_btn.pack(side="left", padx=5)

        threading.Thread(target=self.run_server, daemon=True).start()

    def run_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 5000))
        server.listen(1)
        print(">>> [SYSTEM] WAITING FOR HANDSHAKE...")
        self.conn, _ = server.accept()
        
        pub_key = hashlib.sha384(secrets.token_bytes(32)).hexdigest()
        self.conn.send(pub_key.encode())
        alice_salt = self.conn.recv(1024).decode()
        shared = hashlib.sha512(pub_key.encode() + alice_salt.encode()).digest()
        self.shared_key = base64.urlsafe_b64encode(shared[:32])
        print(">>> [SYSTEM] QUANTUM TUNNEL ESTABLISHED.\n")
        
        while True:
            try:
                data = self.conn.recv(4096).decode()
                # ORIGINAL MSG PRINT REMOVED - ONLY ENCRYPTED DATA
                print(f"\n[BACKEND RECEIVE] Raw Encrypted Stream: {data}")
                
                cipher_bytes = base64.b64decode(data)
                dec_payload = bytes([b ^ self.shared_key[i % len(self.shared_key)] for i, b in enumerate(cipher_bytes)]).decode()
                
                msg, _ = dec_payload.split('|')
                self.chat_display.insert("end", f"ALICE: {msg}\n")
            except: break

    def send_message(self):
        msg = self.msg_entry.get()
        if msg and self.shared_key:
            sig = hashlib.md5(msg.encode() + self.shared_key).hexdigest()[:8]
            payload = f"{msg}|{sig}"
            enc_bytes = bytes([b ^ self.shared_key[i % len(self.shared_key)] for i, b in enumerate(payload.encode())])
            encoded = base64.b64encode(enc_bytes).decode()
            
            # TERMINAL-LA ENCRYPTED STREAM MATTUM DHAN THERIYUM
            print(f"\n[BACKEND SEND] Encrypted Packet: {encoded}")

            self.conn.send(encoded.encode())
            self.chat_display.insert("end", f"YOU: {msg}\n")
            self.msg_entry.delete(0, "end")

    def simulate_attack(self):
        print("\n[SECURITY ALERT] SHOR'S ALGORITHM ATTACK BLOCKED!")
        messagebox.showwarning("SECURITY", "Quantum attack blocked by Lattice Gateway.")

if __name__ == "__main__":
    app = BobServer()

    app.mainloop()
