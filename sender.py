import customtkinter as ctk
import socket, hashlib, secrets, base64, threading, time
from tkinter import messagebox

class AliceClient(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Q-SHIELD | ALICE (CLIENT)")
        self.geometry("900x700")
        self.shared_key = None

        self.header = ctk.CTkLabel(self, text="🛡️ ALICE: SECURE SENDER", font=("Consolas", 20, "bold"), text_color="#fb7185")
        self.header.pack(pady=10)
        self.chat_display = ctk.CTkTextbox(self, fg_color="black", text_color="#fb7185", font=("Consolas", 12))
        self.chat_display.pack(fill="both", expand=True, padx=20, pady=10)

        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", padx=20, pady=10)
        self.msg_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Message...")
        self.msg_entry.pack(side="left", fill="x", expand=True)
        
        self.send_btn = ctk.CTkButton(self.input_frame, text="SEND", command=self.send_message)
        self.send_btn.pack(side="left", padx=5)

        threading.Thread(target=self.connect_to_bob, daemon=True).start()

    def connect_to_bob(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.client.connect(('127.0.0.1', 5000))
                break
            except: time.sleep(1)
            
        pub_key = self.client.recv(1024).decode()
        salt = secrets.token_hex(16)
        self.client.send(salt.encode())
        shared = hashlib.sha512(pub_key.encode() + salt.encode()).digest()
        self.shared_key = base64.urlsafe_b64encode(shared[:32])
        print(">>> [SYSTEM] QUANTUM HANDSHAKE SUCCESSFUL.\n")
        
        while True:
            try:
                data = self.client.recv(4096).decode()
                # ONLY ENCRYPTED DATA IN TERMINAL
                print(f"\n[BACKEND RECEIVE] Encrypted Packet: {data}")
                
                cipher_bytes = base64.b64decode(data)
                dec_payload = bytes([b ^ self.shared_key[i % len(self.shared_key)] for i, b in enumerate(cipher_bytes)]).decode()
                self.chat_display.insert("end", f"BOB: {dec_payload.split('|')[0]}\n")
            except: break

    def send_message(self):
        msg = self.msg_entry.get()
        if msg and self.shared_key:
            sig = hashlib.md5(msg.encode() + self.shared_key).hexdigest()[:8]
            payload = f"{msg}|{sig}"
            enc_bytes = bytes([b ^ self.shared_key[i % len(self.shared_key)] for i, b in enumerate(payload.encode())])
            encoded = base64.b64encode(enc_bytes).decode()
            
            # ORIGINAL MESSAGE PRINT REMOVED
            print(f"\n[BACKEND SEND] Outgoing Cipher: {encoded}")

            self.client.send(encoded.encode())
            self.chat_display.insert("end", f"YOU: {msg}\n")
            self.msg_entry.delete(0, "end")

if __name__ == "__main__":
    app = AliceClient()
    app.mainloop()