# Q-SHIELD: Secure Chat Application

This project is a secure messaging prototype demonstrating an encrypted communication channel between two parties, referred to as Alice (Client) and Bob (Server). Built using Python and CustomTkinter, it focuses on simulating a secure handshake and encrypted data transmission over TCP sockets.

## Project Overview

The main goal of Q-SHIELD is to visualize how secure data transmission works behind the scenes. While the graphical interface shows the readable messages, the terminal logs reveal the actual encrypted "cipher" text being sent over the network. This demonstrates that even if a third party intercepts the data, they cannot read the content without the shared key.

## Features

- **Socket Networking:** Uses Python's built-in socket library to establish a TCP connection between localhost ports.
- **Custom Encryption Handshake:** Implements a dynamic key exchange mechanism using hashing (SHA-512) and random salt generation.
- **XOR Encryption:** Messages are encrypted using a custom XOR cipher based on the generated shared key.
- **GUI Interface:** A dark-mode, modern user interface built with CustomTkinter for a better user experience.
- **Traffic Monitoring:** The backend terminal prints the raw encrypted packets, allowing developers to verify that data is obfuscated during transit.
- **Attack Simulation:** Includes a demonstration feature on the server side to simulate the blocking of a brute-force or quantum attack.

## Technical Details

The application consists of two main scripts:

1. **Bob (Server):** 
   - Listens for incoming connections.
   - Generates a public key and waits for the handshake.
   - acts as the receiver and can reply to messages.

2. **Alice (Client):** 
   - Connects to the server.
   - Initiates the handshake by sending a salt.
   - Generates the shared secret key locally.

### How the Security Works

1. **Handshake:** When Alice connects to Bob, Bob sends a public key. Alice generates a random "salt" and sends it back. Both parties combine these values and hash them to create a symmetrical `shared_key`.
2. **Encryption:** When a message is sent, the text is combined with a signature. Each byte of this payload is XOR-ed against the shared key.
3. **Encoding:** The encrypted bytes are Base64 encoded before being sent over the network to ensure safe transport.
4. **Decryption:** The receiver reverses the process using the same shared key to reveal the original message.

## Prerequisites

To run this project, you need Python installed on your machine. You also need to install the `customtkinter` library.

You can install the dependency using pip:

pip install customtkinter

## How to Run

Since this is a client-server application, you must run the scripts in a specific order.

1. **Start the Server (Bob)**
   Open your terminal and run the Bob script first. This sets up the listener.
   
   python bob_server.py

2. **Start the Client (Alice)**
   Open a new terminal window and run the Alice script.
   
   python alice_client.py

Once both windows are open, you can type messages in the input field and click "Send". Check your terminal windows to see the encrypted data logs appearing in real-time.

## Disclaimer

This project is created for educational purposes to demonstrate the concepts of socket programming, hashing, and basic encryption algorithms. While it implements security concepts, it is a prototype and not intended for use as a production-grade cryptographic tool.

## License

This project is open-source and available for educational use.
