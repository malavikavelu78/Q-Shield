# Q-Shield: Hybrid Post-Quantum Cryptographic Suite

**Q-Shield** is a next-generation security application designed to mitigate the risks posed by **Cryptographically Relevant Quantum Computers (CRQC)**. By implementing **NIST-standardized Post-Quantum Cryptography (PQC)** algorithms within a hybrid framework, Q-Shield ensures data remains secure against both classical and quantum-era attacks.

---

## Executive Summary
Traditional encryption methods like RSA and ECC are vulnerable to **Shor's Algorithm**, which can crack them in polynomial time using a quantum computer. **Q-Shield** transitions security to **Lattice-based Cryptography**, specifically following the **FIPS 203 (ML-KEM)** and **FIPS 204 (ML-DSA)** standards to provide a future-proof encryption ecosystem.

---

## Technical Architecture & Approach

### 1. Key Encapsulation Mechanism (ML-KEM / Kyber)
The core of Q-Shield's key exchange relies on **Module-Lattice-based Key-Encapsulation**.
* **Mathematical Hardness:** Based on the **Learning With Errors (LWE)** problem over module lattices.
* **Functionality:** Securely generates and exchanges a 256-bit shared secret key between two entities without direct transmission of the key itself.



### 2. Digital Signature Algorithm (ML-DSA / Dilithium)
To ensure **Authenticity** and **Non-repudiation**, the system utilizes the Dilithium algorithm.
* **Mechanism:** Employs the **Fiat-Shamir with Aborts** technique to generate compact and secure digital signatures.
* **Integrity:** Every encrypted message is signed; any tampering with the ciphertext will result in a signature verification failure.

### 3. The Hybrid Encryption Model
Q-Shield follows a practical **Hybrid Logic**:
* **Layer 1 (PQC):** Uses Kyber to protect the session key from quantum decryption.
* **Layer 2 (Symmetric):** Uses the PQC-protected key to encrypt bulk data via a high-speed symmetric cipher (simulated with SHA-3/AES logic).
* **Layer 3 (Hashing):** Uses **SHA-3 (Keccak)** for high-security message digesting and randomness generation.



---

## System Workflow
1. **Entropy Collection:** Uses CSPRNG to generate high-quality random seeds.
2. **Key Exchange:** Initiates ML-KEM to establish a quantum-safe shared secret.
3. **Encryption & Signing:** The plaintext message is encrypted using the shared secret and signed with a Dilithium private key.
4. **Verification & Decryption:** The receiver validates the signature before decapsulating the key to retrieve the original plaintext.

---

## Performance Benchmarking
Q-Shield includes a built-in analysis module to evaluate:
* **Execution Latency:** Measured in milliseconds (ms) to show the efficiency of lattice-based math.
* **Key Size Trade-offs:** Comparison graphs between Classical RSA (2048/3072 bit) and NIST PQC levels (512/768/1024).

---

## Tech Stack
* **Language:** Python 3.13+
* **UI Framework:** Tkinter (Desktop GUI)
* **Core Libraries:** `hashlib` (SHA-3), `secrets` (Cryptographic randomness), `time` (Performance tracking)
