# 🛡️ Assignment: Secure Messaging with Forward Secrecy

## 📚 Overview

In this assignment, you will implement a **secure messaging application** between two parties using modern cryptographic techniques inspired by protocols like **Signal** and **TLS**. Your application will support:

- **Key exchange** using ECDH
- **Authenticated encryption** using AES-GCM
- **Forward secrecy** via ephemeral key ratcheting

This assignment is designed to give you hands-on experience with practical cryptography and to deepen your understanding of secure communications protocols.

---

## 🎯 Learning Objectives

By completing this assignment, you will:

- Understand the use of **Elliptic-Curve Diffie–Hellman (ECDH)** for key exchange
- Apply **HKDF** to derive symmetric session keys
- Use **AES-GCM** for authenticated encryption (confidentiality + integrity)
- Demonstrate **forward secrecy** by rotating ephemeral key material
- Document and explain the cryptographic protocol flow

---

## 📦 Starter Code

You are provided with a skeleton Python file: `secure_chat.py`

It includes:

- Basic key generation and exchange functions
- Serialization utilities
- A minimal class-based simulation of two chat participants
- An encryption scheme using AES-GCM

---

## 🛠️ Your Tasks

### ✅ 1. Understand and Complete Key Exchange

- Read and understand the `generate_ecdh_key_pair`, `derive_shared_secret`, and `hkdf_expand` functions.
- Use ECDH to securely agree on a shared secret between two parties (Alice and Bob).
- Derive a session key from the shared secret using HKDF.

### ✅ 2. Implement Authenticated Encryption

- Use **AES-GCM** to encrypt and authenticate messages between parties.
- Encrypt outgoing messages with the current session key.
- Decrypt incoming messages and verify their integrity.

### ✅ 3. Add Forward Secrecy

- Implement **ephemeral key rotation**:
  - After each message (or every N messages), regenerate ephemeral ECDH keys.
  - Derive a new session key from the new shared secret.
- Demonstrate in your simulation that prior session keys are no longer used once keys are rotated.

### ✅ 4. Document the Protocol

Write a short (1–2 page) document or markdown file `protocol.md` including:

- A description of your protocol flow
- The cryptographic primitives used
- How forward secrecy is achieved
- A discussion of the **security goals**: confidentiality, integrity, and forward secrecy
- Limitations or assumptions (e.g., no authentication, simple in-memory simulation)

---

## 🚀 Extension (Optional Challenge)

Implement a **simple networking layer** using `socket`, `Flask`, or any async framework so that Alice and Bob can run in separate processes or machines. You could use:

- TCP sockets for raw message exchange
- Flask or FastAPI for HTTP-based message send/receive

This is optional but highly encouraged if you’re curious about real-world applications.

---

## 📤 Submission Instructions

You should submit:

1. `secure_chat.py` – your main implementation file  
2. `protocol.md` – your documentation of the protocol  
3. (Optional) `networking/` – any extra files for the extended version  
4. A short transcript or screenshot of your working chat simulation (e.g., via `simulate_chat()`)

---

## 🧪 Example Output

```
Session key established.

Alice sends: {"nonce": "...", "ciphertext": "..."}
Bob receives: Hello Bob!

Alice sends (new keys): {"nonce": "...", "ciphertext": "..."}
Bob receives: New key, still secure!
```


---

## 🧾 Grading Criteria

| Criteria                                  | Points |
|-------------------------------------------|--------|
| Key generation and exchange (ECDH)        | 20     |
| AES-GCM encryption/decryption             | 20     |
| Forward secrecy implementation            | 20     |
| Protocol documentation                    | 20     |
| Correct simulation of message exchange    | 10     |
| Code style and clarity                    | 10     |
| **Bonus**: Networking extension           | +10    |

---

## 📎 Resources

- [Elliptic Curve Cryptography (NIST Guide)](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
- [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [`cryptography` Python library docs](https://cryptography.io/en/latest/)
- [Signal Protocol Overview](https://signal.org/docs/)

