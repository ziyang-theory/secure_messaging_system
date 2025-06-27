# This is the starter file for CSC 364 - Foundations of Computer Security 
# Project 1 - Secure Messaging System
# 
# In order to execute this file, you need to run the commands below to install
# the 'cryptography' python library:
#
# python3 -m venv path/to/venv
# source path/to/venv/bin/activate
# python3 -m pip install cryptography
#
# To run this file:
# python3 secure_chat_starter.py
#

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# --- Utilities (do not modify) ---
def generate_ecdh_key_pair():
    private = ec.generate_private_key(ec.SECP384R1())
    return private, private.public_key()

def derive_shared_secret(priv, pub):
    return priv.exchange(ec.ECDH(), pub)

def hkdf_expand(secret, info=b"ratchet"):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(secret)

def encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {"nonce": nonce, "ciphertext": ct}

def decrypt(key, msg):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(msg["nonce"], msg["ciphertext"], None).decode()

# --- Complete this class ---
class Party:
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = generate_ecdh_key_pair()
        self.session_key = None

    def establish_session(self, peer_public_key):
        # TODO: derive session key from peer_public_key
        pass

    def send(self, plaintext):
        # TODO: add ratcheting (if any), then encrypt
        pass

    def receive(self, msg):
        # TODO: decrypt then ratchet (if any)
        pass

# --- Demo usage ---
def simulate_chat():
    alice = Party("Alice")
    bob = Party("Bob")

    # TODO: exchange public keys and establish session

    # TODO: send and receive messages

if __name__ == "__main__":
    simulate_chat()
