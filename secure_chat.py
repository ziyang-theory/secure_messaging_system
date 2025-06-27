# This is the main file for CSC 364 - Foundations of Computer Security 
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
# python3 secure_chat.py
#

import os
import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------
# Key Generation and Utilities
# ------------------------------

# Can either use a Diffe-Hellman or the ECDH key exchange
def generate_dh_key_pair(parameters=None):
    """
    Generates a classic Diffie–Hellman key pair.
    
    If no parameters are provided, generates new parameters (safe but slower).
    In practice, parameters are agreed upon ahead of time.

    Returns: (private_key, public_key, parameters)
    """
    if parameters is None:
        # Generate DH parameters (shared primes, generator)
        # This is a slow operation; reuse in real applications.
        parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Generate the private/public key pair
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters

def generate_ecdh_key_pair():
    """
    Generates an ephemeral ECDH key pair.
    Returns: (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Serializes a public key to PEM format for sharing.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """
    Deserializes a PEM-formatted public key.
    """
    return serialization.load_pem_public_key(pem_bytes)

def derive_shared_secret(private_key, peer_public_key):
    """
    Computes the ECDH shared secret between private and peer public key.
    """
    return private_key.exchange(ec.ECDH(), peer_public_key)

def hkdf_expand(secret, info=b'secure chat'):
    """
    Derives a 256-bit symmetric key from a shared secret using HKDF.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    ).derive(secret)

def ratchet_key(old_key):
    """
    Derives a new session key from the previous key (symmetric ratcheting).
    """
    return hkdf_expand(old_key, info=b'ratchet-step')

# ------------------------------
# Encryption and Decryption
# ------------------------------

def encrypt_message(key, plaintext):
    """
    Encrypts a plaintext string using AES-GCM.
    Returns a dict with nonce and ciphertext (both hex-encoded).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {'nonce': nonce.hex(), 'ciphertext': ciphertext.hex()}

def decrypt_message(key, message):
    """
    Decrypts a message dictionary using AES-GCM.
    Raises an exception if decryption or authentication fails.
    """
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(message['nonce'])
    ciphertext = bytes.fromhex(message['ciphertext'])
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

# ------------------------------
# Party Class with Ratcheting
# ------------------------------

class Party:
    """
    Represents one chat participant (e.g., Alice or Bob),
    holding an ephemeral ECDH key pair and a ratcheting session key.
    """
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = generate_ecdh_key_pair()
        self.sending_key = None
        self.receiving_key = None

    def get_public_bytes(self):
        """
        Returns the PEM-encoded public key to send to the peer.
        """
        return serialize_public_key(self.public_key)

    def establish_session(self, peer_pub_bytes, role='initiator'):
        peer_public_key = deserialize_public_key(peer_pub_bytes)
        shared_secret = derive_shared_secret(self.private_key, peer_public_key)

        if role == 'initiator':
            self.sending_key = hkdf_expand(shared_secret, info=b'sending')
            self.receiving_key = hkdf_expand(shared_secret, info=b'receiving')
        else:
            self.sending_key = hkdf_expand(shared_secret, info=b'receiving')
            self.receiving_key = hkdf_expand(shared_secret, info=b'sending')

    def send(self, plaintext):
        """
        Ratchet the sending key first, then encrypt.
        """
        self.sending_key = ratchet_key(self.sending_key)
        encrypted = encrypt_message(self.sending_key, plaintext)
        return encrypted

    def receive(self, msg):
        """
        Ratchet receiving key before decryption, then decrypt.
        """
        self.receiving_key = ratchet_key(self.receiving_key)
        plaintext = decrypt_message(self.receiving_key, msg)
        return plaintext

# ------------------------------
# Simulated Chat Session
# ------------------------------

def simulate_chat():
    """
    Simulates a secure chat between Alice and Bob with key ratcheting.
    """

    # Step 1: Create Alice and Bob
    alice = Party("Alice")
    bob = Party("Bob")

    # Step 2: Key Exchange
    # Each party exchanges public keys and derives a shared session key
    alice.establish_session(bob.get_public_bytes(), role='initiator')
    bob.establish_session(alice.get_public_bytes(), role='responder')
    print("Session key established.\n")

    # Step 3: Alice sends a message to Bob
    # Her key is ratcheted after sending
    msg1 = "Hello Bob!"
    encrypted_msg1 = alice.send(msg1)
    print(f"Alice sends: {json.dumps(encrypted_msg1)}")

    # Bob receives and decrypts; his key is also ratcheted
    print(f"Bob receives: {bob.receive(encrypted_msg1)}\n")

    # Step 4: Alice sends another message
    # Her session key is ratcheted again
    msg2 = "New ratcheted message!"
    encrypted_msg2 = alice.send(msg2)
    print(f"Alice sends: {json.dumps(encrypted_msg2)}")
    print(f"Bob receives: {bob.receive(encrypted_msg2)}\n")

    # Step 5: Bob replies
    msg3 = "Hello Alice!"
    encrypted_msg3 = bob.send(msg3)
    print(f"Bob sends: {json.dumps(encrypted_msg3)}")
    print(f"Alice receives: {alice.receive(encrypted_msg3)}\n")

# Entry point
if __name__ == "__main__":
    simulate_chat()
