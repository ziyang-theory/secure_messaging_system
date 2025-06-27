# This is the main file for CSC 364 - Foundations of Computer Security 
# Project 1 - Secure Messaging System

# In order to execute this file, if you haven't done this before, you need
# to run the commands below to install the 'cryptography' python library:
#
# python3 -m venv path/to/venv
# source path/to/venv/bin/activate
# python3 -m pip install cryptography
#
# To run the tests:
# python3 test_secure_chat.py
#

import unittest
from secure_chat import (
    generate_ecdh_key_pair,
    derive_shared_secret,
    hkdf_expand,
    encrypt_message,
    decrypt_message,
    ratchet_key,
    Party,
)

class SecureChatTests(unittest.TestCase):

    def test_ecdh_shared_secret_matches(self):
        priv_a, pub_a = generate_ecdh_key_pair()
        priv_b, pub_b = generate_ecdh_key_pair()

        shared_a = derive_shared_secret(priv_a, pub_b)
        shared_b = derive_shared_secret(priv_b, pub_a)

        key_a = hkdf_expand(shared_a)
        key_b = hkdf_expand(shared_b)

        self.assertEqual(key_a, key_b)

    def test_encrypt_decrypt_round_trip(self):
        priv_a, pub_a = generate_ecdh_key_pair()
        priv_b, pub_b = generate_ecdh_key_pair()
        shared = derive_shared_secret(priv_a, pub_b)
        key = hkdf_expand(shared)

        plaintext = "Test message"
        encrypted = encrypt_message(key, plaintext)
        decrypted = decrypt_message(key, encrypted)

        self.assertEqual(decrypted, plaintext)

    def test_decryption_fails_on_tampered_ciphertext(self):
        priv_a, pub_a = generate_ecdh_key_pair()
        priv_b, pub_b = generate_ecdh_key_pair()
        key = hkdf_expand(derive_shared_secret(priv_a, pub_b))

        plaintext = "Integrity test"
        encrypted = encrypt_message(key, plaintext)

        tampered = encrypted.copy()
        tampered['ciphertext'] = '00' + tampered['ciphertext'][2:]

        with self.assertRaises(Exception):
            decrypt_message(key, tampered)

    def test_party_symmetric_key_agreement(self):
        alice = Party("Alice")
        bob = Party("Bob")

        alice.establish_session(bob.get_public_bytes(), role='initiator')
        bob.establish_session(alice.get_public_bytes(), role='responder')

        # Sending and receiving keys should be flipped
        self.assertEqual(alice.sending_key, bob.receiving_key)
        self.assertEqual(alice.receiving_key, bob.sending_key)

    def test_ratchet_after_send_changes_key(self):
        alice = Party("Alice")
        bob = Party("Bob")

        alice.establish_session(bob.get_public_bytes(), role='initiator')
        bob.establish_session(alice.get_public_bytes(), role='responder')

        old_key = alice.sending_key
        alice.send("Message 1")
        self.assertNotEqual(alice.sending_key, old_key)

    def test_ratchet_after_receive_changes_key(self):
        alice = Party("Alice")
        bob = Party("Bob")

        alice.establish_session(bob.get_public_bytes(), role='initiator')
        bob.establish_session(alice.get_public_bytes(), role='responder')

        msg = alice.send("Message 1")
        old_key = bob.receiving_key
        bob.receive(msg)
        self.assertNotEqual(bob.receiving_key, old_key)

    def test_forward_secrecy_blocks_old_key(self):
        """
        Verifies that a message sent after ratcheting cannot be decrypted using the old receiving key.
        """
        alice = Party("Alice")
        bob = Party("Bob")
        alice.establish_session(bob.get_public_bytes(), role='initiator')
        bob.establish_session(alice.get_public_bytes(), role='responder')

        # Send and receive first message
        msg1 = alice.send("First")
        bob.receive(msg1)

        # Save Bob's receiving key *before* receiving the second message
        old_bob_key = bob.receiving_key

        # Alice sends another message using a *ratcheted* key
        msg2 = alice.send("Second")

        # The message is encrypted using a new key
        # Decrypting it with the old key should now fail
        with self.assertRaises(Exception):
            decrypt_message(old_bob_key, msg2)

    def test_ratchet_chain_produces_unique_keys(self):
        """Check that multiple ratchet steps produce different keys."""
        priv, pub = generate_ecdh_key_pair()
        shared = derive_shared_secret(priv, pub)
        k1 = hkdf_expand(shared)
        k2 = ratchet_key(k1)
        k3 = ratchet_key(k2)
        self.assertNotEqual(k1, k2)
        self.assertNotEqual(k2, k3)
        self.assertNotEqual(k1, k3)

if __name__ == "__main__":
    unittest.main()
