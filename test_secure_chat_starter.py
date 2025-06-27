# This is the starter test file for CSC 364 - Foundations of Computer Security 
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
# python3 test_secure_chat_starter.py
#
# Notes for Students
# - You will need to make the establish_session, send, and receive methods
#   functional for the tests to pass.
# - The test_forward_secrecy_hint() is just a placeholder hint for an extension.

import unittest
from secure_chat import Party, generate_ecdh_key_pair

class TestSecureChatStarter(unittest.TestCase):
    def test_key_generation(self):
        priv, pub = generate_ecdh_key_pair()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_session_establishment_and_encryption(self):
        alice = Party("Alice")
        bob = Party("Bob")

        # Exchange public keys and establish session
        alice.establish_session(bob.public_key)
        bob.establish_session(alice.public_key)

        # Send a message from Alice to Bob
        plaintext = "Hello Bob!"
        msg = alice.send(plaintext)
        self.assertIn("ciphertext", msg)
        self.assertIn("nonce", msg)

        # Bob decrypts
        received = bob.receive(msg)
        self.assertEqual(received, plaintext)

    def test_forward_secrecy_hint(self):
        # TODO: old keys shouldn't decrypt future messages
        pass  # Students can implement this once ratcheting is done

    # TODO: add more tests

if __name__ == "__main__":
    unittest.main()
