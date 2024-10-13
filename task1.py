# CSC 321 Module 3 Task 1 Noel Murti
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def aes_encrypt(message, key):
  iv = os.urandom(16) # Random Initialization Vecotr
  cipher = AES.new(key, AES.MODE_CBC, iv)
  ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size)) # Pad the cipher for encrypting
  return iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]  # Extract Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size) # Unpad the decryption for the plaintext
    return plaintext.decode('utf-8')


def diffie_hellman_key_exchange(q, alpha):
    # Alice's side
    XA = os.urandom(16)  # Alice's private key
    XA_int = int.from_bytes(XA, 'big')  # Convert to int
    YA = pow(alpha, XA_int, q)  # Alice's public value
    
    # Bob's side
    XB = os.urandom(16)  # Bob's private key
    XB_int = int.from_bytes(XB, 'big')  # Convert to int
    YB = pow(alpha, XB_int, q)  # Bob's public value
    
    # Shared secrets
    shared_secret_alice = pow(YB, XA_int, q)  # Alice computes the shared secret
    shared_secret_bob = pow(YA, XB_int, q)  # Bob computes the shared secret
    
    assert shared_secret_alice == shared_secret_bob, "Shared secrets do not match!"

    # Hash the shared secret and truncate to 16 bytes
    shared_secret_bytes = shared_secret_alice.to_bytes((shared_secret_alice.bit_length() + 7) // 8, 'big')
    key = hashlib.sha256(shared_secret_bytes).digest()[:16]
    
    return key

