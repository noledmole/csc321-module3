import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# AES-CBC encryption and decryption
def aes_encrypt(message, key):
    iv = os.urandom(16)  # Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return iv + ciphertext  # Prepend IV for decryption

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]  # Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode('utf-8')

# 1. MITM Attack by Modifying Public Keys (YA and YB)
def mitm_attack_modify_keys(q, alpha):
    # Alice's side
    XA = os.urandom(16)  # Alice's private key (random bytes)
    XA_int = int.from_bytes(XA, 'big')  # Alice's private key as int
    YA = pow(alpha, XA_int, q)  # Alice's public value

    # Bob's side
    XB = os.urandom(16)  # Bob's private key (random bytes)
    XB_int = int.from_bytes(XB, 'big')  # Bob's private key as int
    YB = pow(alpha, XB_int, q)  # Bob's public value

    # Mallory intercepts and modifies the values exchanged between Alice and Bob
    # Mallory sends q instead of YA to Bob
    YA_mallory_to_bob = q
    
    # Mallory sends q instead of YB to Alice
    YB_mallory_to_alice = q

    # Alice computes the shared secret using the fake YB (which is q)
    shared_secret_alice = pow(YB_mallory_to_alice, XA_int, q)  # (q ^ XA) % q == 0

    # Bob computes the shared secret using the fake YA (which is q)
    shared_secret_bob = pow(YA_mallory_to_bob, XB_int, q)  # (q ^ XB) % q == 0

    # Both Alice and Bob will now compute s = 0 as the shared secret
    assert shared_secret_alice == shared_secret_bob == 0, "Shared secrets should be 0 in MITM attack"

    # Mallory knows the shared secret is 0 and derives the key
    known_shared_secret = 0
    known_shared_secret_bytes = known_shared_secret.to_bytes((known_shared_secret.bit_length() + 7) // 8, 'big')
    key = hashlib.sha256(known_shared_secret_bytes).digest()[:16]

    return key

# 2. MITM Attack by Modifying the Generator (alpha)
def mitm_attack_modify_generator(q, alpha_choice):
    # Alice's side
    XA = os.urandom(16)  # Alice's private key (random bytes)
    XA_int = int.from_bytes(XA, 'big')  # Alice's private key as int

    # Bob's side
    XB = os.urandom(16)  # Bob's private key (random bytes)
    XB_int = int.from_bytes(XB, 'big')  # Bob's private key as int

    # Mallory modifies the generator alpha
    alpha = alpha_choice

    # Alice computes public value with the modified alpha
    YA = pow(alpha, XA_int, q)

    # Bob computes public value with the modified alpha
    YB = pow(alpha, XB_int, q)

    # Alice and Bob compute shared secrets
    shared_secret_alice = pow(YB, XA_int, q)
    shared_secret_bob = pow(YA, XB_int, q)

    assert shared_secret_alice == shared_secret_bob, "Shared secrets should match"

    # Debugging output to check values
    print(f"alpha = {alpha_choice}, YA = {YA}, YB = {YB}, shared_secret = {shared_secret_alice}")

    # Mallory can now predict the shared secret based on alpha_choice
    if alpha == 1:
        known_shared_secret = 1
    elif alpha == q:
        known_shared_secret = 0
    elif alpha == q - 1:
        # Check the parity of XA_int and XB_int
        if XA_int % 2 == 0 and XB_int % 2 == 0:
            known_shared_secret = 1  # Both exponents even -> shared secret is 1
        elif XA_int % 2 == 1 and XB_int % 2 == 1:
            known_shared_secret = 1  # Both exponents odd -> shared secret is 1
        else:
            known_shared_secret = q - 1  # One even, one odd -> shared secret is q - 1
    else:
        known_shared_secret = shared_secret_alice  # This won't be predictable in general

    # Derive the key from the shared secret
    known_shared_secret_bytes = known_shared_secret.to_bytes((known_shared_secret.bit_length() + 7) // 8, 'big')
    key = hashlib.sha256(known_shared_secret_bytes).digest()[:16]

    return key

# Example for MITM Attack by Modifying Public Keys
print("=== MITM Attack by Modifying Public Keys ===")
q_small = 37
alpha_small = 5
key_mitm = mitm_attack_modify_keys(q_small, alpha_small)

# Alice sends a message to Bob
message_alice = "Hi Bob!"
ciphertext_alice = aes_encrypt(message_alice, key_mitm)

# Bob sends a message to Alice
message_bob = "Hi Alice!"
ciphertext_bob = aes_encrypt(message_bob, key_mitm)

# Mallory can decrypt both messages
message_alice_decrypted_by_mallory = aes_decrypt(ciphertext_alice, key_mitm)
message_bob_decrypted_by_mallory = aes_decrypt(ciphertext_bob, key_mitm)

print(f"Message from Alice decrypted by Mallory: {message_alice_decrypted_by_mallory}")
print(f"Message from Bob decrypted by Mallory: {message_bob_decrypted_by_mallory}\n")


# Example for MITM Attack by Modifying the Generator
print("=== MITM Attack by Modifying the Generator ===")
alpha_choices = [1, q_small, q_small - 1]

for alpha_choice in alpha_choices:
    key_mitm_alpha = mitm_attack_modify_generator(q_small, alpha_choice)
    
    # Alice sends a message to Bob
    message_alice = "Hi Bob!"
    ciphertext_alice = aes_encrypt(message_alice, key_mitm_alpha)
    
    # Bob sends a message to Alice
    message_bob = "Hi Alice!"
    ciphertext_bob = aes_encrypt(message_bob, key_mitm_alpha)

    # Mallory can decrypt both messages
    message_alice_decrypted_by_mallory = aes_decrypt(ciphertext_alice, key_mitm_alpha)
    message_bob_decrypted_by_mallory = aes_decrypt(ciphertext_bob, key_mitm_alpha)

    print(f"Message from Alice decrypted by Mallory (alpha = {alpha_choice}): {message_alice_decrypted_by_mallory}")
    print(f"Message from Bob decrypted by Mallory (alpha = {alpha_choice}): {message_bob_decrypted_by_mallory}")

