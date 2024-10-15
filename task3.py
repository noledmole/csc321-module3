from Crypto.Util.number import getPrime
from hashlib import sha256
import math

# RSA Key Generation
def rsa_key_generation(bits=2048):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Public exponent
    d = pow(e, -1, phi)  # Private exponent
    return (e, d, n)

# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    m = int.from_bytes(plaintext.encode(), byteorder='big')  # Convert plaintext to integer
    c = pow(m, e, n)  # Perform RSA encryption: c = m^e mod n
    return c, m  # Return ciphertext and original integer message

# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    m = pow(ciphertext, d, n)  # Perform RSA decryption: m = c^d mod n
    return m  # Return the decrypted integer

def main():
    # RSA Key Generation
    e, d, n = rsa_key_generation()
    print("RSA Keys Generated:\n")
    print(f"Public Key: (e={e}, n={n})\n")
    # Alice's original message
    message = "Hi Bob!"
    print(f"Alice's original message: {message}")
    # Alice encrypts the message
    ciphertext, original_m = rsa_encrypt((e, n), message)
    print(f"\nAlice's ciphertext: {ciphertext}")
    # Mallory's attack: Multiply ciphertext by 2^e mod n
    attack_multiplier = 2
    modified_ciphertext = (ciphertext * pow(attack_multiplier, e, n)) % n
    print(f"\nMallory's modified ciphertext: {modified_ciphertext}")
    # Bob decrypts the modified ciphertext
    decrypted_m = rsa_decrypt((d, n), modified_ciphertext)
    print(f"\nBob's decrypted integer: {decrypted_m}")
    # Expected decrypted integer (original_m * attack_multiplier) % n
    expected_decrypted_m = (original_m * attack_multiplier) % n
    print(f"Expected decrypted integer: {expected_decrypted_m}")
    # Verify that Bob's decrypted message matches Mallory's expectation
    if decrypted_m == expected_decrypted_m:
        print("\nAttack successful: Bob's decrypted message matches Mallory's prediction.")
    else:
        print("\nAttack failed: Decrypted message does not match.")
    # Attempt to decode the decrypted integer back to text (may not be valid UTF-8)
    try:
        decrypted_message = decrypted_m.to_bytes((decrypted_m.bit_length() + 7) // 8, byteorder='big').decode()
        print(f"\nBob's decrypted message: {decrypted_message}")
    except UnicodeDecodeError:
        print("\nBob's decrypted message is not valid UTF-8 text.")

if __name__ == "__main__":
    main()
