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
    return c

# RSA Decryption with error handling for invalid UTF-8 encoding
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    m = pow(ciphertext, d, n)  # Perform RSA decryption: m = c^d mod n
    try:
        # Try to decode the plaintext back to a string
        plaintext = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode()
    except UnicodeDecodeError:
        # If decoding fails, print a warning and return the raw byte data
        return f"(Decryption resulted in invalid UTF-8 data: {m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')})"
    return plaintext


# MITM RSA Attack: Modify Ciphertext
def mitm_rsa_attack(public_key, original_ciphertext):
    e, n = public_key
    # Mallory modifies the original ciphertext
    modified_ciphertext = (original_ciphertext * pow(2, e, n)) % n
    return modified_ciphertext

# Main function to demonstrate RSA and MITM attack
def main():
    # RSA Key Generation
    e, d, n = rsa_key_generation()  # Generate RSA keys
    print("RSA Keys Generated:\n")
    print(f"Public Key: (e={e}, n={n})")
    print(f"Private Key: (d={d}, n={n})\n")

    # Alice sends a message to Bob
    message = "Hi Bob!"
    print(f"Alice's original message: {message}")

    ciphertext = rsa_encrypt((e, n), message)  # Alice encrypts the message
    print(f"\nEncrypted message (ciphertext): {ciphertext}")

    # Mallory intercepts and modifies the ciphertext
    modified_ciphertext = mitm_rsa_attack((e, n), ciphertext)
    print(f"\nMallory's modified ciphertext: {modified_ciphertext}")

    # Bob decrypts the modified ciphertext
    modified_decrypted_message = rsa_decrypt((d, n), modified_ciphertext)
    print(f"\nBob's decrypted message after MITM attack: {modified_decrypted_message}")

if __name__ == "__main__":
    main()
