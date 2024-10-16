from Crypto.Util.number import getPrime

# RSA Key Generation
def rsa_key_generation(bits=2048):
    # Generate two large primes, p and q
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q  # Compute n
    phi = (p - 1) * (q - 1)  # Compute phi(n)
    e = 65537  # Common public exponent
    d = pow(e, -1, phi)  # Compute private exponent d
    return (e, d, n)

# RSA Encryption for numeric string messages
def rsa_encrypt_numeric(public_key, plaintext):
    e, n = public_key
    # Ensure plaintext is numeric and convert it to an integer
    if not plaintext.isdigit():
        raise ValueError("Plaintext must be a numeric string.")
    m = int(plaintext)
    # Perform RSA encryption: c = m^e mod n
    c = pow(m, e, n)
    return c, m  # Return ciphertext and original integer message

# RSA Decryption returning numeric string
def rsa_decrypt_to_numeric(private_key, ciphertext):
    d, n = private_key
    # Perform RSA decryption: m = c^d mod n
    m = pow(ciphertext, d, n)
    # Return the integer as a numeric string
    return str(m), m  # Return as string and integer

# Mallory's Attack Function (Doubling)
def mitm_rsa_attack(public_key, original_ciphertext):
    e, n = public_key
    # Mallory modifies the original ciphertext by multiplying it by 2^e mod n
    modified_ciphertext = (original_ciphertext * pow(2, e, n)) % n
    return modified_ciphertext

# Mallory's Attack Function with Variable k
def mitm_rsa_attack_with_constant(public_key, original_ciphertext, k):
    e, n = public_key
    # Mallory modifies the original ciphertext by multiplying it by k^e mod n
    modified_ciphertext = (original_ciphertext * pow(k, e, n)) % n
    return modified_ciphertext

# RSA Signing
def rsa_sign(private_key, message):
    d, n = private_key
    m = int.from_bytes(message.encode(), byteorder='big')
    signature = pow(m, d, n)
    return signature

# RSA Verification
def rsa_verify(public_key, message, signature):
    e, n = public_key
    m_verified = pow(signature, e, n)
    m_original = int.from_bytes(message.encode(), byteorder='big')
    return m_verified == m_original

# Main Function for First Attack (Doubling)
def main_numeric_attack():
    # RSA Key Generation
    e, d, n = rsa_key_generation()
    print(f"Public Key: (e={e}, n={n})\n")

    # Alice's Message (Numeric string for clear readability)
    message = "500"
    print(f"Alice's original message: {message}")
    ciphertext, original_m = rsa_encrypt_numeric((e, n), message)
    print(f"Ciphertext: {ciphertext}\n")

    # Mallory's Attack (Doubling)
    modified_ciphertext = mitm_rsa_attack((e, n), ciphertext)
    print(f"Mallory's modified ciphertext: {modified_ciphertext}\n")

    # Bob Decrypts the Modified Ciphertext
    decrypted_plaintext, decrypted_m = rsa_decrypt_to_numeric((d, n), modified_ciphertext)
    print(f"Bob's decrypted integer after attack: {decrypted_m}")
    print(f"Bob's decrypted plaintext after attack: {decrypted_plaintext}\n")

    # Expected Result (Doubling the original message)
    expected_m = (original_m * 2) % n
    print(f"Expected manipulated integer: {expected_m}\n")

    # Verify Attack Success
    if decrypted_m == expected_m:
        print("Attack successful: Decrypted message matches Mallory's prediction.")
    else:
        print("Attack failed: Decrypted message does not match.")

# Main Function for Second Attack (Tripling)
def second_numeric_attack():
    # RSA Key Generation
    e, d, n = rsa_key_generation()
    message = "300"
    print(f"Alice's original message: {message}")
    ciphertext, original_m = rsa_encrypt_numeric((e, n), message)
    print(f"Ciphertext: {ciphertext}\n")

    # Mallory's Attack with k = 3 (Tripling)
    k = 3
    modified_ciphertext = mitm_rsa_attack_with_constant((e, n), ciphertext, k)
    print(f"Mallory's modified ciphertext with k={k}: {modified_ciphertext}\n")

    # Bob Decrypts Modified Ciphertext
    decrypted_plaintext, decrypted_m = rsa_decrypt_to_numeric((d, n), modified_ciphertext)
    print(f"Bob's decrypted integer after attack: {decrypted_m}")
    print(f"Bob's decrypted plaintext after attack: {decrypted_plaintext}\n")

    # Expected Result (Tripling the original message)
    expected_m = (original_m * k) % n
    print(f"Expected manipulated integer: {expected_m}\n")

    # Verify Attack Success
    if decrypted_m == expected_m:
        print("Second attack successful: Decrypted message matches Mallory's prediction.")
    else:
        print("Second attack failed: Decrypted message does not match.")

# Function for RSA Signing Demonstration
def rsa_signature_demo():
    # RSA Key Generation
    e, d, n = rsa_key_generation()
    print(f"Public Key: (e={e}, n={n})\n")

    # Message m3
    message_m3 = "This is message m3"
    print(f"Alice's message m3: {message_m3}")

    # Sign the Message
    signature = rsa_sign((d, n), message_m3)
    print(f"Signature for m3: {signature}\n")

    # Verify the Signature
    is_valid = rsa_verify((e, n), message_m3, signature)
    print(f"Is the signature valid? {is_valid}\n")

# Run Demonstrations
if __name__ == "__main__":
    print("=== First Malleability Attack (Doubling) ===\n")
    main_numeric_attack()
    print("\n=== Second Malleability Attack (Tripling) ===\n")
    second_numeric_attack()
    print("\n=== RSA Signing Demonstration ===\n")
    rsa_signature_demo()
