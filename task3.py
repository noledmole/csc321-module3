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


# Mallory observes and recovers the original message from Alice's decryption
def mallory_observes_recovered_message():
    # RSA Key Generation
    e, d, n = rsa_key_generation()

    # Alice's Original Message
    message = "42"  # Numeric string for Mallory's observation
    print(f"Alice's original message: {message}")

    # Alice encrypts the message
    ciphertext, original_m = rsa_encrypt_numeric((e, n), message)
    print(f"Alice's original ciphertext: {ciphertext}\n")

    # Mallory's Malleability Attack
    modified_ciphertext = mitm_rsa_attack((e, n), ciphertext)
    print(f"Mallory's modified ciphertext (sent back to Alice): {modified_ciphertext}\n")

    # Alice decrypts the modified ciphertext
    decrypted_message_after_attack, decrypted_m_after_attack = rsa_decrypt_to_numeric((d, n), modified_ciphertext)
    print(f"Alice's decrypted integer after attack: {decrypted_m_after_attack}")

    # Mallory observes the result and recovers the original message
    observed_value = decrypted_m_after_attack
    recovered_message_by_mallory = observed_value // 2
    print(f"Mallory infers the original message: {recovered_message_by_mallory}\n")


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


# Mallory's Signature Malleability: Combine signatures of m1 and m2
def rsa_signature_malleability():
    # RSA Key Generation
    e, d, n = rsa_key_generation()

    # Alice signs two messages m1 and m2
    message_m1 = "Message 1"
    message_m2 = "Message 2"

    signature_m1 = rsa_sign((d, n), message_m1)
    signature_m2 = rsa_sign((d, n), message_m2)

    print(f"Signature for Message 1: {signature_m1}")
    print(f"Signature for Message 2: {signature_m2}")

    # Mallory combines the two signatures to create a signature for m3 = m1 * m2
    m1 = int.from_bytes(message_m1.encode(), byteorder='big')
    m2 = int.from_bytes(message_m2.encode(), byteorder='big')
    m3 = m1 * m2

    signature_m3 = (signature_m1 * signature_m2) % n
    print(f"Signature for Message 3 (combined): {signature_m3}")

    # Verify if the signature for m3 is valid
    is_valid_m3 = pow(signature_m3, e, n) == m3
    print(f"Is the combined signature for Message 3 valid? {is_valid_m3}")


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


# Run Demonstrations
if __name__ == "__main__":
    print("=== First Malleability Attack (Doubling) ===\n")
    main_numeric_attack()
    print("\n=== Second Malleability Attack (Tripling) ===\n")
    second_numeric_attack()
    print("\n=== Mallory Observes and Recovers the Original Message ===\n")
    mallory_observes_recovered_message()
    print("\n=== RSA Signing and Signature Malleability ===\n")
    rsa_signature_malleability()
