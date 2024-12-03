from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import urllib.parse
import binascii

class SymmetricKeyCryptography:
    def __init__(self, key_size=16):
        """Initialize with a random key and optional IV for CBC."""
        self.key = get_random_bytes(key_size)  # 16 bytes for AES-128
        self.iv = get_random_bytes(16)  # 16-byte IV for CBC mode

    def pkcs7_padding(self, data):
        """Apply PKCS#7 padding to make data a multiple of 16 bytes."""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def pkcs7_unpadding(self, data):
        """Remove PKCS#7 padding."""
        padding_length = data[-1]
        return data[:-padding_length]

    def xor_bytes(self, a, b):
        """XOR two byte strings."""
        return bytes(x ^ y for x, y in zip(a, b))

    def ecb_encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = b""
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            ciphertext += cipher.encrypt(block)
        return ciphertext

    def ecb_decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plaintext += cipher.decrypt(block)
        return plaintext

    def cbc_encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_ECB)  # ECB used internally for block encryption
        ciphertext = b""
        previous_block = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            block = self.xor_bytes(block, previous_block)
            encrypted_block = cipher.encrypt(block)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        return ciphertext

    def cbc_decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = b""
        previous_block = self.iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = cipher.decrypt(block)
            decrypted_block = self.xor_bytes(decrypted_block, previous_block)
            plaintext += decrypted_block
            previous_block = block
        return plaintext

    def encrypt_file(self, file_path, mode):
        """Encrypt a file in either ECB or CBC mode."""
        with open(file_path, 'rb') as file:
            header = file.read(54)  # BMP header size
            content = file.read()

        content = self.pkcs7_padding(content)

        if mode == 'ECB':
            ciphertext = self.ecb_encrypt(content)
        elif mode == 'CBC':
            ciphertext = self.cbc_encrypt(content)

        output_file = f"{file_path.split('.')[0]}_{mode}.bmp"
        with open(output_file, 'wb') as file:
            file.write(header + ciphertext)  # Reappend header before ciphertext

    def decrypt_file(self, file_path, mode):
        with open(file_path, 'rb') as file:
            header = file.read(54)  # BMP header size
            content = file.read()

        if mode == 'ECB':
            plaintext = self.ecb_decrypt(content)
        elif mode == 'CBC':
            plaintext = self.cbc_decrypt(content)

        plaintext = self.pkcs7_unpadding(plaintext)

        output_file = f"{file_path.split('.')[0]}_decrypted_{mode}.bmp"
        with open(output_file, 'wb') as file:
            file.write(header + plaintext)  # Write back header + decrypted content

    def create_blocks(self, data: bytes) -> bytes:
        """Apply padding to make data a multiple of 16 bytes for AES block size."""
        return pad(data, AES.block_size)

    def submit(self, user_data):
        # Prefix and suffix for constructing the message
        prefix_text = "userid=456;userdata="
        suffix_text = ";session-id=31337"

        # URL encode the input user data
        full_message = prefix_text + urllib.parse.quote(user_data) + suffix_text
        encoded_message = full_message.encode('ascii')

        # Apply padding
        padded_message = self.create_blocks(encoded_message)

        # Encrypt the padded data
        encrypted_message = self.cbc_encrypt(padded_message)

        return encrypted_message

    def verify(self, input_ciphertext):
        # Decrypt the ciphertext
        decrypted_content = self.cbc_decrypt(input_ciphertext)

        # Skip the first 16 bytes (first block becomes garbage after tampering)
        decrypted_content = decrypted_content[16:]

        # Unpad the data
        try:
            unpadded_content = unpad(decrypted_content, AES.block_size)
        except ValueError:
            print("err")
            return False

        # Decode the unpadded data
        decoded_content = unpadded_content.decode('ascii')
        parsed_data = urllib.parse.unquote(decoded_content)

        print("Decrypted Data:", parsed_data)

        # Return True if ';admin=true;' is found, False otherwise
        return ";admin=true;" in decoded_content

    def bit_flip_attack(self, target_ciphertext):
        # Convert ciphertext to a mutable bytearray
        enc_list = bytearray(target_ciphertext)

        # XOR specific bytes to flip 'A' to ';' and '='
        enc_list[4] ^= (ord("A") ^ ord(";"))
        enc_list[10] ^= (ord("A") ^ ord("="))
        enc_list[15] ^= (ord("A") ^ ord(";"))

        # Return the tampered ciphertext
        return bytes(enc_list)

def main():
    """Main method to demonstrate the bit-flip attack using the class-based approach."""
    # Initialize the cryptographic system
    skc = SymmetricKeyCryptography()

    # User input with placeholders 'AadminAtrueA' for tampering
    user_input = "AadminAtrueAYou're the man now, dog;admin=true;"

    # Encrypt the input using the submit function
    ciphertext = skc.submit(user_input)

    # Verify before tampering (should return False)
    print("Admin Access Before Tamper:", skc.verify(ciphertext))

    # Perform the bit-flip attack to tamper with the ciphertext
    tampered_ciphertext = skc.bit_flip_attack(ciphertext)

    # Verify after tampering (should return True)
    print("Admin Access After Tamper:", skc.verify(tampered_ciphertext))

# Run the demonstration
if __name__ == "__main__":
    main()


    def pass_admin_true_directly(self):
        # Step 1: Modify the input to directly include ";admin=true;"
        user_input = "anything;admin=true;"

        # Print the input before URL encoding and encryption
        print(f"Original Input: {user_input}")

        # Encrypt the input using submit() which uses CBC mode
        ciphertext = self.submit(user_input)

        # Step 2: Print the ciphertext to see what is being encrypted
        print(f"Ciphertext with ';admin=true;' directly (hex): {ciphertext.hex()}")

        # Step 3: Pass this ciphertext to the verify function
        result = self.verify(ciphertext)

        # Step 4: Print the decrypted message for inspection
        decrypted_message = self.cbc_decrypt(ciphertext)
        decrypted_message = self.pkcs7_unpadding(decrypted_message)
        print(f"Decrypted Message: {decrypted_message.decode()}")

        # Step 5: Print the result of the verification
        print(f"Admin Access after Direct Input: {'Granted' if result else 'Denied'}")


# if __name__ == "__main__":
#     crypto = SymmetricKeyCryptography()
#     attack_result = crypto.bit_flip_attack()
#     print(f"Attack result: {attack_result}")
#     # # User input with placeholders 'AadminAtrueA'
#     # user_input = "AadminAtrueAYou're the man now, dog;admin=true;"
#     # ciphertext = crypto.submit(user_input)
#     #
#     # # Check admin access before tampering
#     # print("Admin Access Before Tamper:", crypto.verify(ciphertext))
#     #
#     # # Tamper with ciphertext to change 'AadminAtrueA' to ';admin=true;'
#     # tampered_ciphertext = crypto.bit_flip_attack(ciphertext)
#     #
#     # # Check admin access after tampering
#     # print("Admin Access After Tamper:", crypto.verify(tampered_ciphertext))

def main_task_1():
    # Initialize the cryptography object
    cryptography = SymmetricKeyCryptography()

    # Path to the BMP file
    file_path = "cp-logo.bmp"  # Replace with your BMP file path

    # Encrypt the BMP file using ECB and CBC modes
    print("Encrypting file using ECB mode...")
    cryptography.encrypt_file(file_path, 'ECB')

    print("Encrypting file using CBC mode...")
    cryptography.encrypt_file(file_path, 'CBC')

    # Optional: Decrypt the ECB and CBC encrypted files to validate
    print("Decrypting ECB file...")
    cryptography.decrypt_file(f"{file_path.split('.')[0]}_ECB.bmp", 'ECB')

    print("Decrypting CBC file...")
    cryptography.decrypt_file(f"{file_path.split('.')[0]}_CBC.bmp", 'CBC')

    print("Encryption and decryption complete.")



