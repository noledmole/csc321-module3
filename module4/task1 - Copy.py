import hashlib
import time
import random
import string

# Function to compute SHA256 hash and return in hexadecimal format
def sha256_hash(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

# Function to compute truncated SHA256 hash with the given number of bits
def truncated_sha256(input_string, bits):
    full_hash = sha256_hash(input_string)
    truncated_hash = full_hash[:bits // 4]  # Convert bits to hex digits
    return truncated_hash

# Function to calculate the Hamming distance between two strings
def hamming_distance(str1, str2):
    if len(str1) != len(str2):
        raise ValueError("Strings must be of equal length to compute Hamming distance.")
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))

# Function to generate a random string of fixed length
def random_string(length):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

# Function to find collisions with truncated SHA256 hashes
def find_collision(bits):
    start_time = time.time()
    seen_hashes = {}
    count = 0

    while True:
        # Generate a random input string
        input_string = random_string(10)
        truncated_hash = truncated_sha256(input_string, bits)

        # Check if the truncated hash is already seen
        if truncated_hash in seen_hashes:
            print(f"Collision found! Input 1: {input_string}, Input 2: {seen_hashes[truncated_hash]}")
            print(f"Truncated Hash: {truncated_hash}")
            break
        else:
            seen_hashes[truncated_hash] = input_string

        count += 1

    elapsed_time = time.time() - start_time
    print(f"Collision found after {count} inputs. Time taken: {elapsed_time:.4f} seconds.")
    return count, elapsed_time

# Main function
def main():
    print("Task 1a: SHA256 Hashing")
    input_string = "example"
    digest = sha256_hash(input_string)
    print(f"SHA256 digest of '{input_string}': {digest}\n")

    print("Task 1b: Hash Two Strings with 1-bit Difference")
    string1 = "example"
    string2 = "exbmple"  # Change one bit (one character difference)
    hash1 = sha256_hash(string1)
    hash2 = sha256_hash(string2)
    print(f"SHA256 digest of '{string1}': {hash1}")
    print(f"SHA256 digest of '{string2}': {hash2}")
    hamming_dist = hamming_distance(hash1, hash2)
    print(f"Hamming distance between the two digests: {hamming_dist} bytes\n")

    print("Task 1c: Truncating Hashes and Finding Collisions")
    bit_sizes = [8, 16, 24, 32, 40, 48, 50]
    inputs_list = []
    time_list = []

    for bits in bit_sizes:
        print(f"\nFinding collision for {bits}-bit truncated hash...")
        count, elapsed_time = find_collision(bits)
        inputs_list.append(count)
        time_list.append(elapsed_time)

    print("\nCollision Results Summary:")
    for i, bits in enumerate(bit_sizes):
        print(f"{bits}-bit truncated hash: {inputs_list[i]} inputs, {time_list[i]:.4f} seconds")

if __name__ == "__main__":
    main()
