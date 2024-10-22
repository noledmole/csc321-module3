import bcrypt
import nltk
from multiprocessing import Pool
import time

from nltk.corpus import words


# Ensure nltk words package is downloaded only once
def download_nltk_data():
    try:
        nltk.data.find('corpora/words.zip')
    except LookupError:
        nltk.download('words')


# Function to load shadow file and return a dictionary of users and hashes
def load_shadow_file():
    shadow_file = {
        'Bilbo': '$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq',
        'Gandalf': '$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC',
        'Thorin': '$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q',
        'Fili': '$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm',
        'Kili': '$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im',
        'Balin': '$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom',
        'Dwalin': '$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be',
        'Oin': '$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK',
        'Gloin': '$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q',
        'Dori': '$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq',
        'Nori': '$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12',
        'Ori': '$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O',
        'Bifur': '$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK',
        'Bofur': '$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O',
        'Durin': '$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay'
    }
    return shadow_file



# Function to crack the password for a single user using a list of dictionary words
def crack_password_in_chunk(word_chunk, hashed_password):
    for word in word_chunk:
        if bcrypt.checkpw(word.encode(), hashed_password.encode()):
            return word
    return None


# Function to attempt cracking passwords with parallel processing
def parallel_crack_password(user, hashed_password, word_list):
    num_chunks = 4  # Adjust based on your machine's cores
    chunks = [word_list[i::num_chunks] for i in range(num_chunks)]

    with Pool(num_chunks) as pool:
        results = pool.starmap(crack_password_in_chunk, [(chunk, hashed_password) for chunk in chunks])

    for result in results:
        if result is not None:
            return result
    return None


# Function to crack password and track progress
def crack_password_with_tracking(user, hashed_password, word_list):
    start_time = time.time()
    print(f"Starting to crack password for {user}...")

    # Attempt to crack the password using multiprocessing
    password = parallel_crack_password(user, hashed_password, word_list)

    end_time = time.time()
    elapsed_time = end_time - start_time

    if password:
        print(f"Cracked password for {user}: {password} (Time taken: {elapsed_time:.4f} seconds)")
    else:
        print(f"Failed to crack password for {user} (Time taken: {elapsed_time:.4f} seconds)")


# Main function to run the cracking process
def main():
    # Ensure nltk words package is downloaded only once
    download_nltk_data()

    # Load shadow file
    shadow_file = load_shadow_file()

    # Generate word corpus of 6 to 10 letter words
    word_corpus = [word for word in words.words() if 6 <= len(word) <= 10]

    # Crack each user's password with detailed printouts
    for user, hashed_password in shadow_file.items():
        crack_password_with_tracking(user, hashed_password, word_corpus)


if __name__ == "__main__":
    main()
