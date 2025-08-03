import hashlib
import random
import string
from typing import Dict, List

# Base character set: uppercase, lowercase letters, and digits
BASE_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits
CHARSET_LEN = len(BASE_CHARS)


def transform_key(key: int) -> int:
    """
    Obfuscate the original numeric key to avoid predictability.
    """
    return (key * 73 + 19) % 1000


def generate_mappings(key: int, rounds: int = 3) -> List[Dict[str, str]]:
    """
    Generate a list of `rounds` substitution mappings, each shuffled
    with a modified key seed.
    """
    mappings = []
    for i in range(rounds):
        seed = transform_key(key + i)
        rng = random.Random(seed)
        chars = list(BASE_CHARS)
        rng.shuffle(chars)
        mapping = {BASE_CHARS[j]: chars[j] for j in range(CHARSET_LEN)}
        mappings.append(mapping)
    return mappings


def add_salt(ciphertext: str, key: int, interval: int = 4) -> str:
    """
    Insert a salt character every `interval` characters to increase randomness.
    Salt character derived from key: key % 10.
    """
    salt_char = str(key % 10)
    parts = [ciphertext[i: i + interval] for i in range(0, len(ciphertext), interval)]
    return salt_char.join(parts)


def remove_salt(text: str, key: int, interval: int = 4) -> str:
    """
    Remove the salt characters inserted during encryption.
    """
    # Remove every (interval+1)th character (the salt)
    return ''.join(
        ch for i, ch in enumerate(text) if (i % (interval + 1)) != interval
    )


def compute_mac(plaintext: str, key: int) -> str:
    """
    Compute a SHA-256 based MAC combining the plaintext and key.
    """
    data = f"{plaintext}{key}".encode()
    return hashlib.sha256(data).hexdigest()


def encrypt(
    message: str,
    key: int,
    rounds: int = 3,
    add_salt_flag: bool = True
) -> str:
    """
    Encrypt a message using:
      1. Length prefix (4-digit)
      2. Multiple rounds of substitution and position-based shift
      3. Optional salt insertion
      4. MAC appended for integrity

    Returns ciphertext as:
      <encrypted_body><salt><mac>
    """
    # 1. Prefix length metadata
    length_prefix = f"{len(message):04d}"
    payload = length_prefix + message

    # 2. Generate mappings
    mappings = generate_mappings(key, rounds)

    # 3. Apply rounds of substitution with position-based shift
    text = payload
    for rnd, mapping in enumerate(mappings):
        new_chars = []
        for idx, ch in enumerate(text):
            if ch in mapping:
                # Substitute
                sub = mapping[ch]
                # Position-based shift
                pos_offset = (idx + key) % CHARSET_LEN
                orig_index = BASE_CHARS.index(sub)
                shifted = BASE_CHARS[(orig_index + pos_offset) % CHARSET_LEN]
                new_chars.append(shifted)
            else:
                new_chars.append(ch)
        text = ''.join(new_chars)

    # 4. Compute MAC for the unsalted payload
    mac = compute_mac(payload, key)

    # 5. Insert salt if requested
    cipher_body = add_salt(text, key) if add_salt_flag else text

    # 6. Return the final ciphertext
    return cipher_body + mac


def decrypt(
    ciphertext: str,
    key: int,
    rounds: int = 3,
    add_salt_flag: bool = True
) -> str:
    """
    Decrypt the ciphertext produced by `encrypt`. Verifies MAC and length.
    """
    # 1. Extract MAC (64 hex chars)
    mac = ciphertext[-64:]
    body = ciphertext[:-64]

    # 2. Remove salt if used
    text = remove_salt(body, key) if add_salt_flag else body

    # 3. Reverse rounds
    mappings = generate_mappings(key, rounds)
    for rnd, mapping in reversed(list(enumerate(mappings))):
        # Build reverse mapping
        rev_map = {v: k for k, v in mapping.items()}
        new_chars = []
        for idx, ch in enumerate(text):
            if ch in BASE_CHARS:
                # Reverse position shift
                pos_offset = (idx + key) % CHARSET_LEN
                cur_index = BASE_CHARS.index(ch)
                unshifted = BASE_CHARS[(cur_index - pos_offset) % CHARSET_LEN]
                # Reverse substitution
                orig = rev_map.get(unshifted, unshifted)
                new_chars.append(orig)
            else:
                new_chars.append(ch)
        text = ''.join(new_chars)

    # 4. Extract length prefix and message
    length_prefix = text[:4]
    message = text[4:]

    # 5. Reconstruct the original payload
    payload = length_prefix + message

    # 6. Verify MAC
    expected_mac = compute_mac(payload, key)
    if mac != expected_mac:
        raise ValueError("MAC verification failed: data integrity compromised.")

    # 7. Validate length
    if int(length_prefix) != len(message):
        raise ValueError("Length prefix mismatch: possible tampering.")

    return message


def prompt_key():
    while True:
        try:
            return int(input("Enter a numeric key: "))
        except ValueError:
            print("Please enter a valid integer key.")

def encrypt_file(input_path: str, output_path: str, key: int):
    with open(input_path, "r", encoding="utf-8") as infile:
        plaintext = infile.read()
    ciphertext = encrypt(plaintext, key)
    with open(output_path, "w", encoding="utf-8") as outfile:
        outfile.write(ciphertext)
    print(f"File encrypted and saved to {output_path}")

def decrypt_file(input_path: str, output_path: str, key: int):
    with open(input_path, "r", encoding="utf-8") as infile:
        ciphertext = infile.read()
    try:
        plaintext = decrypt(ciphertext, key)
        with open(output_path, "w", encoding="utf-8") as outfile:
            outfile.write(plaintext)
        print(f"File decrypted and saved to {output_path}")
    except Exception as e:
        print("Error during decryption:", e)

# Example usage
if __name__ == "__main__":
    user_key = prompt_key()

    while True:
        print("\nChoose what you want to do:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Change key")
        print("4. Encrypt a file")
        print("5. Decrypt a file")
        print("6. Exit")
        choice = input("Enter your choice (1-6): ").strip()

        if choice == '1':
            while True:
                original = input("\nEnter the message to encrypt (or type '[90]' to return): ")
                if original.lower() == '[90]':
                    break
                encrypted = encrypt(original, user_key)
                print()
                print("Encrypted:", encrypted)
        elif choice == '2':
            while True:
                encrypted = input("\nEnter the message to decrypt (or type '[90]' to return): ")
                if encrypted.lower() == '[90]':
                    break
                try:
                    decrypted = decrypt(encrypted, user_key)
                    print()
                    print("Decrypted:", decrypted)
                except Exception as e:
                    print("Error:", e)
        elif choice == '3':
            user_key = prompt_key()
            print("Key changed successfully.")
        elif choice == '4':
            in_path = input("Enter path to file to encrypt: ").strip()
            out_path = input("Enter output file path: ").strip()
            encrypt_file(in_path, out_path, user_key)
        elif choice == '5':
            in_path = input("Enter path to file to decrypt: ").strip()
            out_path = input("Enter output file path: ").strip()
            decrypt_file(in_path, out_path, user_key)
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
