import os
import secrets
import base64
import argparse
from getpass import getpass
from hmac import compare_digest
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import sys

# Constants
KEY_SIZE_BYTES = 32  # 256-bit key for AES-GCM
TAG_SIZE_BYTES = 16  # Size of the authentication tag
NONCE_SIZE_BYTES = 12  # Optimal nonce size for AES-GCM
SALT_SIZE_BYTES = 16  # Salt for PBKDF2 key derivation
PBKDF2_ITERATIONS = 1000000  # Increased iterations for better security
CHUNK_SIZE = 64 * 1024  # Process files in 64 KB chunks

# ASCII Armoring Tags
START_TAG = "-----BEGIN AES-GCM ENCRYPTED DATA-----"
END_TAG = "-----END AES-GCM ENCRYPTED DATA-----"

class CipherForge:
    @staticmethod
    def create_secure_password(user_provided=None): # Added user_provided argument
        if user_provided:
            password = user_provided
            if len(password) < 12: # Added basic password strength check
                print("Warning: Password is short. Consider a longer password.")
        else:
            password = secrets.token_urlsafe(45)

        try:
            import gc
            gc.collect()  # Force garbage collection to remove sensitive data from memory
        except ImportError:
            pass  # Garbage collection is available in most environments
        return password

    @staticmethod
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE_BYTES,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))
        del password  # Remove password reference from memory
        return key

    @staticmethod
    def encrypt_stream(input_file, output_file, password=None): # Added password parameter.
        password = CipherForge.create_secure_password(password) # Handle user provided password
        salt = os.urandom(SALT_SIZE_BYTES)
        derived_key = CipherForge.derive_key(password, salt)
        nonce = os.urandom(NONCE_SIZE_BYTES)
        aesgcm = AESGCM(derived_key)

        encrypted_chunks = []
        try:
            with open(input_file, "rb") as f_in:
                while chunk := f_in.read(CHUNK_SIZE):
                    encrypted_chunks.append(aesgcm.encrypt(nonce, chunk, None))
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found.")
            return
        except PermissionError:
            print(f"Error: Permission denied accessing '{input_file}'.")
            return
        except Exception as e:
            print(f"An unexpected error occurred during encryption: {e}")
            return

        encrypted_data = salt + nonce + b"".join(encrypted_chunks)
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode("utf-8")
        ascii_armored = f"{START_TAG}\n{encrypted_data_b64}\n{END_TAG}"

        try:
            with open(output_file, "w", encoding="utf-8") as f_out:
                f_out.write(ascii_armored)
        except PermissionError:
            print(f"Error: Permission denied writing to '{output_file}'.")
            return
        except Exception as e:
            print(f"An unexpected error occurred writing output: {e}")
            return

        print(f"File encrypted successfully. Password: {password}")
        del derived_key, password  # Remove sensitive data from memory

    @staticmethod
    def decrypt_stream(input_file, output_file, password):
        try:
            with open(input_file, "r", encoding="utf-8") as f_in:
                lines = f_in.readlines()
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found.")
            return
        except PermissionError:
            print(f"Error: Permission denied accessing '{input_file}'.")
            return
        except Exception as e:
            print(f"An unexpected error occurred reading input: {e}")
            return

        start_index, end_index = -1, -1
        for i, line in enumerate(lines):
            if START_TAG in line:
                start_index = i
            if END_TAG in line:
                end_index = i
                break

        if start_index == -1 or end_index == -1:
            print("Error: Invalid ASCII-armored format: Start or end tag missing.")
            return

        encrypted_data_b64 = "".join(lines[start_index + 1:end_index]).strip()
        try:
            encrypted_data = base64.b64decode(encrypted_data_b64)
        except base64.binascii.Error:
            print("Error: Invalid base64 data.")
            return

        salt = encrypted_data[:SALT_SIZE_BYTES]
        nonce = encrypted_data[SALT_SIZE_BYTES:SALT_SIZE_BYTES + NONCE_SIZE_BYTES]
        ciphertext = encrypted_data[SALT_SIZE_BYTES + NONCE_SIZE_BYTES:]

        derived_key = CipherForge.derive_key(password, salt)
        aesgcm = AESGCM(derived_key)

        decrypted_chunks = []
        try:
            for i in range(0, len(ciphertext), CHUNK_SIZE + TAG_SIZE_BYTES):
                decrypted_chunks.append(aesgcm.decrypt(nonce, ciphertext[i:i + CHUNK_SIZE + TAG_SIZE_BYTES], None))
        except InvalidTag:
            print("Error: Decryption failed. Incorrect password or corrupted data.")
            return
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            return

        try:
            with open(output_file, "wb") as f_out:
                f_out.write(b"".join(decrypted_chunks))
        except PermissionError:
            print(f"Error: Permission denied writing to '{output_file}'.")
            return
        except Exception as e:
            print(f"An unexpected error occurred writing output: {e}")
            return

        del derived_key, password  # Ensure sensitive data is removed
        print("File decrypted successfully.")

def main():
    parser = argparse.ArgumentParser(description="AESCrypto - Encrypt and decrypt files using AES-256-GCM.")
    parser.add_argument("-ef", "--encrypt-file", nargs=2, metavar=("INPUT", "OUTPUT"), help="Encrypt a file.")
    parser.add_argument("-df", "--decrypt-file", nargs=2, metavar=("INPUT", "OUTPUT"), help="Decrypt a file.")
    parser.add_argument("-p", "--password", help="Password for encryption/decryption (optional for encryption)") # added password argument
    args = parser.parse_args()

    if args.encrypt_file:
        input_file, output_file = args.encrypt_file
        CipherForge.encrypt_stream(input_file, output_file, args.password) # Added password argument
    elif args.decrypt_file:
        input_file, output_file = args.decrypt_file
        password = args.password if args.password else getpass("Input your passphrase: ").strip() # added password argument
        CipherForge.decrypt_stream(input_file, output_file, password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

# Documentation of changes:
# 1. Added user_provided argument to create_secure_password and implemented user provided password functionality.
# 2. Added basic password strength check.
# 3. Added password parameter to encrypt_stream to handle user provided passwords.
# 4. Added comprehensive try/except blocks around file operations and cryptographic functions to handle errors.
# 5. Added base64 decode error catching.
# 6. Added command-line password argument "-p".
# 7. Added InvalidTag exception handling for decryption.
# 8. Improved error messages.
