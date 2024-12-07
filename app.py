import base64
import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import Blowfish, DES
import os

# Key generation
aes_key = get_random_bytes(16)
des_key = get_random_bytes(24)
blowfish_key = get_random_bytes(16)
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
rsa_private_cipher = PKCS1_OAEP.new(rsa_key)

ecc_key = ECC.generate(curve='P-256')
ecc_public_key = ecc_key.public_key()
ecc_private_key = ecc_key

xor_key = 29
caesar_shift = 5


def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(char) ^ key) for char in text)


def caesar_encrypt_decrypt(text, shift, mode='encrypt'):
    shift = shift if mode == 'encrypt' else -shift
    return ''.join(
        chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
        for char in text
    )


def aes_encrypt_decrypt(message, key, mode='encrypt'):
    cipher = AES.new(key, AES.MODE_CBC)
    if mode == 'encrypt':
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted).decode()
    else:
        raw = base64.b64decode(message)
        iv = raw[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)
        return decrypted.decode()


def des3_encrypt_decrypt(message, key, mode='encrypt'):
    cipher = DES3.new(key, DES3.MODE_CBC)
    if mode == 'encrypt':
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(message.encode(), DES3.block_size))
        return base64.b64encode(iv + encrypted).decode()
    else:
        raw = base64.b64decode(message)
        iv = raw[:DES3.block_size]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(raw[DES3.block_size:]), DES3.block_size)
        return decrypted.decode()


def rsa_encrypt_decrypt(message, mode='encrypt'):
    if mode == 'encrypt':
        encrypted = rsa_cipher.encrypt(message.encode())
        return base64.b64encode(encrypted).decode()
    else:
        decrypted = rsa_private_cipher.decrypt(base64.b64decode(message))
        return decrypted.decode()


def blowfish_encrypt_decrypt(message, key, mode='encrypt'):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    if mode == 'encrypt':
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(message.encode(), Blowfish.block_size))
        return base64.b64encode(iv + encrypted).decode()
    else:
        raw = base64.b64decode(message)
        iv = raw[:Blowfish.block_size]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(raw[Blowfish.block_size:]), Blowfish.block_size)
        return decrypted.decode()


def hmac_sha256(message, key):
    h = HMAC.new(key, message.encode(), SHA256)
    return h.hexdigest()


def brute_force_attack(message):
    print("Attempting brute force decryption...")
    print("Trying Caesar Cipher...")
    for shift in range(1, 26):
        try:
            decrypted = caesar_encrypt_decrypt(message, shift, mode='decrypt')
            print(f"Caesar Cipher (Shift {shift}): {decrypted}")
        except Exception:
            continue

    print("\nTrying XOR Encryption...")
    for key in range(256):
        try:
            decrypted = xor_encrypt_decrypt(message, key)
            print(f"XOR Decryption (Key {key}): {decrypted}")
        except Exception:
            continue

    print("\nAES, RSA, 3DES, Blowfish brute force attacks are impractical without keys.")
    return "Brute force completed."


def styled_input(prompt):
    print("**********************************************")
    print(f"*{prompt.center(40)}*")
    print("**********************************************")
    return input("Enter your text (type 'END' to finish):\n>> ")


def encrypt_message():
    message = styled_input("Encrypt a Message")
    if message.upper() == "END":
        return
    print("Choose your encryption technique:")
    print("1. AES Encryption")
    print("2. RSA Encryption")
    print("3. 3DES Encryption")
    print("4. Blowfish Encryption")
    print("5. HMAC-SHA256 Encryption")
    choice = input("Enter your choice (1-5): ")
    if choice == "1":
        print(f"Encrypted Message (AES): {aes_encrypt_decrypt(message, aes_key, mode='encrypt')}")
    elif choice == "2":
        print(f"Encrypted Message (RSA): {rsa_encrypt_decrypt(message, mode='encrypt')}")
    elif choice == "3":
        print(f"Encrypted Message (3DES): {des3_encrypt_decrypt(message, des_key, mode='encrypt')}")
    elif choice == "4":
        print(f"Encrypted Message (Blowfish): {blowfish_encrypt_decrypt(message, blowfish_key, mode='encrypt')}")
    elif choice == "5":
        print(f"HMAC-SHA256: {hmac_sha256(message, blowfish_key)}")
    else:
        print("Invalid choice.")


def decrypt_message():
    message = styled_input("Decrypt a Message")
    if message.upper() == "END":
        return
    print("Choose your decryption technique:")
    print("1. AES Decryption")
    print("2. RSA Decryption")
    print("3. 3DES Decryption")
    print("4. Blowfish Decryption")
    print("5. HMAC-SHA256 Decryption")
    choice = input("Enter your choice (1-5): ")
    if choice == "1":
        print(f"Decrypted Message (AES): {aes_encrypt_decrypt(message, aes_key, mode='decrypt')}")
    elif choice == "2":
        print(f"Decrypted Message (RSA): {rsa_encrypt_decrypt(message, mode='decrypt')}")
    elif choice == "3":
        print(f"Decrypted Message (3DES): {des3_encrypt_decrypt(message, des_key, mode='decrypt')}")
    elif choice == "4":
        print(f"Decrypted Message (Blowfish): {blowfish_encrypt_decrypt(message, blowfish_key, mode='decrypt')}")
    elif choice == "5":
        print(f"HMAC-SHA256: {message} (No Decryption)")
    else:
        print("Invalid choice.")


def main():
    while True:
        print("**********************************************")
        print("*           Encryption Tool Main Menu        *")
        print("**********************************************")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Brute Force Attack")
        print("4. Exit the program")
        choice = input("Enter your choice: ")
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            encrypted_message = styled_input("Brute Force Attack")
            if encrypted_message.upper() == "END":
                continue
            brute_force_attack(encrypted_message)
        elif choice == "4":
            print("\nThank you for using the Encryption Tool!")
            print("We hope to see you again!")
            print("[Program finished]")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
