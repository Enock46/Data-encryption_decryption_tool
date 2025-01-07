from cryptography.fernet import Fernet

# Key generation
def generate_key():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to encryption.key")

# Load the key
def load_key():
    with open("encryption.key", "rb") as key_file:
        return key_file.read()

# Encrypt a message
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())  # Convert the string message to bytes and encrypt
    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()  # Decrypt and decode back to string
        return decrypted_message
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Main program
if __name__ == "__main__":
    action = input("Choose action: generate_key / encrypt / decrypt: ").strip().lower()

    if action == "generate_key":
        generate_key()
    elif action == "encrypt":
        key = load_key()
        message = input("Enter the message to encrypt: ")
        encrypted = encrypt_message(message, key)
        print("Encrypted message:", encrypted)
    elif action == "decrypt":
        key = load_key()
        encrypted_message_input = input("Enter the message to decrypt (from the previous encrypted output): ")

        # Convert the input string back to bytes (it should be in base64 format)
        encrypted_message = encrypted_message_input.encode()

        decrypted = decrypt_message(encrypted_message, key)
        if decrypted:
            print("Decrypted message:", decrypted)
        else:
            print("Failed to decrypt the message.")
    else:
        print("Invalid action!")
from cryptography.fernet import Fernet

# Key generation
def generate_key():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to encryption.key")

# Load the key
def load_key():
    try:
        with open("encryption.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Key file not found. Please generate a key first.")
        return None

# Encrypt a message
def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Main program
if __name__ == "__main__":
    action = input("Choose action: generate_key / encrypt / decrypt: ").strip().lower()

    if action == "generate_key":
        generate_key()
    elif action == "encrypt":
        key = load_key()
        if key:
            message = input("Enter the message to encrypt: ")
            encrypted = encrypt_message(message, key)
            print("Encrypted message:", encrypted.decode())  # Decode bytes to a string for display
    elif action == "decrypt":
        key = load_key()
        if key:
            encrypted_message_input = input("Enter the message to decrypt (from the previous encrypted output): ")
            try:
                # Convert string input back to bytes
                encrypted_message = encrypted_message_input.encode()
                decrypted = decrypt_message(encrypted_message, key)
                if decrypted:
                    print("Decrypted message:", decrypted)
                else:
                    print("Failed to decrypt the message.")
            except Exception as e:
                print(f"Error processing input: {e}")
    else:
        print("Invalid action!")
