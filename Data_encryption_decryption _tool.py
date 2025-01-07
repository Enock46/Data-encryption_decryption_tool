from cryptography.fernet import Fernet

# Key generation
def generate_key():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    print("\nKey generated and saved to 'encryption.key'.\n")

# Load the key
def load_key():
    try:
        with open("encryption.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("\nKey file not found. Please generate a key first.\n")
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
        print(f"\nDecryption failed: {e}\n")
        return None

# Display menu
def display_menu():
    print("\n--- Encryption Tool ---")
    print("1. Generate Encryption Key")
    print("2. Encrypt a Message")
    print("3. Decrypt a Message")
    print("4. Exit")

# Main program
def main():
    while True:
        display_menu()
        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            generate_key()
        elif choice == "2":
            key = load_key()
            if key:
                message = input("\nEnter the message to encrypt: ")
                encrypted = encrypt_message(message, key)
                print("\nEncrypted message:")
                print(encrypted.decode())  # Display as a string
        elif choice == "3":
            key = load_key()
            if key:
                encrypted_message_input = input("\nEnter the encrypted message to decrypt: ")
                try:
                    encrypted_message = encrypted_message_input.encode()  # Convert to bytes
                    decrypted = decrypt_message(encrypted_message, key)
                    if decrypted:
                        print("\nDecrypted message:")
                        print(decrypted)
                except Exception as e:
                    print(f"\nError processing input: {e}\n")
        elif choice == "4":
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid choice. Please try again.\n")

if __name__ == "__main__":
    main()
