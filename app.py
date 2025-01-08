from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"  # For flash messages

# Key generation and loading
KEY_FILE = "encryption.key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    return None

# Encryption and decryption
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    try:
        return fernet.decrypt(encrypted_message).decode()
    except Exception:
        return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate-key")
def generate_key_route():
    generate_key()
    flash("Encryption key has been generated successfully!", "success")
    return redirect(url_for("index"))

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        key = load_key()
        if not key:
            flash("No encryption key found. Please generate a key first.", "error")
            return redirect(url_for("index"))

        message = request.form.get("message")
        if message:
            encrypted_message = encrypt_message(message, key)
            return render_template("encrypt.html", encrypted_message=encrypted_message.decode())
    return render_template("encrypt.html")

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        key = load_key()
        if not key:
            flash("No encryption key found. Please generate a key first.", "error")
            return redirect(url_for("index"))

        encrypted_message = request.form.get("encrypted_message")
        if encrypted_message:
            decrypted_message = decrypt_message(encrypted_message.encode(), key)
            if decrypted_message:
                return render_template("decrypt.html", decrypted_message=decrypted_message)
            else:
                flash("Decryption failed. Ensure the encrypted message is valid.", "error")
    return render_template("decrypt.html")

if __name__ == "__main__":
    app.run(debug=True)
