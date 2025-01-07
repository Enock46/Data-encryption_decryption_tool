from flask import Flask, request, render_template, flash, redirect, url_for
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Key generation route
@app.route("/generate_key", methods=["POST"])
def generate_key_route():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    flash("Key generated and saved to 'encryption.key'.", "success")
    return redirect(url_for("home"))

# Encryption route
@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    key = load_key()
    if not key:
        flash("Encryption key not found. Please generate a key first.", "error")
        return redirect(url_for("home"))

    message = request.form["message"]
    encrypted_message = encrypt_message(message, key)
    return render_template(
        "index.html",
        encrypted_message=encrypted_message.decode(),
        decrypted_message=None,
    )

# Decryption route
@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    key = load_key()
    if not key:
        flash("Decryption key not found. Please generate a key first.", "error")
        return redirect(url_for("home"))

    encrypted_message = request.form["encrypted_message"]
    try:
        decrypted_message = decrypt_message(encrypted_message.encode(), key)
        return render_template(
            "index.html",
            encrypted_message=None,
            decrypted_message=decrypted_message,
        )
    except Exception as e:
        flash(f"Decryption failed: {e}", "error")
        return redirect(url_for("home"))

# Load encryption key
def load_key():
    try:
        with open("encryption.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        return None

# Encrypt a message
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Decrypt a message
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Home route
@app.route("/")
def home():
    return render_template("index.html", encrypted_message=None, decrypted_message=None)


if __name__ == "__main__":
    app.run(debug=True)
