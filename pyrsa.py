import os
import base64
import FreeSimpleGUI as sg
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

#boring math stuff

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return private_key.public_key(), private_key

def encrypt_decrypt_message(key, message, encrypt=True):
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    if encrypt:
        chunk_size = 190
        result = bytearray()
        for start in range(0, len(message), chunk_size):
            chunk = message[start:start + chunk_size]
            processed_chunk = key.encrypt(chunk.encode(), pad)
            result.extend(processed_chunk)
        return bytes(result)
    else:
        encrypted_chunk_size = 256
        result = bytearray()
        for start in range(0, len(message), encrypted_chunk_size):
            chunk = message[start:start + encrypted_chunk_size]
            processed_chunk = key.decrypt(chunk, pad)
            result.extend(processed_chunk)
        return result.decode()

def derive_encrypt_decrypt_key(data, passphrase, salt=None, decrypt=False):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    cipher = Fernet(key)
    processed_data = (cipher.decrypt if decrypt else cipher.encrypt)(data.encode())
    return processed_data.decode() if decrypt else (key, salt, processed_data)

#gui layout

sg.theme('DarkBlack') #https://www.geeksforgeeks.org/themes-in-pysimplegui/ for a full list of themes
label_width = 20

layout = [
    [sg.Radio("Encrypt", "RADIO1", default=True, key="-ENCRYPT-"), sg.Radio("Decrypt", "RADIO1", key="-DECRYPT-")],
    [sg.Text("Message:", size=(label_width, 1)), sg.Multiline(key="-MESSAGE-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Text("Result:", size=(label_width, 1)), sg.Multiline(key="-RESULT-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Text("Public Key:", size=(label_width, 1)), sg.Multiline(key="-PUBLIC_KEY-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Text("Private Key:", size=(label_width, 1)), sg.Multiline(key="-PRIVATE_KEY-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Button(x) for x in ["Process", "Generate Keys", "Clear", "Copy Results", "Copy Public Key", "Load Encrypted Key", "Save Public Key", "Save Private Key", "Exit"]]
]

window = sg.Window("PyRSA", layout, resizable=True)

public_key, private_key = None, None

while True:
    event, values = window.read()
    if event in (sg.WIN_CLOSED, "Exit"):
        break

    message = values["-MESSAGE-"].strip()
    if event == "Process":
        if values["-ENCRYPT-"]:
            if public_key:
                encrypted_message = encrypt_decrypt_message(public_key, message, True)
                window["-RESULT-"].update(base64.b64encode(encrypted_message).decode())
            else:
                sg.popup_error("Generate or load a public key first.")
        elif values["-DECRYPT-"]:
            if private_key:
                try:
                    encrypted_message = base64.b64decode(message)
                    decrypted_message = encrypt_decrypt_message(private_key, encrypted_message, False)
                    window["-RESULT-"].update(decrypted_message)
                except Exception as e:
                    sg.popup_error(f"Decryption error: {str(e)}")
            else:
                sg.popup_error("Generate or load a private key first.")
    # generate key button
    if event == "Generate Keys":
        public_key, private_key = generate_key_pair()
        window["-PUBLIC_KEY-"].update(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        window["-PRIVATE_KEY-"].update(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    #save the keys
    if event == "Save Public Key" and values["-PUBLIC_KEY-"]:
        with open("public-key.txt", "w") as pub_file:
            pub_file.write(values["-PUBLIC_KEY-"])
        sg.popup("Public key saved successfully!")

    if event == "Save Private Key" and values["-PRIVATE_KEY-"]:
        choice = sg.popup_yes_no("Encrypt the private key before saving?")
        if choice == "Yes":
            passphrase = sg.popup_get_text("Passphrase for encryption:", password_char="*")
            if not passphrase:
                sg.popup_error("Passphrase is required.")
                continue
            key, salt, encrypted_data = derive_encrypt_decrypt_key(values["-PRIVATE_KEY-"], passphrase)
            with open("private-key.txt", "wb") as priv_file:
                priv_file.write(salt + encrypted_data)
            sg.popup("Encrypted private key saved successfully!")
        else:
            with open("private-key.txt", "w") as priv_file:
                priv_file.write(values["-PRIVATE_KEY-"])
            sg.popup("Private key saved (unencrypted).")
    #load the key
    if event == "Load Encrypted Key":
        with open("private-key.txt", "rb") as file:
            data = file.read()
            salt, encrypted_key = data[:16], data[16:]
        passphrase = sg.popup_get_text("Passphrase for decryption:", password_char="*")
        private_key_content = derive_encrypt_decrypt_key(encrypted_key.decode(), passphrase, salt, True)
        window["-PRIVATE_KEY-"].update(private_key_content)
    #clear msg
    if event == "Clear":
        window["-MESSAGE-"].update("")
    #copy to clipboard
    if event in ("Copy Results", "Copy Public Key"):
        content = values["-RESULT-"] if event == "Copy Results" else values["-PUBLIC_KEY-"]
        sg.clipboard_set(content)

window.close()
