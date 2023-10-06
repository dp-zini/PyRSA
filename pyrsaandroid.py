import os
import base64
import PySimpleGUI as sg
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

# Functions

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return private_key.public_key(), private_key

def encrypt_decrypt_message(key, message, encrypt=True):
    method = key.encrypt if encrypt else key.decrypt
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    processed_message = method(message.encode() if encrypt else message, pad)
    return processed_message.decode() if not encrypt else processed_message

def derive_encrypt_decrypt_key(data, passphrase, salt=None, decrypt=False):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    cipher = Fernet(key)
    processed_data = (cipher.decrypt if decrypt else cipher.encrypt)(data.encode())
    return processed_data.decode() if decrypt else (key, salt, processed_data)

# GUI Layout

sg.theme('DarkBlack') 
font_size = 14
sg.set_options(font=("Any", font_size))
label_width = 10

layout = [
    [sg.Radio("Encrypt", "RADIO1", default=True, key="-ENCRYPT-", font=("Any", font_size)), sg.Radio("Decrypt", "RADIO1", key="-DECRYPT-", font=("Any", font_size))],
    [sg.Text("Message:", size=(label_width, 1), font=("Any", font_size)), sg.Multiline(key="-MESSAGE-", size=(20, 2), expand_x=True)],
    [sg.Text("Result:", size=(label_width, 1), font=("Any", font_size)), sg.Multiline(key="-RESULT-", size=(20, 2), expand_x=True)],
    [sg.Text("Public Key:", size=(label_width, 1), font=("Any", font_size)), sg.Multiline(key="-PUBLIC_KEY-", size=(20, 2), expand_x=True)],
    [sg.Text("Private Key:", size=(label_width, 1), font=("Any", font_size)), sg.Multiline(key="-PRIVATE_KEY-", size=(20, 2), expand_x=True)],
    [sg.Combo(["Process", "Generate Keys", "Clear", "Copy Results", "Copy Public Key", "Load Encrypted Key", "Save Public Key", "Save Private Key"],
              size=(15, 1), default_value="Process", key="-ACTIONS-", font=("Any", font_size)), sg.Button("Execute", size=(12, 1), font=("Any", font_size))],
    [sg.Button("Exit", size=(12, 1), font=("Any", font_size))]
]

window = sg.Window("PyRSA", layout, resizable=True)

public_key, private_key = None, None

while True:
    event, values = window.read()

    if event in (sg.WIN_CLOSED, "Exit"):
        break

    message = values["-MESSAGE-"].strip()

    if event == "Execute":
        selected_action = values["-ACTIONS-"]

        if selected_action == "Process":
            if values["-ENCRYPT-"]:
                if public_key or values["-PUBLIC_KEY-"]:
                    public_key = public_key or serialization.load_pem_public_key(values["-PUBLIC_KEY-"].encode())
                    window["-RESULT-"].update(encrypt_decrypt_message(public_key, message).hex())
                else:
                    sg.popup_error("Provide or generate a public key for encryption.")
            else:
                if private_key or values["-PRIVATE_KEY-"]:
                    private_key = private_key or serialization.load_pem_private_key(values["-PRIVATE_KEY-"].encode(), None, default_backend())
                    try:
                        window["-RESULT-"].update(encrypt_decrypt_message(private_key, bytes.fromhex(message), False))
                    except Exception as e:
                        sg.popup_error(f"Decryption error: {str(e)}")
                else:
                    sg.popup_error("Provide or generate a private key for decryption.")

        elif selected_action == "Generate Keys":
            public_key, private_key = generate_key_pair()
            window["-PUBLIC_KEY-"].update(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
            window["-PRIVATE_KEY-"].update(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())

        elif selected_action == "Clear":
            window["-MESSAGE-"].update("")

        elif selected_action == "Copy Results":
            content = values["-RESULT-"]
            sg.clipboard_set(content)

        elif selected_action == "Copy Public Key":
            content = values["-PUBLIC_KEY-"]
            sg.clipboard_set(content)

        elif selected_action == "Load Encrypted Key":
            with open("private-key.txt", "rb") as file:
                data = file.read()
                salt, encrypted_key = data[:16], data[16:]
            passphrase = sg.popup_get_text("Passphrase for decryption:", password_char="*")
            private_key_content = derive_encrypt_decrypt_key(encrypted_key.decode(), passphrase, salt, True)
            window["-PRIVATE_KEY-"].update(private_key_content)

        elif selected_action == "Save Public Key":
            with open("public-key.txt", "w") as pub_file:
                pub_file.write(values["-PUBLIC_KEY-"])
            sg.popup("Public key saved successfully!")

        elif selected_action == "Save Private Key":
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

window.close()
