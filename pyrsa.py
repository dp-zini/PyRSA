from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import PySimpleGUI as sg

# generates keys
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

# encrypts w/ public key
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# decrypts w/ private key
def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# sets theme full list https://www.geeksforgeeks.org/themes-in-pysimplegui/
sg.theme('DarkBlack')

# designates layout
layout = [
    [sg.Radio("Encrypt", "Radio1", default=True, key="-ENCRYPT-"), sg.Radio("Decrypt", "Radio1", key="-DECRYPT-")],
    [sg.Text("Enter Message:")],
    [sg.Multiline(key="-MESSAGE-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Text("Result:")],
    [sg.Multiline(key="-RESULT-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Text("Public Key (PEM format):")],
    [sg.Multiline(key="-PUBLIC_KEY-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Text("Private Key (PEM format):")],
    [sg.Multiline(key="-PRIVATE_KEY-", size=(40, 5), expand_x=True, expand_y=True)],
    [sg.Button("Process"), sg.Button("Generate Keys"), sg.Button("Clear"), sg.Button("Copy Results"),
     sg.Button("Copy Public Key"), sg.Button("Copy Private Key"), sg.Button("Save Keys"), sg.Exit()]
]

window = sg.Window("PyRSA", layout, resizable=True, default_element_size=(14, 1))

public_key = None
private_key = None

while True:
    event, values = window.read()

    # exits when you exit
    if event == sg.WIN_CLOSED or event == "Exit":
        break

    # generate key button
    if event == "Generate Keys":
        public_key, private_key = generate_key_pair()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        window["-PUBLIC_KEY-"].update(public_pem)
        window["-PRIVATE_KEY-"].update(private_pem)

    # saves the keys
    if event == "Save Keys":
        if values["-PUBLIC_KEY-"] and values["-PRIVATE_KEY-"]:
            with open("public-key.txt", "w") as pub_file:
                pub_file.write(values["-PUBLIC_KEY-"])
            with open("private-key.txt", "w") as priv_file:
                priv_file.write(values["-PRIVATE_KEY-"])
            sg.popup("Keys saved successfully!")
        else:
            sg.popup_error("Please provide or generate keys before saving.")

    # encrypt or decrypt selection
    if event == "Process":
        message = values["-MESSAGE-"].strip()

        if not message:
            sg.popup_error("Please enter a message.")
            continue

        # Use custom inputted keys if they exist, otherwise use the generated ones
        if not public_key and values["-PUBLIC_KEY-"]:
            try:
                public_key = serialization.load_pem_public_key(values["-PUBLIC_KEY-"].encode())
            except Exception as e:
                sg.popup_error(f"Error with the provided public key: {str(e)}")
                continue

        if not private_key and values["-PRIVATE_KEY-"]:
            try:
                private_key = serialization.load_pem_private_key(values["-PRIVATE_KEY-"].encode(), None, default_backend())
            except Exception as e:
                sg.popup_error(f"Error with the provided private key: {str(e)}")
                continue

        if values["-ENCRYPT-"]:
            if not public_key:
                sg.popup_error("Please generate or provide a valid public key.")
                continue

            ciphertext = encrypt_message(public_key, message)
            window["-RESULT-"].update(ciphertext.hex())

        elif values["-DECRYPT-"]:
            if not private_key:
                sg.popup_error("Please generate or provide a valid private key.")
                continue

            try:
                ciphertext = bytes.fromhex(message)
                plaintext = decrypt_message(private_key, ciphertext)
                window["-RESULT-"].update(plaintext)
            except Exception as e:
                sg.popup_error(f"Decryption error: {str(e)}")

    # clears msg when button is pressed
    if event == "Clear":
        window["-MESSAGE-"].update("")

    # copy to clipboard when button is pressed
    if event == "Copy Results":
        result_text = values["-RESULT-"]
        sg.clipboard_set(result_text)

    if event == "Copy Public Key":
        public_key_text = values["-PUBLIC_KEY-"]
        sg.clipboard_set(public_key_text)

    if event == "Copy Private Key":
        private_key_text = values["-PRIVATE_KEY-"]
        sg.clipboard_set(private_key_text)

window.close()
