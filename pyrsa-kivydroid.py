import base64
import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.uix.checkbox import CheckBox
from kivy.core.clipboard import Clipboard
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return private_key.public_key(), private_key

def encrypt_decrypt_message(key, message, encrypt=True):
    method = key.encrypt if encrypt else key.decrypt
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    processed_message = method(message.encode() if encrypt else message, pad)
    return processed_message.decode() if not encrypt else processed_message.hex()

def derive_encrypt_decrypt_key(data, passphrase, salt=None, decrypt=False):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    cipher = Fernet(key)
    processed_data = (cipher.decrypt if decrypt else cipher.encrypt)(data.encode())
    return processed_data.decode() if decrypt else (salt + processed_data)

class PyRSA(App):
    public_key = None
    private_key = None

    def build(self):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        radio_layout = BoxLayout(size_hint=(1, None), height=30)
        self.encrypt_chk = CheckBox(group='encrypt_decrypt')
        self.decrypt_chk = CheckBox(group='encrypt_decrypt')
        radio_layout.add_widget(Label(text='Encrypt'))
        radio_layout.add_widget(self.encrypt_chk)
        radio_layout.add_widget(Label(text='Decrypt'))
        radio_layout.add_widget(self.decrypt_chk)
        layout.add_widget(radio_layout)

        layout.add_widget(Label(text='Message:'))
        self.txt_message = TextInput(multiline=True)
        layout.add_widget(self.txt_message)

        layout.add_widget(Label(text='Result:'))
        self.txt_result = TextInput(multiline=True, readonly=True)
        layout.add_widget(self.txt_result)

        layout.add_widget(Label(text='Public Key:'))
        self.txt_public_key = TextInput(multiline=True)
        layout.add_widget(self.txt_public_key)

        layout.add_widget(Label(text='Private Key:'))
        self.txt_private_key = TextInput(multiline=True)
        layout.add_widget(self.txt_private_key)

        self.action_spinner = Spinner(text="Process", values=("Process", "Generate Keys", "Clear", "Copy Results", "Copy Public Key", "Load Encrypted Key", "Save Private Key"))
        layout.add_widget(self.action_spinner)

        btn_layout = BoxLayout(size_hint=(1, None), height=300, spacing=10)
        btn_layout.add_widget(Button(text="Execute", on_press=self.execute_action))
        btn_layout.add_widget(Button(text="Paste", on_press=self.paste_from_clipboard))
        btn_layout.add_widget(Button(text="Clear All", on_press=self.clear_all_fields))
        btn_layout.add_widget(Button(text="Exit", background_color=(1,0,0,1), on_press=self.exit_app))
        layout.add_widget(btn_layout)

        return layout

    def execute_action(self, instance):
        message = self.txt_message.text.strip()
        action = self.action_spinner.text

        try:
            if action == "Process":
                self.process_action()
            elif action == "Generate Keys":
                self.generate_keys_action()
            elif action == "Clear":
                self.txt_message.text = ''
            elif action == "Copy Results":
                Clipboard.copy(self.txt_result.text)
            elif action == "Copy Public Key":
                Clipboard.copy(self.txt_public_key.text)
            elif action == "Load Encrypted Key":
                self.load_encrypted_key_action()
            elif action == "Save Private Key":
                self.display_popup_input("Input required", "Passphrase for encryption:", self.save_encrypted_private_key)
        except Exception as e:
            self.display_popup("Error", str(e))

    def process_action(self):
        if self.encrypt_chk.active:
            self.public_key = self.public_key or serialization.load_pem_public_key(self.txt_public_key.text.encode())
            self.txt_result.text = encrypt_decrypt_message(self.public_key, self.txt_message.text)
        elif self.decrypt_chk.active:
            self.private_key = self.private_key or serialization.load_pem_private_key(self.txt_private_key.text.encode(), None, default_backend())
            self.txt_result.text = encrypt_decrypt_message(self.private_key, bytes.fromhex(self.txt_message.text), False)

    def generate_keys_action(self):
        self.public_key, self.private_key = generate_key_pair()
        self.txt_public_key.text = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.txt_private_key.text = self.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    def load_encrypted_key_action(self):
        with open("private-key.txt", "rb") as file:
            data = file.read()
            encrypted_key = data[16:]
        
        def after_passphrase(passphrase):
            if passphrase:
                decrypted_key = derive_encrypt_decrypt_key(encrypted_key.decode(), passphrase, salt=data[:16], decrypt=True)
                self.txt_private_key.text = decrypted_key
                
        self.display_popup_input("Input required", "Passphrase for decryption:", after_passphrase)

    def save_encrypted_private_key(self, passphrase):
        if passphrase:
            encrypted_key = derive_encrypt_decrypt_key(self.txt_private_key.text, passphrase)
            with open("private-key.txt", "wb") as priv_file:
                priv_file.write(encrypted_key)
            self.display_popup("Success", "Encrypted private key saved successfully!")

    def paste_from_clipboard(self, instance):
        content = Clipboard.paste()
        self.txt_message.text = content

    def clear_all_fields(self, instance):
        self.txt_message.text = ''
        self.txt_result.text = ''
        self.txt_public_key.text = ''
        self.txt_private_key.text = ''

    def display_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(0.8, 0.4), auto_dismiss=True)
        popup.open()

    def display_popup_input(self, title, message, callback=None):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        layout.add_widget(Label(text=message))
        txt_input = TextInput(password=True, multiline=False)
        layout.add_widget(txt_input)
        btn = Button(text="Submit", size_hint=(1, 0.6), on_press=lambda _: (callback(txt_input.text) if callback else None, popup.dismiss()))
        layout.add_widget(btn)
        popup = Popup(title=title, content=layout, size_hint=(0.8, 0.3))
        popup.open()

    def exit_app(self, instance):
        App.get_running_app().stop()

if __name__ == '__main__':
    PyRSA().run()
