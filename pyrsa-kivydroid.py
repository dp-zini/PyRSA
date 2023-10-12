import base64
import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.spinner import Spinner
from kivy.uix.popup import Popup
from kivy.uix.checkbox import CheckBox
from kivy.core.clipboard import Clipboard
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

# boring math stuff

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

# main app

class PyRSA(App):
    public_key = None
    private_key = None

    def build(self):
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # choose encrypt/decrypt
        radio_layout = BoxLayout(size_hint=(1, None), height=30)
        self.encrypt_chk = CheckBox(group='encrypt_decrypt')
        self.decrypt_chk = CheckBox(group='encrypt_decrypt')
        radio_layout.add_widget(Label(text='Encrypt'))
        radio_layout.add_widget(self.encrypt_chk)
        radio_layout.add_widget(Label(text='Decrypt'))
        radio_layout.add_widget(self.decrypt_chk)
        self.layout.add_widget(radio_layout)
        
        # input plaintext
        self.layout.add_widget(Label(text='Message:'))
        self.txt_message = TextInput(multiline=True)
        self.layout.add_widget(self.txt_message)
        
        # show result
        self.layout.add_widget(Label(text='Result:'))
        self.txt_result = TextInput(multiline=True, readonly=True)
        self.layout.add_widget(self.txt_result)
        
        # public key input/display
        self.layout.add_widget(Label(text='Public Key:'))
        self.txt_public_key = TextInput(multiline=True)
        self.layout.add_widget(self.txt_public_key)
        
        # private key input/display
        self.layout.add_widget(Label(text='Private Key:'))
        self.txt_private_key = TextInput(multiline=True)
        self.layout.add_widget(self.txt_private_key)
        
        # dropdown menu
        self.action_spinner = Spinner(text="Process", values=("Process", "Generate Keys", "Clear", "Copy Results", "Copy Public Key", "Load Encrypted Key", "Save Public Key", "Save Private Key"))
        self.layout.add_widget(self.action_spinner)
        
        # buttons
        btn_layout = BoxLayout(size_hint=(1, None), height=300, spacing=10)
        btn_execute = Button(text="Execute")
        btn_execute.bind(on_press=self.execute_action)
        btn_layout.add_widget(btn_execute)

        btn_paste = Button(text="Paste")
        btn_paste.bind(on_press=self.paste_from_clipboard)
        btn_layout.add_widget(btn_paste)

        btn_clear_all = Button(text="Clear All")
        btn_clear_all.bind(on_press=self.clear_all_fields)
        btn_layout.add_widget(btn_clear_all)
        
        btn_exit = Button(text="Exit", background_color=(1,0,0,1))
        btn_exit.bind(on_press=self.exit_app)
        btn_layout.add_widget(btn_exit)

        self.layout.add_widget(btn_layout)

        return self.layout

    def execute_action(self, instance):
        message = self.txt_message.text.strip()
        action = self.action_spinner.text
        
        # do the thing
        if action == "Process":
            if self.encrypt_chk.active:
                # encrypt
                if self.public_key or self.txt_public_key.text:
                    try:
                        self.public_key = self.public_key or serialization.load_pem_public_key(self.txt_public_key.text.encode())
                        self.txt_result.text = encrypt_decrypt_message(self.public_key, message).hex()
                    except Exception as e:
                        self.display_popup("Error", str(e))
                else:
                    self.display_popup("Error", "Provide or generate a public key for encryption.")
            
            elif self.decrypt_chk.active:
                # decrypt
                if self.private_key or self.txt_private_key.text:
                    try:
                        self.private_key = self.private_key or serialization.load_pem_private_key(self.txt_private_key.text.encode(), None, default_backend())
                        decrypted_message = encrypt_decrypt_message(self.private_key, bytes.fromhex(message), False)
                        self.txt_result.text = decrypted_message
                    except Exception as e:
                        self.display_popup("Error", f"Decryption error: {str(e)}")
                else:
                    self.display_popup("Error", "Provide or generate a private key for decryption.")

        # generate keys
        elif action == "Generate Keys":
            self.public_key, self.private_key = generate_key_pair()
            self.txt_public_key.text = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            self.txt_private_key.text = self.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        
        # clear msg box
        elif action == "Clear":
            self.txt_message.text = ''
        
        # copy results
        elif action == "Copy Results":
            Clipboard.copy(self.txt_result.text)
        
        # copy public key
        elif action == "Copy Public Key":
            Clipboard.copy(self.txt_public_key.text)
        
        # load encrypted key with passphrase
        elif action == "Load Encrypted Key":
            try:
                with open("private-key.txt", "rb") as file:
                    data = file.read()
                    salt, encrypted_key = data[:16], data[16:]
                passphrase = self.display_popup_input("Input required", "Passphrase for decryption:")
                if passphrase:
                    private_key_content = derive_encrypt_decrypt_key(encrypted_key.decode(), passphrase, salt, True)
                    self.txt_private_key.text = private_key_content
            except Exception as e:
                self.display_popup("Error", str(e))
        
        # save public key
        elif action == "Save Public Key":
            with open("public-key.txt", "w") as pub_file:
                pub_file.write(self.txt_public_key.text)
            self.display_popup("Success", "Public key saved successfully!")
        
        # save private key
        elif action == "Save Private Key":
            with open("private-key.txt", "w") as priv_file:
                priv_file.write(self.txt_private_key.text)
            self.display_popup("Success", "Private key saved successfully!")

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

    def display_popup_input(self, title, message):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        layout.add_widget(Label(text=message))
        txt_input = TextInput(password=True, multiline=False)
        layout.add_widget(txt_input)

        btn = Button(text="Submit", size_hint=(1, 0.6))
        layout.add_widget(btn)
        
        popup = Popup(title=title, content=layout, size_hint=(0.8, 0.3), auto_dismiss=False)
        
        def close_popup(instance):
            popup.dismiss()
        btn.bind(on_press=close_popup)
        
        popup.open()
        popup.bind(on_dismiss=lambda _: setattr(self, '_popup_input_result', txt_input.text))
        return self._popup_input_result

    def exit_app(self, instance):
        App.get_running_app().stop()

if __name__ == '__main__':
    PyRSA().run()