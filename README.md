# PyRSA

PyRSA provides a simple way to encrypt and decrypt RSA in python. 

## Key Features
- Quickly generate RSA key pairs.
- Support for custom RSA keys (PEM format only).
- Encrypt and decrypt messages seamlessly.
- Option to save and load encrypted private keys.

## Installation
PyRSA uses PySimpleGUI for the GUI, and also uses the cryptography library for encryption and decryption.

``` python
pip install PySimpleGUI cryptography
```
## Usage
``` python
$ python pyrsa.py
```
From the GUI:
- Select encryption or decryption
- Enter your message
- Generate RSA keys or input your own
- Process your input
- Copy the result, save the keys or clear the input box and do it all over again!

## Contributions
Feel free to contribute! There's probably some blatant security flaws in this lol, so take the code, edit it, use it in your own projects, do whatever! Just give proper attribution.

## License
Licensed under the MIT License, for more info see [LICENSE](https://github.com/dp-zini/PyRSA/blob/main/LICENSE)
