import requests
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256


class ClearKey_RSA:
    def __init__(
            self,
            key_length=2048
    ):
        """
        Decrypts RSA encrypted ClearKey responses
        Author: github.com/DevLARLEY
        """
        self.private_key = RSA.generate(key_length)
        self.public_key = self.private_key.publickey()

    def export_spki(self) -> str:
        spki = self.public_key.export_key(format='DER')
        return base64.b64encode(spki).decode('utf-8')

    @staticmethod
    def pad_b64_to_bytes(encoded_str):
        return base64.b64decode(encoded_str.replace('-', '+').replace('_', '/') + '==')

    def decrypt_key(self, b64_key: str) -> bytes:
        cipher = PKCS1_OAEP.new(self.private_key, hashAlgo=SHA256)
        return cipher.decrypt(self.pad_b64_to_bytes(b64_key))


if __name__ == '__main__':
    rsa = ClearKey_RSA()

    response = requests.post(
        'https://<clearkey api endpoint>',
        json={
            "kids": [
                # Key IDs and split up json
            ],
            "type": "temporary",
            "spki": rsa.export_spki()
        }
    )

    data = response.json()

    for key_data in data['keys']:
        kid_hex = rsa.pad_b64_to_bytes(key_data['kid']).hex()
        decrypted_hex = rsa.decrypt_key(key_data['k']).hex()

        print(f"{kid_hex}:{decrypted_hex}")
