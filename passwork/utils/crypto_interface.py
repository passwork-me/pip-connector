import os
import re
import hashlib
import secrets
import binascii
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as padding_rsa
from cryptography.hazmat.backends import default_backend


from ..utils.base32 import base32


__all__ = [
    "encrypt_aes",
    "decrypt_aes",
    "generate_password",
    "get_master_key",
    "get_request_headers",
    "generate_string",
    "rsa_decrypt"
]


def evp_bytes_to_key(password: str, salt: bytes, key_len: int, iv_len: int):
    """
    OpenSSL key and IV generation
    """
    dt = d = b""
    while len(dt) < key_len + iv_len:
        # hash the input to generate enough bytes for key and IV
        d = hashlib.md5(d + password.encode() + salt).digest()
        dt += d
    return dt[:key_len], dt[key_len: key_len + iv_len]


def encrypt_aes(message: str | bytes, passphrase: str, is_bytes: bool = False):
    """
    Encrypts a message using AES in CBC mode with a key derived from the passphrase
    """

    salt = os.urandom(8)
    key_len = 32
    iv_len = 16
    key, iv = evp_bytes_to_key(passphrase, salt, key_len, iv_len)

    # AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    # pad the message
    padder = padding.PKCS7(128).padder()
    message = message if is_bytes else message.encode()
    padded_data = padder.update(message) + padder.finalize()

    # encrypt the padded message
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # add salt to ciphertext
    encrypted_data = b"Salted__" + salt + ciphertext
    encrypted_data_b64 = b64encode(encrypted_data)

    return base32.encode(encrypted_data_b64.decode())


def decrypt_aes(encrypted_data_b32: str, passphrase: str, is_bytes: bool = False):
    """
    Decrypts a message encrypted with AES in CBC mode using the passphrase
    """
    encrypted_data_b64 = base32.decode(encrypted_data_b32)
    encrypted_data = b64decode(encrypted_data_b64)

    # extract the salt and the ciphertext from the decoded data
    salt = encrypted_data[8:16]  # salt is after the "Salted__" marker
    ciphertext = encrypted_data[16:]

    key_len = 32
    iv_len = 16
    key, iv = evp_bytes_to_key(passphrase, salt, key_len, iv_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # decrypt and unpad the message
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext if is_bytes else plaintext.decode("utf-8")


def generate_string(length: int = 32):
    possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(possible) for _ in range(length))


def generate_password(length: int = 32):
    possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^"
    return "".join(secrets.choice(possible) for _ in range(length))


def get_master_key(mk_options: dict, master_password: str):
    # parse the PBKDF option
    pattern = r"^(?P<type>pbkdf):(?P<digest>.+):(?P<iterations>.+):(?P<bytes>.+):(?P<salt>.+)$"
    match = re.match(pattern, mk_options["mkOptions"], re.IGNORECASE | re.MULTILINE)

    if not match:
        raise ValueError("Match is not suited to pattern")

    mk_options = match.groupdict()

    salt = mk_options["salt"]
    iterations = int(mk_options["iterations"]) if mk_options.get("iterations") else 300000
    bytes_dklen = int(mk_options["bytes"]) if mk_options.get("bytes") else 64
    digest = "sha256"

    # get pbkdf master key
    dk = hashlib.pbkdf2_hmac(digest, master_password.encode(), salt.encode(), iterations, dklen=bytes_dklen)
    return binascii.b2a_base64(dk).decode().strip()


def get_request_headers(token: str, master_key: str, use_master_password: bool):
    headers = {"Passwork-Auth": token}

    if use_master_password:
        # calculate hash
        master_key_hash = hashlib.sha256(master_key.encode()).hexdigest()
        headers["Passwork-MasterHash"] = master_key_hash
    return headers


def rsa_decrypt(data, private_key):
    private_key = serialization.load_pem_private_key(
        private_key.encode(),  # Convert to bytes
        password=None
    )
    decrypted_data = private_key.decrypt(
        b64decode(data),
        padding_rsa.PKCS1v15()
    )
    return decrypted_data