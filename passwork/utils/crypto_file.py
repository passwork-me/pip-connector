import hashlib
import os

from loguru import logger
from pathlib import Path
from base64 import b64decode, b64encode

from ..utils.crypto_interface import decrypt_aes, encrypt_aes, generate_string


__all__ = [
    "encrypt_password_attachment",
    "decrypt_and_save_password_attachment",
    "format_attachments",
]


def read_file(filepath: str):
    with open(filepath, "rb") as file:
        return file.read()


def encode_file(data: bytes, passkey: str | None = None):
    if passkey is None:
        return b64encode(b64encode(data)).decode()
    else:
        return encrypt_aes(b64encode(data), passkey, is_bytes=True)


def get_string_from_blob(blob: bytes):
    result = "".join([chr(byte) for byte in blob])
    return result


def encrypt_password_attachment(buffer: bytes, password_encryption_key: str):
    if len(buffer) > 1024 * 1024 * 5:
        raise ValueError("Attached file max size is 5MB")

    if password_encryption_key:
        key = generate_string(length=100)
        encrypted_key = encrypt_aes(key, password_encryption_key)
        encrypted_data = encode_file(buffer, key)
    else:
        key = "a" * 32
        encrypted_key = b64encode(key.encode()).decode()
        encrypted_data = encode_file(buffer)

    blob_string = get_string_from_blob(buffer)
    computed_hash = hashlib.sha256(blob_string.encode()).hexdigest()
    return {
        "encryptedKey": encrypted_key,
        "encryptedData": encrypted_data,
        "hash": computed_hash,
    }


def decode_file(data: str, passkey: str | None = None):
    if passkey is None:
        decoded_data = b64decode(b64decode(data))
    else:
        decoded_data = b64decode(decrypt_aes(data, passkey, is_bytes=True))
    return decoded_data


def format_attachments(attachments: list, password_encryption_key: str):
    result = []
    for attachment in attachments:
        path, name = attachment["path"], attachment["name"]
        if not path:
            continue

        file_buffer = read_file(path)
        result.append(
            {
                **encrypt_password_attachment(file_buffer, password_encryption_key),
                "name": name if name else Path(path).stem,
            }
        )
    return result


def save_attachment(byte_data_content: bytes, filename: str, download_path: str):
    Path(download_path).mkdir(parents=True, exist_ok=True)
    download_path = os.path.join(download_path, filename)
    with open(download_path, "wb") as file:
        file.write(byte_data_content)

    logger.success(f"Decrypted file saved to {download_path}")


def decrypt_and_save_password_attachment(attachment: dict, password_encryption_key: str, download_path: str):
    if not attachment:
        return None

    key = decrypt_aes(attachment["encryptedKey"], password_encryption_key) if password_encryption_key else None
    byte_data = decode_file(attachment["encryptedData"], key)

    blob_string = get_string_from_blob(byte_data)
    computed_hash = hashlib.sha256(blob_string.encode()).hexdigest()

    if computed_hash != attachment["hash"]:
        raise Exception("Can't decrypt attachment: hashes are not equal")

    save_attachment(byte_data, attachment["name"], download_path)
