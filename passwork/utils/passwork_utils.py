import re
from ..utils import crypto_interface

__all__ = [
    "get_encryption_key",
    "get_vault_password",
    "get_customs",
    "is_valid_totp",
    "use_key_encryption",
    "validate_customs",
    "encrypt_string",
    "encrypt_customs",
    "decrypt_string",
    "get_inbox_encryption_key"
]


def get_encryption_key(password: dict, vault_password: str, use_master_password: bool = False):
    if not use_master_password:
        return ""

    if password.get("cryptedKey"):
        if password.get("shortcut"):
            return crypto_interface.decrypt_aes(password["shortcut"]["cryptedKey"], vault_password)
        else:
            return crypto_interface.decrypt_aes(password["cryptedKey"], vault_password)
    else:
        return vault_password


def get_vault_password(vault: dict, master_key: str):
    password = vault.get("passwordCrypted") or vault.get("vaultPasswordCrypted")

    if vault.get("scope") == "domain":
        domain_master = crypto_interface.decrypt_aes(vault["domainMaster"], master_key)
        return crypto_interface.decrypt_aes(password, domain_master)
    else:
        return crypto_interface.decrypt_aes(password, master_key)


def get_customs(password_item: dict, password_master_key: str, options):
    if not password_item.get("custom"):
        return None
    return [
        {
            "name": decrypt_string(custom["name"], password_master_key, options),
            "type": decrypt_string(custom["type"], password_master_key, options),
            "value": decrypt_string(custom["value"], password_master_key, options),
        }
        for custom in password_item["custom"]
        if custom["name"] and custom["type"] and custom["value"]
    ]


def is_valid_totp(totp_value: str):
    regex = r"^([A-Za-z2-7=]{8})+$"
    return bool(re.match(regex, totp_value))


def use_key_encryption(vault: dict):
    return bool(vault.get("vaultPasswordCrypted"))


def validate_customs(customs: list):
    if any(f["type"] == "totp" and not is_valid_totp(f["value"]) for f in customs):
        raise Exception({"code": "invalidTotpFormat"})


def encrypt_string(string: str, encryption_key: str, options):
    if options.use_master_password:
        return crypto_interface.encrypt_aes(string, encryption_key)
    return crypto_interface.b64encode(string.encode()).decode()


def decrypt_string(string: str, encryption_key: str, options):
    if options.use_master_password:
        return crypto_interface.decrypt_aes(string, encryption_key)
    return crypto_interface.b64decode(string).decode()


def encrypt_customs(custom_fields: list, encryption_key: str, options):
    encrypted_fields = []
    for custom in custom_fields:
        encrypted_custom = {}
        for field, value in custom.items():
            if field not in ["name", "value", "type"]:
                encrypted_custom[field] = value  # Preserve these fields without encryption
            else:
                encrypted_custom[field] = encrypt_string(value, encryption_key, options)
        encrypted_fields.append(encrypted_custom)
    return encrypted_fields


def get_inbox_encryption_key(inbox_password, options):
    user_info = options.user_info
    if options.use_master_password:
        if not user_info.get("keys"):
            raise Exception({"code": "Can't fetch user private keys"})
        private_key = decrypt_string(user_info["keys"]["privateCrypted"], options.master_key, options)
        return crypto_interface.rsa_decrypt(inbox_password["cryptedKey"], private_key).decode()
    else:
        return ""
