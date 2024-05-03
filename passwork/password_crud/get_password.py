import os
import json
from loguru import logger
from passwork.passwork_api import PassworkAPI


def get_password(api: PassworkAPI,
                 password_id: str,
                 download_attachments_path: str = "",
                 log_pretty_data: bool = True) -> dict:

    """
    Retrieve password information from Passwork API.

    Args:
        api (PassworkAPI): An instance of PassworkAPI class initialized with appropriate credentials.
        password_id (str): The unique identifier of the password to retrieve.
        download_attachments_path (str): Path for downloading attachments.
        log_pretty_data (bool): Whether to log the retrieved password information. Defaults to True.

    Returns:
        dict: A dictionary containing the retrieved password information.

    This function authenticates with the Passwork API, retrieves password details, including associated vault,
    custom fields, attachments, and plaintext value. If specified, it
    logs this information using the logger.

    Example usage:
        api = PassworkAPI(credentials)\n
        password_info = get_password(api, 'password123')

    Raises:
        ValueError: If password_id is empty or None.
    """

    api.login()

    password_item = api.get_password(password_id=password_id)

    vault_id = password_item.get("vaultId")
    vault_item = api.get_vault(vault_id=vault_id)

    vault_password = api.get_vault_password(vault_item=vault_item)
    password_encryption_key = api.get_password_encryption_key(
        password_item=password_item, vault_password=vault_password
    )

    password_item["custom"] = api.get_customs(
        password_item=password_item, password_encryption_key=password_encryption_key
    )

    if not download_attachments_path:
        download_attachments_path = os.path.join("downloaded_attachments", password_id)

    api.get_attachments(
        password_item=password_item,
        password_encryption_key=password_encryption_key,
        download_path=download_attachments_path,
    )

    password_plain_text = api.get_password_plain_text(
        password_item=password_item, password_encryption_key=password_encryption_key
    )

    # receive full password info
    full_password_info = {
        "password": password_item,
        "vault": vault_item,
        "vaultMasterKey": vault_password,
        "passwordMasterKey": password_encryption_key,
        "passwordPlainText": password_plain_text,
    }

    pretty_data = json.dumps(full_password_info, indent=4)
    if log_pretty_data:
        logger.success(pretty_data)

    return full_password_info
