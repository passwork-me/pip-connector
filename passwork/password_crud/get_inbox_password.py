import os
import json
from loguru import logger
from passwork.passwork_api import PassworkAPI


def get_inbox_password(
        api: PassworkAPI,
        inbox_password_id: str = "",
        download_attachments_path: str = "",
        log_pretty_data: bool = True,
) -> dict | None:

    """
    Retrieve inbox password information from Passwork API.

    Args:
        api (PassworkAPI): An instance of PassworkAPI class initialized with appropriate credentials.
        inbox_password_id (str): The unique identifier of the password to retrieve.
        download_attachments_path (str): Path for downloading attachments.
        log_pretty_data (bool): Whether to log the retrieved password information. Defaults to True.

    Returns:
        dict: A dictionary containing the retrieved inbox password information.
        None: if inbox_password_id is not specified.

    This function authenticates with the Passwork API, retrieves inbox password details, including associated vault,
    custom fields, attachments, and plaintext value. If specified, it
    logs this information using the logger.

    Example usage:
        api = PassworkAPI(credentials)\n
        password_info = get_inbox_password(api, 'password123')

    Raises:
        ValueError: If inbox_password_id is empty or None.
    """

    api.login()
    api.get_user_info()

    if not inbox_password_id:
        inbox_passwords = api.get_inbox_passwords()

        if not inbox_passwords:
            logger.error("Inbox passwords not found")
            raise Exception

        logger.warning("inbox_password_id is not specified, here is information about existing passwords in the inbox:")

        found_inbox_passwords_ids = [inbox_password["id"] for inbox_password in inbox_passwords]
        logger.success(f"Found inbox password IDs: {', '.join(found_inbox_passwords_ids)}")
        for numb, inbox_password in enumerate(inbox_passwords):
            logger.success(f"Found inbox password #{numb + 1}/{len(inbox_passwords)}: {inbox_password}")
        return

    inbox_item = api.get_inbox_password(inbox_password_id)
    inbox_password_item = inbox_item["password"]
    encryption_key = api.get_inbox_encryption_key(inbox_item)

    # get inbox password customs
    inbox_password_item["custom"] = api.get_customs(
        password_item=inbox_password_item, password_encryption_key=encryption_key
    )

    if not download_attachments_path:
        download_attachments_path = os.path.join("downloaded_inbox_attachments", inbox_password_id)
    # download inbox password attachments
    api.get_attachments(
        password_item=inbox_password_item,
        password_encryption_key=encryption_key,
        download_path=download_attachments_path,
    )

    # get inbox password plain text
    password_plain_text = api.get_password_plain_text(
        password_item=inbox_password_item, password_encryption_key=encryption_key
    )

    # receive full inbox password info
    inbox_password_info = {
        "inbox_item": inbox_item,
        "passwordPlainText": password_plain_text,
    }

    pretty_data = json.dumps(inbox_password_info, indent=4)
    if log_pretty_data:
        logger.success(pretty_data)

    return inbox_password_info

