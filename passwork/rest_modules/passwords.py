import requests
from loguru import logger

from ..rest_modules import is_failed_status_code
from ..utils import (
    generate_password,
    encrypt_string,
    use_key_encryption,
    validate_customs,
    encrypt_customs,
    format_attachments,
)


def get_password(options, password_id):
    # receive password item
    response = requests.get(
        url=f"{options.host}/passwords/{password_id}",
        headers=options.request_headers,
    )
    if is_failed_status_code(
        status_code=response.status_code,
        prefix=f"Password with ID {password_id} not found",
    ):
        raise Exception

    return response.json().get("data")


def get_attachments(password_item: dict, options):
    attachments = password_item.get("attachments")
    # receive attachments
    if not attachments:
        logger.warning(f"Password with ID {password_item.get('id')} has no attachments")
        return None

    return [
        get_attachment(password_item.get("id"), attachment["id"], options)
        for attachment in attachments
    ]


def get_attachment(password_id: str, attachment_id: str, options):
    response = requests.get(
        url=f"{options.host}/passwords/{password_id}/attachment/{attachment_id}",
        headers=options.request_headers,
    )

    if is_failed_status_code(
        status_code=response.status_code,
        prefix=f"Failed to get attachments for password ID {password_id}",
    ):
        raise Exception

    return response.json().get("data")


def search_passwords(options, search_params: dict):
    """
    search_params = {
        "query": "",
        "tags": [],
        "colors": [],
        "vaultId": None,
        "includeShared": False,
        "includeShortcuts": False,
    }
    """

    response = requests.post(
        url=f"{options.host}/passwords/search",
        json=search_params,
        headers=options.request_headers,
    )

    search_result = response.json().get("data")
    if not search_result:
        logger.warning("Passwords with the specified search parameters were not found")
    if isinstance(search_result, dict) and "errorMessage" in search_result:
        logger.error(search_result["errorMessage"])
        raise Exception
    return search_result


def add_password(fields: dict, vault: dict, vault_password: str, options):
    if not fields:
        fields = {}

    encryption_key = (
        generate_password() if options.use_master_password else vault_password
    )

    fields["cryptedPassword"] = encrypt_string(fields["password"], encryption_key, options)
    if use_key_encryption(vault):
        fields["cryptedKey"] = encrypt_string(encryption_key, vault_password, options)
    fields.pop("password", None)

    if "custom" in fields and len(fields["custom"]) > 0:
        validate_customs(fields["custom"])
        fields["custom"] = encrypt_customs(fields["custom"], encryption_key, options)

    if "attachments" in fields and len(fields["attachments"]) > 0:
        fields["attachments"] = format_attachments(fields["attachments"], encryption_key)

    fields.setdefault("name", "")

    response = requests.post(
        url=f"{options.host}/passwords", json=fields, headers=options.request_headers
    )

    if is_failed_status_code(
        status_code=response.status_code, prefix="Error when adding a new password"
    ):
        raise Exception

    return response.json().get("data")


def delete_password(password_id: str, options):
    response = requests.delete(
        url=f"{options.host}/passwords/{password_id}", headers=options.request_headers
    )

    if is_failed_status_code(
        status_code=response.status_code,
        prefix=f"Error when deleting password with id {password_id}",
    ):
        raise Exception

    logger.success(f"Deletion of password with id {password_id} completed successfully")


def get_inbox_passwords(options):
    response = requests.get(
        url=f"{options.host}/sharing/inbox/list", headers=options.request_headers
    )

    if is_failed_status_code(
        status_code=response.status_code,
        prefix=f"Error when getting list of inbox passwords",
    ):
        raise Exception

    return response.json().get("data")


def get_inbox_password(inbox_password_id, options):
    response = requests.post(
        url=f"{options.host}/sharing/inbox/{inbox_password_id}", headers=options.request_headers
    )

    if is_failed_status_code(
        status_code=response.status_code,
        prefix=f"Error when getting inbox password id: {inbox_password_id}",
    ):
        raise Exception

    inbox_password = response.json().get("data")
    return inbox_password
