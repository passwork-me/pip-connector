from loguru import logger
from passwork.passwork_api import PassworkAPI


def add_password(api: PassworkAPI, password_adding_fields: dict, vault_id: str = None, password_id: str = None) -> dict:
    """
    Add a new password to Passwork.

    Args:
        api (PassworkAPI): An instance of PassworkAPI class initialized with appropriate credentials.
        vault_id (str): The ID of the vault to add the password to. If not provided, the vault ID will be retrieved
                        from the password itself.
        password_id (str): The ID of an existing password. If provided, its vault ID will be used instead of vault_id.

        password_adding_fields (dict): Fields for the new password

    Returns:
        dict: Information about the added password.

    This function logs in to the Passwork API, adds a new password with the provided fields to the specified vault or
    the vault of an existing password. It then logs out from the API.

    Example usage:
        api = PassworkAPI(options_override=options_override)\n
        added_password_info = add_password(api, password_fields, vault_id=VAULT_ID, password_id=PASSWORD_ID)\n
        logger.success(f"Password with id {added_password_info['id']} has been added")
    """

    # password_adding_fields example:
    # {
    #     "name": "test",
    #     "url": "https://passwork.com",
    #     "login": "PassLogin",
    #     "description": "Password for testing",
    #     "folderId": None,
    #     "password": "password",
    #     "shortcutId": None,
    #     "tags": [],
    #     "snapshot": None,
    #     "color": "3",
    #     "custom": [
    #         {
    #             "name": "Additional login 1",
    #             "value": "PassLogin1",
    #             "type": "text"
    #         },
    #         {
    #             "name": "Additional password 1",
    #             "value": "password1",
    #             "type": "password"
    #         },
    #         {
    #             "name": "TOTP 1",
    #             "value": "JBSWY3DPEHPK3PXP",
    #             "type": "totp"
    #         }
    #     ],
    #     "attachments": [
    #         {
    #             "path": "../upload_attachments/file1.svg",
    #             "name": "file1.svg"
    #         },
    #         {
    #             "path": "../upload_attachments/file2.png",
    #             "name": "file2.png"
    #         }
    #     ]
    # }

    api.login()

    vault_id = vault_id if vault_id else api.get_password(password_id=password_id)["vaultId"]
    password_adding_fields["vaultId"] = vault_id
    vault_item = api.get_vault(vault_id=vault_id)
    vault_password = api.get_vault_password(vault_item=vault_item)

    added_password_info = api.add_password(password_adding_fields, vault_item, vault_password)
    logger.success(f"Password with id {added_password_info['id']} has been added")

    api.logout()

    return added_password_info
