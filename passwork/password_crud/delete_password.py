from passwork.passwork_api import PassworkAPI


def delete_password(api: PassworkAPI, password_id: str) -> None:
    """
    Delete a password from the Passwork API.

    Args:
        api (PassworkAPI): An instance of PassworkAPI class initialized with appropriate credentials.
        password_id (str): The unique identifier of the password to delete.

    This function logs in to the Passwork API, deletes the specified password using its unique identifier,
    and then logs out from the API.

    Example usage:
        api = PassworkAPI(credentials)\n
        delete_password(api, 'password123')

    Raises:
        ValueError: If password_id is empty or None.
    """

    api.login()

    # Delete the specified password
    api.delete_password(password_id=password_id)

    api.logout()
