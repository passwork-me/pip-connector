from loguru import logger
from passwork.passwork_api import PassworkAPI

def search_password(api: PassworkAPI, search_params: dict) -> list:
    """
    Search for passwords matching given criteria.

    REST Endpoint: POST /passwords/search

    Args:
        api (PassworkAPI): An instance of PassworkAPI class initialized with appropriate credentials.
        search_params (dict): Search criteria:
            {
                "query": str,
                "tags": list[str],
                "colors": list[str],
                "vaultId": str | None,
                "includeShared": bool,
                "includeShortcuts": bool
            }

    Returns:
        list: An array of password items.

    This function logs in to the Passwork API, searches for passwords based on the provided criteria,
    and then logs out from the API.

    Example usage:
        api = PassworkAPI(credentials)\n
        search_params = {"colors": [1, 3]}\n
        passwords = search_passwords(api, search_params)
    """
    # Login to the Passwork API
    api.login()

    # Search for passwords based on the provided criteria
    found_passwords = api.search_password(**search_params)

    # Log the found passwords if any
    if found_passwords:
        found_passwords_ids = [found_password["id"] for found_password in found_passwords]
        logger.success(f"Found password IDs: {', '.join(found_passwords_ids)}")
        for numb, found_password in enumerate(found_passwords):
            logger.success(f"Found password #{numb+1}/{len(found_passwords)}: {found_password}")

    # Logout from the Passwork API
    api.logout()

    return found_passwords
