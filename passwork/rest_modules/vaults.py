import requests
import hashlib


from ..rest_modules import is_failed_status_code
from ..utils import decrypt_string, encrypt_string
from ..utils.passwork_utils import generate_vault_master_password, generate_vault_salt


def get_vault(vault_id: str, options):
    # receive vault item
    response = requests.get(
        url=f"{options.host}/vaults/{vault_id}",
        headers=options.request_headers,
    )
    if is_failed_status_code(prefix=f"Vault with ID {vault_id} not found", status_code=response.status_code):
        raise Exception
    return response.json().get("data")

def add_vault(name: str, is_private: bool, domain: dict,  options):
    fields = {
        "name": name,
        "isPrivate": is_private,
    }

    if not is_private:
        fields["domainId"] = domain.get("domainId")

    group_password = generate_vault_master_password()
    salt = generate_vault_salt()

    fields["salt"] = salt

    domain_master = decrypt_string(domain.get("mpCrypted"), options.master_key, options)

    fields["mpCrypted"] = encrypt_string(group_password, domain_master, options)
    fields["passwordHash"] = hashlib.sha256((group_password + salt).encode('utf-8')).hexdigest()

    if is_private:
        fields["passwordCrypted"] = encrypt_string(group_password, options.master_key, options)

    response = requests.post(
        url=f"{options.host}/vaults", json=fields, headers=options.request_headers
    )

    if is_failed_status_code(status_code=response.status_code, prefix="Error when adding a new vault", success_status_code=201):
        raise Exception

    return response.json().get("data")

def get_domain(options):
    response = requests.get(
        url=f"{options.host}/vaults/domain",
        headers=options.request_headers,
    )
    if is_failed_status_code(prefix=f"Failed to retrieve vault domain info", status_code=response.status_code):
        raise Exception
    return response.json().get("data")