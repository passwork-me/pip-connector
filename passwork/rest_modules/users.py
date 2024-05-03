import requests

from ..rest_modules import is_failed_status_code, is_failed_log_in_status_code


class Users:
    def __init__(self, options):
        self.options = options

    def login(self):
        url = f"{self.options.host}/auth/login/{self.options.api_key}"
        response = requests.post(
            url=url,
            json={"useMasterPassword": self.options.use_master_password},
        )
        if is_failed_log_in_status_code(status_code=response.status_code):
            raise Exception
        tokens = response.json().get("data")
        token, refresh_token = tokens.get("token"), tokens.get("refreshToken")

        return token, refresh_token

    def get_mk_options(self):
        # PBKDF option
        response = requests.get(
            url=f"{self.options.host}/user/get-master-key-options",
            headers={"Passwork-Auth": self.options.token},
        )
        if is_failed_status_code(
            prefix="Failed to retrieve master key options",
            status_code=response.status_code,
        ):
            raise Exception
        return response.json().get("data")

    def logout(self):
        response = requests.post(
            url=f"{self.options.host}/auth/logout",
            headers={"Passwork-Auth": self.options.token},
        )
        if is_failed_status_code(prefix="Failed to log out", status_code=response.status_code):
            raise Exception
        return response.json().get("data")

    def get_user_info(self):
        response = requests.get(
            url=f"{self.options.host}/user/info",
            headers=self.options.request_headers,
        )
        if is_failed_status_code(prefix="Failed to get user info", status_code=response.status_code):
            raise Exception
        return response.json().get("data")
