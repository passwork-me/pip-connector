from .rest_modules.users import Users
from .utils import get_master_key, get_request_headers


class SessionOptions:
    """Stores data for making requests to the API and for encryption and decryption functions"""
    def __init__(self, host: str, api_key: str, master_password: str | None):
        self.user = Users(self)
        self.host = host
        self.api_key = api_key
        self.master_password = master_password
        self.use_master_password = True if self.master_password else False
        self.hash = "sha256"
        self.token = None
        self.refresh_token = None
        self.master_key = None
        self.request_headers = None
        self.user_info = None

    def login(self):
        """Log in to the API and retrieve tokens"""
        self.token, self.refresh_token = self.user.login()

    def logout(self):
        """Log out from the API"""
        self.user.logout()

    def get_user_info(self):
        """Get user info"""
        self.user_info = self.user.get_user_info()

    def create_headers(self):
        """Create headers for API requests"""
        mk_options = self.user.get_mk_options()
        self.master_key = get_master_key(mk_options, self.master_password) if mk_options.get("mkOptions") else None
        self.request_headers = get_request_headers(self.token, self.master_key, self.use_master_password)
