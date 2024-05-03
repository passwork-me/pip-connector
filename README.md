## About the API
Passwork API lets you retrieve, create, update passwords, folders and vaults. It is an easy way how you can integrate Passwork with your infrastructure. Use our Passwork Python Connector to make the integration smoother. The API operates behalf of the user whom API Key is used.
Check for all available methods in
[Passwork API Methods](passwork/passwork_api.py)

## How to install
⚠️<b style='color:YELLOW'>WARNING</b> the connector will not work with python version less than <b>3.10</b>
```shell script
pip install git+https://github.com/passwork-me/pip-connector
```

## Credentials
The following credentials are required for operation:

<b>host:</b> The address of the API server, like `https://.../api/v4` <br>
<b>api_key:</b> Your API key for authentication, instructions for obtaining below <br>
<b>master_password:</b> Client-side encryption key. Only add it when client-side encryption is enabled <br>

### API Key

![alt text](passwork/passwork.png)

- Sign in to your Passwork
- Menu → API Settings
- Enter your authorization key and generate the API Key

Method `login()` on instance of [PassworkAPI class](passwork/passwork_api.py) is used to retrieve a temporary API Token.
An API token is a session token. It is valid as long as you are accessing the API. After it expires, you will need to log in again.
API Token Lifetime can be set up in your Passwork.
The retrieved API token is stored as an instance variable named `session_options` within the [PassworkAPI class](passwork/passwork_api.py) and is subsequently sent in an HTTP header.

## Step-by-step guide

### Create session (common step for all operations)
0. Create instance of API connection and open session.

```python
from passwork.passwork_api import PassworkAPI

api = PassworkAPI(
    host="https://.../api/v4",
    api_key="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    master_password="master_password"
)

```

### [Password search by parameters](passwork/password_crud/search_password.py)

1. Fill data in `search_params` dict template with searching parameters to `search_password` method

```python
search_params = {
    "query": "test",
    "tags": [],
    "colors": [],
    "vaultId": None,
    "includeShared": False,
    "includeShortcuts": False,
}
```

2. Search password

```python
from passwork.password_crud import search_password
found_passwords = search_password(api, search_params)
```

### [Get full password info](passwork/password_crud/get_password.py)
<b style='color:green'>NOTE</b> `password_id` must contain the identifier of the target password, in the example a non-existent identifier is specified.</br>
<b style='color:green'>NOTE</b> `download_attachments_path` is not a required argument, without specifying it, attachments will be saved to <b>downloaded_attachments/{password_id}</b> folder.

1. Specify `password_id` and get full password info
```python
from passwork.password_crud import get_password

password_id = "0123456789abcdefghijklmn"
download_attachments_path = f"example_folder/{password_id}"

password_full_info = get_password(
    api=api,
    password_id=password_id,
    download_attachments_path=download_attachments_path,
    log_pretty_data=False,
)
```

### [Get inbox password info](passwork/password_crud/get_inbox_password.py)
<b style='color:green'>NOTE</b> Without explicitly specifying `inbox_password_id` information about existing passwords in the inbox will be logged.</br>
<b style='color:green'>NOTE</b> `download_attachments_path` is not a required argument, without specifying it, attachments will be saved to <b>downloaded_inbox_attachments/{password_id}</b> folder.
1. Get full inbox password info
```python
from passwork.password_crud import get_inbox_password

inbox_password_id = "0123456789abcdefghijklmn"
download_attachments_path = f"example_folder/{inbox_password_id}"

inbox_password_full_info = get_inbox_password(
    api=api,
    inbox_password_id=inbox_password_id,
    download_attachments_path=download_attachments_path,
    log_pretty_data=False,
)
```

### [Add password](passwork/password_crud/add_password.py)
<b style='color:green'>NOTE</b> If `vault_id` is specified, the `password_id` variable may be empty.
Without specifying of `vault_id`, the identifier of the vault where the password with id = `password_id` is stored will be taken. 
The identifiers `password_id` and `vault_id` in the example are non-existent.

1. Fill data in `password_adding_fields` dict template. Template is available in [add_password](passwork/password_crud/add_password.py) function
```python
password_adding_fields = {...}
```

2. Add password
```python
from passwork.password_crud import add_password

vault_id = "0123456789abcdefghijklmn"

added_password_info = add_password(
    api=api,
    password_adding_fields=password_adding_fields,
    vault_id=vault_id,
    )
```

### [Delete password](passwork/password_crud/delete_password.py)
<b style='color:green'>NOTE</b> `password_id` must contain the identifier of the target password, in the example a non-existent identifier is specified

1. Delete a password by its id
```python
from passwork.password_crud import delete_password

password_id = "0123456789abcdefghijklmn"

delete_password(api=api, password_id=password_id)
```

### License
This project is licensed under the terms of the MIT license.
