from datetime import datetime
from api.v2.utils.request import post, get
from api.v2.utils.custom_exception import LoginFailed, ErrorOccurred

class CyberArk:
    def __init__(self, credentials: dict = {}, token: str = None)-> None:
        self.username = credentials.get('username')
        self.password = credentials.get('password')
        self.hostname = credentials.get('hostname')
        self.token = token
        self.headers = {
            'Accept': 'application/json'
        }
        self.connected = False
        if self.hostname is None:
            # raise Exception("The hostname is empty")
            return False
        if (self.username is None or self.password is None):
            if self.token is None:
                return False
                # raise Exception("You should set username and password or token")

        # if not (self.username and self.password and self.hostname) or not self.token:

    def __str__(self):
        return 'cyberark'

    def connect(self) -> bool:
        body = {'UserName': self.username, 'Password': self.password}
        response = post(f'{self.hostname}/PasswordVault/api/Auth/cyberark/Logon', self.headers, body)
        response_json = response.json()
        if response.status_code != 200:
            return False, response_json.get('ErrorMessage', 'Login failed')
        self.token = response.text.strip('"')
        self.headers['Authorization'] = self.token
        self.connected = True
        return True, None

    def get_safes(self) -> dict:
        response = get(f'{self.hostname}/PasswordVault/api/Safes', self.headers)
        if response.status_code == 401:
            self.connect()
            response = get(f'{self.hostname}/PasswordVault/api/Safes', self.headers)

        if response.status_code == 200:
            return True, response.json()
        else:
            return False, "An error occured when tying access your safes. Please check your account info or right"

    def get_safe_by_id(self, safe_id) -> dict:
        response = get(f'{self.hostname}/PasswordVault/api/Safes/{safe_id}', self.headers, {'includeAccounts': 'true'})
        if response.status_code == 401:
            self.connect()
            response = get(f'{self.hostname}/PasswordVault/api/Safes/{safe_id}', self.headers, {'includeAccounts': 'true'})

        if response.status_code == 200:
            return True, response.json()
        else:
            return False, f"An error occured when tying access to {safe_id}. Please check your account info or right"

    def get_secret_by_id(self, secret_id) -> dict:
        response = get(f'{self.hostname}/PasswordVault/api/Accounts/{secret_id}', self.headers)
        if response.status_code == 401:
            self.connect()
            response = get(f'{self.hostname}/PasswordVault/api/Accounts/{secret_id}', self.headers)
        if response.status_code == 200:
            to_return = response.json()
            body = {'Reason': f'Access to my secret at {str(datetime.utcnow())}', 'ActionType': 'Show'}
            get_secret_request = post(f'{self.hostname}/PasswordVault/api/Accounts/{secret_id}/Secret/Retrieve', self.headers, body=body)
            if get_secret_request.status_code == 401:
                self.connect()
                get_secret_request = post(f'{self.hostname}/PasswordVault/api/Accounts/{secret_id}/Secret/Retrieve', self.headers, body=body)
            if get_secret_request.status_code != 200:
                to_return['secret'] = None
            else:
                to_return['secret'] = get_secret_request.text

            return True, to_return
        else:
            return False, f"An error occured when tying access to {secret_id}. Please check your account info or right"

    def disconnect(self):
        response = post(f'{self.hostname}/PasswordVault/api/Auth/cyberark/Logoff', self.headers, {})
        self.token = response.text.strip('"')
        self.headers['Authorization'] = None
        self.connected = False

# try:
#     cyb = CyberArk({'username': 'axetag', 'password': 'Azerty123456*', 'hostname': 'https://axetag.trustmycloud.com'})
#     cyb.connect()
#     # print(cyb.get_safes())
#     # print(cyb.get_safe('VaultInternal'))
#     print(cyb.get_secret('2_6'))
# except LoginFailed as e:
#     print('Login failed')
# except Exception as e:
#     print(str(e))