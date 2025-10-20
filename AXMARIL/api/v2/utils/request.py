import requests

def post(url: str, headers: dict, body: dict, params: dict = None):
    if params is None:
        response = requests.post(url, headers=headers, json=body, verify=False)
    else:
        response = requests.post(url, headers=headers, json=body, params=params, verify=False)
    return response
def get(url: str, headers: dict, params: dict = None):
    if params is None:
        response = requests.get(url, headers=headers, verify=False)
    else:
        response = requests.get(url, headers=headers, params=params, verify=False)
    return response

def delete(url: str, headers: dict, params: dict = None):
    if params is None:
        response = requests.delete(url, headers=headers)
    else:
        response = requests.delete(url, headers=headers, params=params)
    return response

def put(url: str, headers: dict, body: dict, params: dict = None):
    if params is None:
        response = requests.put(url, headers=headers, json=body)
    else:
        response = requests.put(url, headers=headers, json=body, params=params)
    return response

def patch(url: str, headers: dict, body: dict, params: dict = None):
    if params is None:
        response = requests.patch(url, headers=headers, json=body)
    else:
        response = requests.patch(url, headers=headers, json=body, params=params)
    return response
