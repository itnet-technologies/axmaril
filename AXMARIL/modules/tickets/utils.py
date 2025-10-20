import requests
import uuid
import os
from modules.required_packages import ObjectId

"""
altara_api_base = "http://localhost:4040/api/v1"
bucket_username = "aogoula@axe-tag.com"
bucket_password = "String1#"
bucket_id = "659fb7292a8b28b9f2839226"
bucket_workspace = "fdd_fdf_64765eadf9ce76ace79be945"


# Cette fonction retourne le token du compte sur lequel se trouve le container de stockage de fichier
def get_bucket_token(username, password, url):

    # Fonction pour effectuer la requete login sur Altara
    def login_request():
        credentials = {"email": username,"password": password}
        response = requests.post(url, json=credentials)
        return response
    
    initial_response = login_request()

    # Verifiez si la requete a reussi
    if initial_response.status_code == 200:

        # Recuperation de la reponse en json
        data = initial_response.json()

        # Extraction du token dans le data
        token = data.get("data", {}).get("user", {}).get("token")
        return token
    
    # Verifiez si la requete echoue
    if initial_response.status_code in [401, 403]:

        # Regenerer un nouveau token
        response = login_request()

        if response.status_code == 200:
            data = response.json()
            new_token = data.get("data", {}).get("user", {}).get("token")
            return new_token


# x_auth_token = get_bucket_token(bucket_username, bucket_password, f"{altara_api_base}/auth/login")
x_auth_token = None
print(x_auth_token)


def get_headers():
    headers = {
        "accept": "*/*",
        "Content-Type": "multipart/form-data",
        "Authorization": f"Bearer {x_auth_token}"
    }
    return headers


def format_filename(filename):
    import re
    cleaned_filename = re.sub(r'[\x00-\x1F\x7F/\x5C]', '-', filename)

    ascii_filename = cleaned_filename.encode('ascii', 'ignore').decode('ascii')

    formatted_filename = ascii_filename.replace('_', '-')

    return formatted_filename


def upload_files_to_bucket(files):
    all = []

    # Verifiez si aucun fichier n'existe
    if not files:
        return False, all

    # Parcourir la liste de fichiers
    for file in files:
        # Renommer les fichiers
        filename = f"{uuid.uuid4()}_{format_filename(file.filename)}"
        
        # Recuperer la taille de chaque fichier
        file_size = len(file.read())

        object_data = {
            "file": file,
            "object_name": filename,
            "object_size": file_size
        }

        print(object_data)

        # Uploader des fichiers sur objectstorage
        response = requests.post(
            f"{altara_api_base}/storage/v2/containers/{bucket_id}/objects/create",
            data=object_data,
            headers=get_headers()
        )

        print(response, response.json())

        if response.status_code == 200:
            data = response.json()
            object_id = data.get("data", {}).get("object_id")
            all.append(object_id)

    print(all)    
    return True, all
 """       

UPLOAD_FOLDER = 'modules/tickets/uploads'

def generate_file_url(filename):
    return f"/{UPLOAD_FOLDER}/{filename}"


def upload_files(files):
    from app import app
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    uploaded_files = []

    if not files:
        return uploaded_files

    for file in files:
        filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        url = generate_file_url(filename)
        uploaded_files.append({'id': str(ObjectId()), 'url': url})

    return uploaded_files
