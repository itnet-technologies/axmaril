import json
import mysql.connector
from mysql.connector import Error

CONFIG_FILE_PATH = "/home/ubuntu/AXMARIL/static/config.json"

with open(CONFIG_FILE_PATH, 'r') as f:
    config = json.load(f)

def get_db_connection():
    try:
        user = config.get("MYSQL_USER")
        if user is None:
            raise ValueError("MYSQL_USER non défini dans la configuration")
        conn = mysql.connector.connect(
            host=config.get("MYSQL_HOST", "localhost"),
            user=user,
            password=config.get("MYSQL_PASSWORD"),
            database=config.get("MYSQL_DB", "guacamole_db"),
            port=int(config.get("MYSQL_PORT", 3306))
        )
        return conn
    except Error as e:
        print(f"Erreur de connexion à la BDD: {e}")
        raise
