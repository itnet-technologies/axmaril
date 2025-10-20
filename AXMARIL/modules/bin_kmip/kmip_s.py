from kmip.services.server import KmipServer
import logging
import sys
import os 
import argparse
from dotenv import load_dotenv


#parser = argparse.ArgumentParser(description="Démarrage du serveur KMIP avec un fichier .env.")
parser = argparse.ArgumentParser(description="Démarrage du serveur KMIP avec des options de ligne de commande.")

parser.add_argument("--config-path", type=str, help="Chemin vers le fichier de configuration.")
parser.add_argument("--log-path", type=str, help="Chemin vers le fichier de log.")
parser.add_argument("--policy-path", type=str, help="Chemin vers le fichier de politique.")
parser.add_argument("--tls-cipher-suites", type=str, help="Liste des suites de chiffrement TLS.")
parser.add_argument("--logging-level", type=str, default="DEBUG", help="Niveau de logging (par défaut : DEBUG).")
parser.add_argument("--tls", action="store_true", help="Activer TLS (par défaut : désactivé).")
parser.add_argument("--database-path", type=str, help="Chemin vers la base de données.")
parser.add_argument("--port", type=int, required=True, help="Port sur lequel le serveur écoute.")
# parser.add_argument(
#     "--env",
#     type=str,
#     default=".env",
#     help="Chemin vers le fichier .env (par défaut : .env)"
# )

args = parser.parse_args()

# Configurer le logging
logging.basicConfig(level=getattr(logging, args.logging_level.upper(), logging.DEBUG))

# missing_args = []

# if not os.path.exists(args.config_path):
#     missing_args.append(f"--config-path : {args.config_path} est introuvable.")
# if not os.path.exists(args.log_path):
#     missing_args.append(f"--log-path : {args.log_path} est introuvable.")
# if not os.path.exists(args.policy_path):
#     missing_args.append(f"--policy-path : {args.policy_path} est introuvable.")
# if not os.path.exists(args.database_path):
#     missing_args.append(f"--database-path : {args.database_path} est introuvable.")
# if args.port <= 0 or args.port > 65535:
#     missing_args.append("--port : doit être un entier entre 1 et 65535.")

# # Si des erreurs sont détectées, les afficher et terminer l'exécution
# if missing_args:
#     print("Erreur : les arguments suivants sont invalides ou manquants :")
#     for error in missing_args:
#         print(f"  - {error}")
#     sys.exit(1)
# if not os.path.exists(args.env):
#     print(f"Erreur : Le fichier .env spécifié ({args.env}) est introuvable.")
#     exit(1)
# else:
#     load_dotenv(args.env)
#     print(f"Fichier .env chargé depuis : {args.env}")


# CONFIG_PATH = os.getenv('CONFIG_PATH')
# LOG_PATH = os.getenv('LOG_PATH')
# POLICY_PATH = os.getenv('POLICY_PATH')
# TLS_CIPHER_SUITES = os.getenv('TLS_CIPHER_SUITES')
# LOGING_LEVEL = os.getenv('LOGING_LEVEL')
# TLS = bool(os.getenv('TLS'))
# DATABASE_PATH = os.getenv('DATABASE_PATH')
# PORT = int(os.getenv('PORT'))
# print(f"this is the port {PORT}")

if __name__ == '__main__':
    print("Initialisation du serveur KMIP...")
    try:
        server = KmipServer(
            hostname='0.0.0.0',
            port=args.port,
            auth_suite='TLS1.2',
            config_path=args.config_path,
            log_path=args.log_path,
            policy_path=args.policy_path,
            enable_tls_client_auth=args.tls,
            tls_cipher_suites=args.tls_cipher_suites,
            logging_level=args.logging_level,
            database_path=args.database_path
        )
        print("Serveur KMIP créé avec succès.")

        print("Démarrage du serveur KMIP...")
        server.start()  # Initialise le serveur et le socket.
        server.serve()  # Démarre le service et reste actif.
        
    except KeyboardInterrupt:
        print("Arrêt du serveur KMIP...")
        server.stop()  # Arrête le serveur proprement
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        logging.exception("Erreur lors du démarrage du serveur KMIP")