from kmip.services.server import KmipServer
import logging
import sys
import os 

# Configurer le logging
logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    print("Initialisation du serveur KMIP...")

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5696 

    try:
        server = KmipServer(
            hostname='0.0.0.0',
            port=port,
            auth_suite='TLS1.2',
            config_path='/home/AZUMARIL/modules/kmip_etc/server.conf',
            log_path='/home/AZUMARIL/modules/kmip_etc/server.log',
            policy_path='/home/AZUMARIL/modules/kmip_etc/policies',
            enable_tls_client_auth=False,
            tls_cipher_suites='ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256',
            logging_level='DEBUG',
            database_path='/tmp/pykmip.db'
        )
        print("Serveur KMIP créé avec succès.")

        print("Démarrage du serveur KMIP...")
        server.start()  # Initialise le serveur et le socket.
        server.serve()  # Démarre le service et reste actif.
        print("Serveur KMIP démarré avec succès.")
        
    except KeyboardInterrupt:
        print("Arrêt du serveur KMIP...")
        server.stop()  # Arrête le serveur proprement
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        logging.exception("Erreur lors du démarrage du serveur KMIP")

