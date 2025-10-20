import subprocess
import sys
import time
import sys
import os
import getpass
import traceback
from dotenv import load_dotenv
from pathlib import Path
#from required_packages import KMIP_ENABLED



def commander(KMIP_ENABLED):
    # command = [f"/home/itnet/Azumaril/static/shamir2.py"]
    command = [os.path.dirname(__file__) + "/../static/kmip"]
    if getattr(sys, 'frozen', False):
        command[0] = f"{sys._MEIPASS}/static/kmip"
    #command += arg_list
    if KMIP_ENABLED is True:
        print(command)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )
            print("Commande exécutée avec succès :", result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors de l'exécution de la commande : {e.stderr}")
        
commander(True)