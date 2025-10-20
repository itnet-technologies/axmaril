import os
import subprocess
import sys
import time  # Importer le module time

# Chemins locaux
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JAVA_HOME = os.path.join(SCRIPT_DIR, "java")  # Dossier Java portable
TOMCAT_HOME = os.path.join(SCRIPT_DIR, "tomcatapp")  # Dossier Tomcat portable

# Configuration des variables d'environnement
os.environ["JAVA_HOME"] = JAVA_HOME
os.environ["PATH"] = f"{JAVA_HOME}/bin:" + os.environ.get("PATH", "")

def check_java():
    """Vérifie si Java est fonctionnel à partir du dossier fourni."""
    try:
        subprocess.run(["java", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("✔ Java est installé et accessible.")
    except FileNotFoundError:
        print("❌ Java n'est pas accessible. Assurez-vous que le dossier Java est correct.")
        sys.exit(1)

def start_tomcat():
    """Démarre le serveur Tomcat."""
    startup_script = os.path.join(TOMCAT_HOME, "bin/startup.sh")
    if not os.path.exists(startup_script):
        print(f"❌ Le script de démarrage Tomcat est introuvable : {startup_script}")
        sys.exit(1)
    try:
        print("➡ Démarrage de Tomcat...")
        subprocess.run(["bash", startup_script], check=True)
        print("✔ Tomcat a été démarré avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors du démarrage de Tomcat : {e}")
        sys.exit(1)

def restart_tomcat():
    """Arrête et redémarre Tomcat."""
    print("Arrêt de Tomcat...")
    os.system("/home/ubuntu/script/tomcatapp/bin/shutdown.sh")
    time.sleep(5)  # Attente avant de redémarrer Tomcat
    print("Redémarrage de Tomcat...")
    os.system("/home/ubuntu/script/tomcatapp/bin/startup.sh")
    print("Tomcat redémarré avec succès.")

def stop_tomcat():
    """Arrête le serveur Tomcat."""
    shutdown_script = os.path.join(TOMCAT_HOME, "bin/shutdown.sh")
    if not os.path.exists(shutdown_script):
        print(f"❌ Le script d'arrêt Tomcat est introuvable : {shutdown_script}")
        sys.exit(1)
    try:
        print("➡ Arrêt de Tomcat...")
        subprocess.run(["bash", shutdown_script], check=True)
        print("✔ Tomcat a été arrêté avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'arrêt de Tomcat : {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Utilisation incorrecte. Exemples :")
        print("   python3 run_tomcat.py check_java")
        print("   python3 run_tomcat.py start")
        print("   python3 run_tomcat.py stop")
        sys.exit(1)

    action = sys.argv[1].lower()

    if action == "check_java":
        check_java()
    elif action == "start":
        check_java()
        start_tomcat()
    elif action == "stop":
        stop_tomcat()
    elif action == "restart":
        restart_tomcat()
    else:
        print(f"❌ Action inconnue : {action}")
        sys.exit(1)
