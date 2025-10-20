#!/bin/bash

# Définir le répertoire du script (pour accéder aux fichiers extraits de manière dynamique)
SCRIPT_DIR=$(dirname $(realpath $0))
echo $SCRIPT_DIR
# Utilisation des chemins relatifs pour accéder aux fichiers extraits
JAVA_HOME="$SCRIPT_DIR/../java"  # Java dans le répertoire où le binaire est extrait
CATALINA_HOME="$SCRIPT_DIR/../tomcat"  # Tomcat dans le même répertoire
JRE_HOME="$JAVA_HOME"

# Ajouter JAVA_HOME au PATH
export JAVA_HOME
export JRE_HOME
export PATH="$JAVA_HOME/bin:$PATH"

check_java() {
    # Vérifier si Java est installé
    if java -version &>/dev/null; then
        echo "✔ Java est installé et accessible."
    else
        echo "❌ Java n'est pas accessible. Assurez-vous que le dossier Java est correct."
        exit 1
    fi
}

start_tomcat() {
    # Démarrer Tomcat
    STARTUP_SCRIPT="$CATALINA_HOME/bin/startup.sh"
    if [ ! -f "$STARTUP_SCRIPT" ]; then
        echo "❌ Le script de démarrage Tomcat est introuvable : $STARTUP_SCRIPT"
        exit 1
    fi
    echo "➡ Démarrage de Tomcat..."
    bash "$STARTUP_SCRIPT" > tomcat.log
    echo "✔ Tomcat a été démarré avec succès."
}

stop_tomcat() {
    # Arrêter Tomcat
    SHUTDOWN_SCRIPT="$CATALINA_HOME/bin/shutdown.sh"
    if [ ! -f "$SHUTDOWN_SCRIPT" ]; then
        echo "❌ Le script d'arrêt Tomcat est introuvable : $SHUTDOWN_SCRIPT"
        exit 1
    fi
    echo "➡ Arrêt de Tomcat..."
    bash "$SHUTDOWN_SCRIPT"
    echo "✔ Tomcat a été arrêté avec succès."
}

restart_tomcat() {
    # Redémarrer Tomcat
    stop_tomcat
    echo "Attente avant de redémarrer..."
    sleep 5
    start_tomcat
    echo "Tomcat redémarré avec succès."
}

# Vérifier les arguments passés au script
if [ $# -lt 1 ]; then
    echo "❌ Aucun argument fourni, démarrage de Tomcat par défaut."
    action="start"
else
    action=$1
fi

# Exécuter l'action appropriée
case $action in
    check_java)
        check_java
        ;;
    start)
        check_java
        start_tomcat
        ;;
    stop)
        stop_tomcat
        ;;
    restart)
        restart_tomcat
        ;;
    *)
        echo "❌ Action inconnue : $action"
        exit 1
        ;;
esac
