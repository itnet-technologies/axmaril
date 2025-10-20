#!/bin/bash

# Définir le répertoire où se trouve guacd de manière dynamique
SCRIPT_DIR=$(dirname $(realpath $0))
echo "script dir : $SCRIPT_DIR"
echo "GUACD_HOME : /etc/guacamole"
#/home/ubuntu/api/modules/static/guacamole/etc/guacamole
# Définir le répertoire GUACD_HOME de manière relative
GUACD_HOME2="$SCRIPT_DIR/../bin"

# Ajouter le chemin des bibliothèques Guacamole à LD_LIBRARY_PATH
export LD_LIBRARY_PATH="$SCRIPT_DIR/../lib:$LD_LIBRARY_PATH"
export GUACD_HOME="/etc/guacamole"
printenv GUACD_HOME

# Spécifier le chemin du fichier de configuration de manière relative
export GUACD_CONFIG="/etc/guacamole/guacd.conf"

start_guacd() {
    # Vérifier si guacd est déjà en cours d'exécution
    if pgrep -x "guacd" > /dev/null; then
        echo "✔ guacd est déjà en cours d'exécution."
    else
        echo "➡ Démarrage de guacd..."
        export GUACD_CONFIG="/etc/guacamole/guacd.conf"
        "$GUACD_HOME2/guacd" &  # Démarre guacd avec le fichier de configuration spécifié
        echo "✔ guacd a été démarré avec succès."
    fi
}

stop_guacd() {
    # Arrêter guacd
    if pgrep -x "guacd" > /dev/null; then
        echo "➡ Arrêt de guacd..."
        pkill guacd  # Arrêter guacd
        echo "✔ guacd a été arrêté avec succès."
    else
        echo "❌ guacd n'est pas en cours d'exécution."
    fi
}

restart_guacd() {
    # Redémarrer guacd
    stop_guacd
    echo "Attente avant de redémarrer..."
    sleep 5
    start_guacd
    echo "guacd redémarré avec succès."
}

# Vérifier les arguments passés au script
if [ $# -lt 1 ]; then
    echo "❌ Aucun argument fourni, démarrage de guacd par défaut."
    action="start"
else
    action=$1
fi

# Exécuter l'action appropriée
case $action in
    start)
        start_guacd
        ;;
    stop)
        stop_guacd
        ;;
    restart)
        restart_guacd
        ;;
    *)
        echo "❌ Action inconnue : $action"
        exit 1
        ;;
esac
