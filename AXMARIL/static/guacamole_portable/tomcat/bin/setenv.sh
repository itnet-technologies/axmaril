#!/bin/bash
#export JAVA_HOME="/opt/guacamole/java"
#export JRE_HOME="$JAVA_HOME"  # Si le répertoire jre/ n'existe pas
#!/bin/bash

# Définir JAVA_HOME et JRE_HOME en fonction du chemin d'extraction temporaire
SCRIPT_DIR=$(dirname $(realpath $0))
export JAVA_HOME="$SCRIPT_DIR/../../java"
export JRE_HOME="$JAVA_HOME"  # Si le répertoire jre/ n'existe pas
