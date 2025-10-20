#!/bin/bash

# Définir le répertoire du script (pour accéder aux fichiers extraits de manière dynamique)
SCRIPT_DIR=$(dirname $(realpath $0))
DEFAULT_USER=$(whoami)
MARIADB_SAFE="$SCRIPT_DIR/../mysql/mariadb-11.6.2/bin/mariadbd-safe"

# Variables par défaut
dbpath=""
db_user="$DEFAULT_USER"
db_password=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -dbp|--dbpath)
      dbpath="$2"
      shift 2
      ;;
    -u|--user)
      db_user="$2"
      shift 2
      ;;
    -p|--password)
      db_password="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Vérification des paramètres obligatoires
if [ -z "$dbpath" ]; then
    echo "Usage: $0 --dbpath <database_path> [--user <db_user>] [--password <db_password>]"
    exit 1
fi

# Lancer MariaDB avec les paramètres fournis  --password="$db_password"
$MARIADB_SAFE --datadir="$dbpath" --user="$db_user" &
