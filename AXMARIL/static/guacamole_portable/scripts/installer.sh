#!/bin/bash
exec > script.log 2>&1

SCRIPT_DIR=$(dirname $(realpath $0))
USER=$(whoami)
echo $USER

echo $SCRIPT_DIR

# Parse arguments
dbpath=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -dbp|--dbpath)
      dbpath="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$dbpath" ]; then
    echo "Usage: $0 --dbpath <database_path>"
    exit 1
fi

# Define paths
BASEDIR="$SCRIPT_DIR/../mysql/mariadb-11.6.2"
MARIADB_INSTALL="$BASEDIR/scripts/mariadb-install-db"
MARIADB_SAFE="$BASEDIR/bin/mariadbd-safe"
MARIADB="$BASEDIR/bin/mariadb"
SQL_SCHEMA_FOLDER="$SCRIPT_DIR/../mysql/schemas"

# sudo -S chmod 777 $BASEDIR/lib/plugin/auth_pam_tool_dir/auth_pam_tool
# echo $SQL_SCHEMA_FOLDER
# INSTALLER_SH="$(dirname "$0")/guacamole_portable/scripts/installer.sh"

# Ensure database path exists
if [ ! -d "$dbpath" ]; then
    echo "Database path does not exist. Creating..."
    mkdir -p "$dbpath"
fi

# # Step 1: Initialize MySQL data directory
echo "Initializing MariaDB database..."
sudo $MARIADB_INSTALL --basedir="$BASEDIR" --datadir="$dbpath" --user="$USER"

# # Step 2: Start MariaDB
echo "Starting MariaDB..."
$MARIADB_SAFE --datadir="$dbpath" --user="$USER" &

# # Wait for MariaDB to fully start
sleep 10

echo "Creating database users..."

# Step 3: Set up MySQL root user and create database
# mysql_commands="
# ALTER USER 'root'@'localhost' IDENTIFIED BY 'Password01*';
# ALTER USER 'root'@'localhost' PASSWORD EXPIRE NEVER;
# CREATE DATABASE guacamole_db;
# CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'Password01*';
# GRANT ALL PRIVILEGES ON guacamole_db.* TO 'guacamole_user'@'localhost';
# FLUSH PRIVILEGES;
# EXIT;
# "

# echo "$mysql_commands" | $MARIADB -u $USER

# Step 4: Import Guacamole database schema
echo "Storing Guacamole database schema..."
echo $SQL_SCHEMA_FOLDER/000-create-database-user.sql
$MARIADB -u $USER < $SQL_SCHEMA_FOLDER/000-create-database-user.sql
sleep 3
$MARIADB -u guacamole_user -pPassword01* guacamole_db < $SQL_SCHEMA_FOLDER/001-create-schema.sql
sleep 3
$MARIADB -u guacamole_user -pPassword01* guacamole_db < $SQL_SCHEMA_FOLDER/002-create-admin-user.sql
# cat "$SQL_SCHEMA_FOLDER"/002-create-admin-user.sql | $MARIADB -u guacamole_user -p='Password01*'

# # Step 5: Run the installer script
# chmod +x "$INSTALLER_SH"
# "$INSTALLER_SH"

# sudo -S dpkg -i $SCRIPT_DIR/../deps/*.deb
cd $SCRIPT_DIR/../
echo "changing directory"
echo $(pwd)
sudo -S ./configure --with-init-dir=/etc/init.d --enable-allow-freerdp-snapshots
sudo -S make
sudo -S make install
sudo -S ldconfig
# sudo -S mkdir -p /etc/guacamole/{extensions,lib}
# sudo -S chmod -R 644 /etc/guacamole/*
# sudo -S chmod 755 /etc/guacamole/
# sudo -S cp $SCRIPT_DIR/../mysql/jar/mysql-connector-j-9.1.0.jar /etc/guacamole/lib/
# sudo -S cp $SCRIPT_DIR/../mysql/jar/guacamole-auth-jdbc-mysql-1.5.5.jar /etc/guacamole/extensions/
# sudo -S cp $SCRIPT_DIR/../guacamole_config_file/guacamole.properties /etc/guacamole/guacamole.properties
# sudo -S cp $SCRIPT_DIR/../guacamole_config_file/user-mapping.xml /etc/guacamole/
# sudo -S cp $SCRIPT_DIR/../guacamole_config_file/guacd.conf /etc/guacamole/
# sudo -S touch /etc/guacamole/already_installed.txt
# sudo -S sh $SCRIPT_DIR/run_tomcat.sh &
# sudo -S sh $SCRIPT_DIR/run_guacd.sh &
# echo "http://localhost:8080/guacamole"
echo "Installation completed."