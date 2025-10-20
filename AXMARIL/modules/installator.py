import subprocess, os, sys
import time, re, requests, argparse
import getpass, shutil

# PARSER = argparse.ArgumentParser(description="Seans-Python-Flask-REST-Boilerplate")
# # PARSER.add_argument('config','-config', helfvp='The api configirutation file')

# PARSER.add_argument("-dbp", "--dbpath", help="dbpath")
# PARSER.add_argument("-u", "--user", help="dbpath")
# PARSER.add_argument("-p", "--password", help="dbpath")
# PARSER.add_argument(
#     "--start-guacd",
#     action="store_true",
#     help="get the doc",
# )
# PARSER.add_argument(
#     "--start-tomcat",
#     action="store_true",
#     help="get the doc",
# )
# PARSER.add_argument(
#     "--start-maria",
#     action="store_true",
#     help="get the doc",
# )

# PARSER.add_argument(
#     "--launch-guacamole-service",
#     action="store_true",
#     help="get the doc",
# )

# args = PARSER.parse_args()
# # args = vars(args)
# # Accept unknown arguments
# args, unknown = PARSER.parse_known_args()

# print("Known arguments:", args)
# print("Unknown arguments:", unknown)

def copy_contents(src_folder, dest_folder):
    # Ensure destination folder exists
    os.makedirs(dest_folder, exist_ok=True)

    # Copy each file and folder inside the source
    for item in os.listdir(src_folder):
        src_path = os.path.join(src_folder, item)
        dest_path = os.path.join(dest_folder, item)

        if os.path.isdir(src_path):
            # Copy directories recursively
            shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
        else:
            # Copy individual files
            shutil.copy2(src_path, dest_path)

    print(f"Copied all contents from {src_folder} to {dest_folder}")

skip = False

# if args["start_guacd"]:
#     skip = True
#     process = subprocess.run(run_guacd, text=True, capture_output=True, shell=True)
#     print(process.stdout)
#     print(process.stderr)  # In case of errors
# if args["start_tomcat"]:
#     skip = True
#     process = subprocess.run(run_tomcat, text=True, capture_output=True, shell=True)
#     print(process.stdout)
#     print(process.stderr)  # In case of errors

# if args["start_maria"]:
#     skip = True
#     process = subprocess.run(run_maria, text=True, capture_output=True, shell=True)
#     print(process.stdout)
#     print(process.stderr)  # In case of errors

def install_db_user(initialization = False, dbpath = None, USER = None):
    BASEDIR = os.path.dirname(__file__) + f"/../static/guacamole_portable/mysql/mariadb-11.6.2"
    MARIADB_INSTALL = f"{BASEDIR}/scripts/mariadb-install-db"
    MARIADB_SAFE = f"{BASEDIR}/bin/mariadbd-safe"
    MARIADB = f"{BASEDIR}/bin/mariadb"
    SQL_SCHEMA_FOLDER = os.path.dirname(__file__) + f"/../static/guacamole_portable/mysql/schemas"
    
    if getattr(sys, 'frozen', False):
        BASEDIR = f"{sys._MEIPASS}/static/guacamole_portable/mysql/mariadb-11.6.2"
        MARIADB_INSTALL = f"{BASEDIR}/scripts/mariadb-install-db"
        MARIADB_SAFE = f"{BASEDIR}/bin/mariadbd-safe"
        MARIADB = f"{BASEDIR}/bin/mariadb"
        SQL_SCHEMA_FOLDER = f"{sys._MEIPASS}/static/guacamole_portable/mysql/schemas"
        
    # # Step 1: Initialize MySQL data directory
    # echo "Initializing MariaDB database..."
    if initialization:
        password = getpass.getpass("Please enter admin password in order to setup guacamole correctly : ")
        process = subprocess.run(f'sudo -S {MARIADB_INSTALL} --basedir="{BASEDIR}" --datadir="{dbpath}" --user="{USER}', input=password, text=True, capture_output=True, shell=True)
    # sudo $MARIADB_INSTALL --basedir="$BASEDIR" --datadir="$dbpath" --user="$USER"

    # # Step 2: Start MariaDB
    # echo "Starting MariaDB..."
    process = subprocess.run(f'{MARIADB} -u="{USER}" < {SQL_SCHEMA_FOLDER}/000-create-database-user.sql', text=True, capture_output=True, shell=True)
    print(process.stdout)
    print(process.stderr)
    process = subprocess.run(f'{MARIADB} -u="guacamole_user" -pPassword01* guacamole_db < {SQL_SCHEMA_FOLDER}/001-create-schema.sql', text=True, capture_output=True, shell=True)
    print(process.stdout)
    print(process.stderr)
    process = subprocess.run(f'{MARIADB} -u="guacamole_user" -pPassword01* guacamole_db < {SQL_SCHEMA_FOLDER}/002-create-admin-user.sql', text=True, capture_output=True, shell=True)
    print(process.stdout)
    print(process.stderr)
    # $MARIADB -u $USER < $SQL_SCHEMA_FOLDER/000-create-database-user.sql
    # sleep 3
    # $MARIADB -u guacamole_user -pPassword01* guacamole_db < $SQL_SCHEMA_FOLDER/001-create-schema.sql
    # sleep 3
    # $MARIADB -u guacamole_user -pPassword01* guacamole_db < $SQL_SCHEMA_FOLDER/002-create-admin-user.sql
    
def launch_guacamole_service(args):
    skip = True
    guacamole_config_folder = os.path.dirname(__file__) + f"/../static/guacamole_portable/guacamole_config_file"
    scripts = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/*.sh"
    installer_sh = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./installer.sh --dbpath {args['dbpath']}"
    run_guacd = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./run_guacd.sh"
    run_tomcat = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./run_tomcat.sh"
    run_maria = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./run_maria.sh --dbpath {args['dbpath']} --user {args['user']}"
    if getattr(sys, 'frozen', False):
        guacamole_config_folder = f"{sys._MEIPASS}/static/guacamole_portable/guacamole_config_file"
        installer_sh = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./installer.sh --dbpath {args['dbpath']}"
        run_guacd = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./run_guacd.sh"
        run_tomcat = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./run_tomcat.sh"
        run_maria = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./run_maria.sh --dbpath {args['dbpath']} --user {args['user']}"
        scripts = f"{sys._MEIPASS}/static/guacamole_portable/scripts/*.sh"

    installer_sh_file = installer_sh.replace("./", "").replace(f" --dbpath {args['dbpath']}", "")
    # password = getpass.getpass("Please enter admin password in order to setup guacamole correctly : ")
    process = subprocess.run(f"sudo kill -9 $(lsof -t -i:4822)", text=True, capture_output=True, shell=True)
    process = subprocess.run(f"sudo kill -9 $(lsof -t -i:3306)", text=True, capture_output=True, shell=True)
    process = subprocess.run(f"sudo kill -9 $(lsof -t -i:8080)", text=True, capture_output=True, shell=True)
    process = subprocess.run(f"sudo chmod +x {scripts}", text=True, capture_output=True, shell=True)
    process = subprocess.run(f"sudo chmod -R 777 {scripts.replace('/scripts/*.sh', '')}", text=True, capture_output=True, shell=True)
    process = subprocess.run(run_maria, text=True, capture_output=True, shell=True)
    print(process.stdout)
    print(process.stderr)  # In case of errors
    process = subprocess.run(run_tomcat, text=True, capture_output=True, shell=True)
    print(process.stdout)
    print(process.stderr)  # In case of errors
    process = subprocess.run(run_guacd, text=True, capture_output=True, shell=True)
    print(process.stdout)
    print(process.stderr)  # In case of errors

def run_installation(skip, args):
    guacamole_config_folder = os.path.dirname(__file__) + f"/../static/guacamole_portable/guacamole_config_file"
    scripts = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/*.sh"
    installer_sh = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./installer.sh --dbpath {args['dbpath']}"
    run_guacd = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./run_guacd.sh"
    run_tomcat = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./run_tomcat.sh"
    run_maria = os.path.dirname(__file__) + f"/../static/guacamole_portable/scripts/./run_maria.sh --dbpath {args['dbpath']} --user {args['user']}"
    if getattr(sys, 'frozen', False):
        guacamole_config_folder = f"{sys._MEIPASS}/static/guacamole_portable/guacamole_config_file"
        installer_sh = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./installer.sh --dbpath {args['dbpath']}"
        run_guacd = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./run_guacd.sh"
        run_tomcat = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./run_tomcat.sh"
        run_maria = f"{sys._MEIPASS}/static/guacamole_portable/scripts/./run_maria.sh --dbpath {args['dbpath']} --user {args['user']}"
        scripts = f"{sys._MEIPASS}/static/guacamole_portable/scripts/*.sh"

    installer_sh_file = installer_sh.replace("./", "").replace(f" --dbpath {args['dbpath']}", "")
    print(installer_sh)
    print(args)
    # sys.exit(1)
    if not skip:
        # password = getpass.getpass("Please enter admin password in order to setup guacamole correctly : ")
        pass

    if not skip :
        # os.makedirs("/etc/guacamole", exist_ok=True)
        copy_contents(guacamole_config_folder, "/etc/guacamole")
        # shutil.copytree(guacamole_config_folder, "/etc/guacamole")
        # shutil.copy2(src_file, dest_file)
        process = subprocess.run(f"sudo chmod -R 777 /etc/guacamole", text=True, capture_output=True, shell=True)#, input=password,
        process = subprocess.run(f"sudo chmod -R 777 /etc/guacamole", text=True, capture_output=True, shell=True)#, input=password,
        process = subprocess.run(f"sudo chmod +x {scripts}", text=True, capture_output=True, shell=True)#, input=password,
        process = subprocess.run(f"sudo chmod -R 777 {scripts.replace('/scripts/*.sh', '')}", text=True, capture_output=True, shell=True)#, input=password,
        process = subprocess.run(installer_sh, text=True, capture_output=True, shell=True)#, input=password,
        print(process.stdout)
        print(process.stderr)  # In case of errors
        process = subprocess.run(run_tomcat, text=True, capture_output=True, shell=True)#, input=password,
        print(process.stdout)
        print(process.stderr)  # In case of errors
        process = subprocess.run(run_guacd, text=True, capture_output=True, shell=True)#, input=password,
        print(process.stdout)
        print(process.stderr)  # In case of errors

# while True:
#     print("running..")
#     time.sleep(60)
# def installator(dbpath):

#     basedir = os.path.dirname(__file__) + f"/guacamole_portable/mysql/mariadb-11.6.2"
#     mariadb_install = f"{basedir}/scripts/mariadb-install-db"
#     mariadb_safe = os.path.dirname(__file__) + f"/guacamole_portable/mysql/mariadb-11.6.2/bin/mariadbd-safe"
#     mariadb = os.path.dirname(__file__) + f"/guacamole_portable/mysql/mariadb-11.6.2/bin/mariadb"
#     sql_schema_folder = os.path.dirname(__file__) + f"/guacamole_portable/mysql/schemas"

#     installer_sh = os.path.dirname(__file__) + f"/guacamole_portable/scripts/./installer.sh"
#     if getattr(sys, 'frozen', False):
#         # mongod_exe = f"{sys._MEIPASS}/guacamole_portable/mysql/mariadb-11.6.2/mongod"
#         basedir = f"{sys._MEIPASS}/guacamole_portable/mysql/mariadb-11.6.2"
#         mariadb_install = f"{basedir}/scripts/mariadb-install-db"
#         mariadb_safe = f"{sys._MEIPASS}/guacamole_portable/mysql/mariadb-11.6.2/bin/mariadbd-safe"
#         mariadb = f"{sys._MEIPASS}/guacamole_portable/mysql/mariadb-11.6.2/bin/mariadb"
#         sql_schema_folder = f"{sys._MEIPASS}/guacamole_portable/mysql/schemas"
#         installer_sh = f"{sys._MEIPASS}/guacamole_portable/scripts/./installer.sh"

#     if not os.path.exists(dbpath):
#         print("Database path not existing")
#         print("Generating database path")
#         os.mkdir(dbpath)

#     print("Initialising mysql database")
#     # Step 1: Initialize MySQL data directory and capture the temporary password
#     init_database_process = subprocess.Popen(
#         [
#             mariadb_install,
#             f"--basedir={basedir}",
#             f"--datadir={dbpath}"
#             "--user=$USER"
#         ],
#         stdout=subprocess.PIPE,
#         stderr=subprocess.PIPE
#     )
#     stdout, stderr = init_database_process.communicate()
#     print(stdout)
#     print(stderr)
#     print("Starting database")
#     start_database_process = subprocess.Popen(
#         [
#             mariadb_safe,
#             f"--datadir={dbpath}"
#         ],
#         stdout=subprocess.PIPE,
#         stderr=subprocess.PIPE
#     )
#     stdout, stderr = start_database_process.communicate()
#     print(stdout)
#     print(stderr)
    
#     print("waiting for mariadb to start..")
    
#     time.sleep(5)

#     print("Creating database users")
#     # Step 3: Set MySQL root password and disable expiration
#     mysql_commands = f"""
#     ALTER USER 'root'@'localhost' IDENTIFIED BY 'Password01*';
#     ALTER USER 'root'@'localhost' PASSWORD EXPIRE NEVER;
#     FLUSH PRIVILEGES;

#     CREATE DATABASE guacamole_db;
#     CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'Password01*';
#     GRANT ALL PRIVILEGES ON guacamole_db.* TO 'guacamole_user'@'localhost';
#     FLUSH PRIVILEGES;

#     EXIT;
#     """
#     r = subprocess.run(["whoami"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     user = r.stdout.replace("\n", "")
#     print(f"database user : {user}")
#     subprocess.run([mariadb, "-u", user], input=mysql_commands, text=True)

#     print("Storing guacamole database schema")
#     # cat *.sql | mysql -u root -p guac_db
#     subprocess.run(
#         [
#             "cat", 
#             f"{sql_schema_folder}/*.sql", 
#             "|", 
#             mariadb, 
#             "-u", 
#             "guacamole_user", 
#             "-p=Password01*", 
#             "guacamole_db"
#         ], 
#         text=True, 
#         stdout=subprocess.PIPE, 
#         stderr=subprocess.PIPE
#     )
#     # r = subprocess.run(["sudo", "chmod", "+x", installer_sh.replace("./", "")], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     r = subprocess.run([installer_sh], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     print(r.stdout)
#     print(r.stderr)
# installator(args["dbpath"])
# mysql_commands = "\n3621\n"
# r = subprocess.run(["sudo", "pwd"], text=True, stdout=subprocess.PIPE, input=mysql_commands, stderr=subprocess.PIPE)
# print(r.stdout)

# import subprocess
