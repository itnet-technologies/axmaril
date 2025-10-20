# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: installer.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import subprocess
import time
import json
import shutil
import sys, getpass
import logging
import argparse
import psutil
import requests

def kill_main_process(process_name):
    print(f'trying to kill process {process_name}')
    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            if proc.info['name'] == process_name and (proc.ppid() == 1 or not any(proc.children())):
                print(f'Killing process: {proc.name()} (PID: {proc.pid})')
                proc.kill()
                return
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def kill_process_by_name_or_port(identifier):
    """
    Kill the main process based on the process name or port number.
    If a port number is given, find the process listening on that port.
    """
    if isinstance(identifier, int):
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == identifier:
                if conn.status == psutil.CONN_LISTEN:
                    process = psutil.Process(conn.pid)
                    print(f'Killing process on port {identifier}: {process.name()} (PID: {process.pid})')
                    process.kill()
                    return
        else:
            print(f'No process found listening on port {identifier}.')
    else:
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                if proc.info['name'] == identifier and (proc.ppid() == 1 or not any(proc.children())):
                    print(f'Killing process: {proc.name()} (PID: {proc.pid})')
                    proc.kill()
                    return
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        print(f'No process found with the name {identifier}.')
PARSER = argparse.ArgumentParser(description='axmaril installer')
PARSER.add_argument('-folder', '--installation-folder', help='installation folder')
PARSER.add_argument('-conf', '--config-file', help='the path of te config file')
PARSER.add_argument('-rhost', '--raft-host', help='the host of the raft')
PARSER.add_argument('-rpartners', '--raft-partners', help='the partners of raft host')
PARSER.add_argument('-license', '--license-file', help='license file path')
PARSER.add_argument('-maxkeys', '--max-keys', help='the maximum number of key when initialising')
PARSER.add_argument('-minkeys', '--min-keys', help='the maximum number of key when initialising')
PARSER.add_argument('-binpath', '--bin-path', help='path of the bin file')
PARSER.add_argument('-gdb', '--guacamole-database', help='path of the bin file')
PARSER.add_argument('-gdp', '--guacamole-db-path', help='path of the bin file')
PARSER.add_argument('-gif', '--guacamole-installation-folder', help='path of the bin file')
PARSER.add_argument('-lp', '--log-path', help='path of the bin file')
PARSER.add_argument('-gip', '--guacamole-installer', help='path of the bin file')
args = PARSER.parse_args()
args = vars(args)
logfile = args.get('log_path', None)
if logfile == "":
    logfile = None
if logfile is None:
    logfile = 'installer.log'
    
logging.basicConfig(filename=logfile, filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)

class StreamToLogger(object):

    def __init__(self, logger, log_level):
        self.logger = logger
        self.log_level = log_level
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.log_level, line.rstrip())

    def flush(self):
        return
sys.stdout = StreamToLogger(logging.getLogger('STDOUT'), logging.INFO)
sys.stderr = StreamToLogger(logging.getLogger('STDERR'), logging.ERROR)

def move_file(source):
    try:
        shutil.move(source, '/usr/local/bin')
        print(f'Moved {source} to /usr/local/bin')
    except Exception as e:
        print(f'Error moving file: {e}')

def install_guacamole():
    pass

def deploy_axmaril(args):
    print(args)
    parent_dir = args['installation_folder']
    conf_dir = args['config_file']
    raft_host = args.get('raft_host', None)
    raft_partners = args.get('raft_partners', None)
    license_file = args.get('license_file', None)
    gdbp = args.get('guacamole_db_path', None)
    gip = args.get('guacamole_installer', None)
    maxkeys = int(args['max_keys'])
    minkeys = int(args['min_keys'])
    bin_file = args['bin_path']
    full_path = parent_dir
    print(f'Création du dossier : {full_path}')
    os.makedirs(f'{full_path}', exist_ok=True)
    os.makedirs(f'{full_path}/data', exist_ok=True)
    os.makedirs(f'{full_path}/file_keys', exist_ok=True)
    environment_vars = {'AZUMARIL_INITIATOR_DBPATH': f'{full_path}'}
    if raft_host is not None and raft_host != '':
        environment_vars['RAFT_HOST'] = raft_host
        print(f'Saving raft host parameter : {raft_host}')
    if raft_partners is not None and raft_partners != '':
        environment_vars['RAFT_PARTNERS'] = raft_partners
        print(f'Saving raft partner parameter : {raft_partners}')
    if license_file is not None and license_file != '':
        environment_vars['LICENSE_FILE_PATH'] = license_file
        print(f'Saving license file parameter : {license_file}')
    for var_name, value in environment_vars.items():
        os.environ[var_name] = value
    print('Déplacement du fichier binaire et configuration des permissions...')
    subprocess.run(['sudo', 'mv', bin_file, '/usr/local/bin/axmaril'])
    subprocess.run(['sudo', 'chmod', 'a+x', '/usr/local/bin/axmaril'])
    print("Lancement de l'application Axmaril...")
    RH = environment_vars.get('RAFT_HOST', None) is not None
    RP = environment_vars.get('RAFT_PARTNERS', None) is not None
    LFP = environment_vars.get('LICENSE_FILE_PATH', None) is not None
    cluster_mode = RH and RP and LFP
    starter_command = ['axmaril']
    if cluster_mode:
        starter_command.append('--start-cluster')
    subprocess.Popen(starter_command)
    time.sleep(25)
    print("Initialisation de l'application...")
    init_data = {'minkey': minkeys, 'maxkey': maxkeys}
    print(init_data)
    response = requests.post('https://localhost:54321/initialise', json=init_data, verify=False)
    with open(f'{full_path}/file_keys/log.txt', 'w') as log_file:
        log_file.write(f'Status Code: {response.status_code}\n')
        log_file.write(f'Response: {response.text}\n')
    with open(f'{full_path}/file_keys/log.txt', 'r') as log_file:
        log_content = log_file.read()
    print(log_content)
    keys = log_content.split('"keys":[')[1].split(']')[0]
    key_list = [key.strip('"') for key in keys.split(',')]
    print('Clés extraites:')
    for key in key_list:
        print(key)
    selected_keys = key_list[:minkeys]
    keys_json = json.dumps(selected_keys)
    print(f'Clés pour unseal: {keys_json}')
    with open(conf_dir, 'r') as conf_file:
        config_data = conf_file.read()
    try:
        with open(conf_dir, 'r') as conf_file:
            config_data = json.load(conf_file)
    except json.JSONDecodeError:
        print(f'Error: Invalid JSON format in configuration file: {conf_dir}')
        return None
    unseal_data = {'keys': selected_keys, 'oneFile': True, 'config_data': config_data}
    print('Enregistremnt du fichier de configuration...')
    subprocess.run(['curl', '-k', '-i', '-X', 'POST', 'https://localhost:54321/config', '-H', 'Content-Type: application/json', '-d', json.dumps(unseal_data)])
    unseal_data = {'keys': selected_keys, 'oneFile': False, 'config_data': {}}
    subprocess.run(['curl', '-k', '-i', '-X', 'POST', 'https://localhost:54321/unseal', '-H', 'Content-Type: application/json', '-d', json.dumps(unseal_data)])
    axmaril_service_file = '/etc/systemd/system/axmaril.service'
    service_content = f"""\n[Unit]\nDescription="Azumaril manage your cloud server"\nDocumentation=https://www.vaultproject.io/docs/\nRequires=network-online.target\nAfter=network-online.target\n\n[Service]\nUser=root\nEnvironment="AZUMARIL_INITIATOR_DBPATH={full_path}"\nEnvironment="AZUMARIL_KEYS={','.join(selected_keys)}"\n    """
    if RH:
        service_content += f'\nEnvironment="RAFT_HOST={raft_host}'
    if RP:
        service_content += f'\nEnvironment="RAFT_PARTNERS={raft_partners}'
    if LFP:
        service_content += f'\nEnvironment="LICENSE_FILE_PATH={license_file}'
    if cluster_mode:
        service_content += '\nExecStart=/usr/local/bin/axmaril --start-cluster'
    else:
        service_content += '\nExecStart=/usr/local/bin/axmaril'
    service_content += '\nExecStop=pkill -9 axmaril\n\n[Install]\nWantedBy=multi-user.target\n    '
    with open(axmaril_service_file, 'w') as service_file:
        service_file.write(service_content)
    print(f'Fichier de service AXMARIL créé ou modifié : {axmaril_service_file}')
    subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
    subprocess.run(['sudo', 'systemctl', 'enable', 'axmaril'])
    print('Arrêt de tous les processus AXMARIL...')
    # guacamole_installer = os.path.dirname(__file__) + f"/guacamole_portable/installer"
    # print(f"guacamole installer bin path : {gip}")
        # installer = os.path.dirname(__file__) + f"/../static/installer"
    # password = getpass.getpass("Please enter admin password in order to setup guacamole correctly : ")

    # guacamole_installation = [gip, "--dbpath", gdbp]
    # # process = subprocess.Popen(["python", "-c", "print(input().upper())"], 
    # #                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    # process = subprocess.Popen(guacamole_installation, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # stdout, _ = process.communicate(password)  # Sending "hello" as input
    # print(stdout)
    
    # kill_main_process('axmaril')
    # kill_main_process('mongod')
    # kill_main_process('mongosh')
    # print('Tous les processus AXMARIL arrêtés.')
    # time.sleep(5)
    # subprocess.run(['sudo', 'systemctl', 'start', 'axmaril'])
    print('Service AXMARIL démarré et activé pour le démarrage automatique.')
    print("Déploiement d'AXMARIL terminé avec succès.")
deploy_axmaril(args)