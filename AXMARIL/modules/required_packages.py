import ast
from base64 import b64decode
from binascii import unhexlify
import getpass
import mimetypes
import string
from distutils import extension
import hashlib
import os
import signal 
import socket
import random
import re
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import subprocess
import sys
import threading
import io
import configparser
import traceback
import uuid

import rsa
from flask import jsonify, request, Blueprint, url_for, redirect, send_file, session
import httpx
import pymongo
from datetime import datetime, timedelta
import jwt
import requests
from modules.shamir_loader import loader, commander, reinit, loader_v2
from password_strength import PasswordPolicy
from bson import json_util, ObjectId
import json
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from pathlib import Path
import argparse
from modules.installator import run_installation, launch_guacamole_service, install_db_user

from captcha.image import ImageCaptcha
from flask import Flask, send_from_directory, render_template, after_this_request
from modules.initializer import initEnv
import psutil
# ---new-----
# import socket
# import random
import distro
from gevent.pywsgi import WSGIServer
import http.server
from OpenSSL import crypto
import ssl
import gunicorn.app.base
import socketserver
from typing import Final
import pyotp, time
from threading import Thread
from functools import wraps
from ldap3.utils.hashed import hashed
from random import randint
from ldap3.core.exceptions import LDAPException
from ldap3.extend.microsoft.addMembersToGroups import (
    ad_add_members_to_groups as addUsersInGroups,
)
import pathlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from ldap3 import (
    LEVEL,
    MODIFY_ADD,
    MODIFY_REPLACE,
    MODIFY_DELETE,
    Server,
    Connection,
    ALL,
    SUBTREE,
    ALL_ATTRIBUTES,
    HASHED_SALTED_SHA,
)
from flask_cors import CORS
from mongita import MongitaClientDisk
# from .raft.raft import is_leader
from typing import Dict, List, Union
from pysyncobj import SyncObjConf
from pysyncobj import SyncObj
from pysyncobj import replicated, SyncObjConsumer
from pysyncobj.batteries import ReplCounter, ReplDict
import zipfile
import shutil
from flask_caching import Cache
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})

# from kmip.services.server import KmipServer
import logging


# Configurer le logging
# logging.basicConfig(level=logging.DEBUG)

# counter1 = None
# counter2 = None
# dict1 = None

# def updater(c1, c2, d1):
#     global counter1 
#     global counter2 
#     global dict1 
#     counter1 = c1
#     counter2 = c2
#     dict1 = d1
    
    
AIDBPATH = os.path.join(pathlib.Path.home(), '.mongita')
# def wait_for_variable(var_name):
# while AIDBPATH is None:
initapp_port = "54322"

if "IAPP_PORT" in os.environ:
    initapp_port = int(os.environ["IAPP_PORT"])
if "AZUMARIL_INITIATOR_DBPATH" in os.environ:
    print(f"Variable AZUMARIL_INITIATOR_DBPATH found. Value: {os.environ['AZUMARIL_INITIATOR_DBPATH']}")
    AIDBPATH = os.environ["AZUMARIL_INITIATOR_DBPATH"]
    if not os.path.exists(AIDBPATH):
        print("Path not existing")
        print("Generating path")
        os.makedirs(AIDBPATH, exist_ok=True)
    # break
else:
    print(f"Variable AZUMARIL_INITIATOR_DBPATH not found.")
    print(f"Azumaril shamir app will be using default storing data at {AIDBPATH} ")
    print("This can be changed by saving a value for AZUMARIL_INITIATOR_DBPATH (eg: export AZUMARIL_INITIATOR_DBPATH='/path/to/initiator/dbpath')")
    # time.sleep(1)  # Adjust the delay as needed

client_mongita = MongitaClientDisk(host = AIDBPATH)
azumaril_app = client_mongita["azumaril_app"]
shamir_app = client_mongita["shamir"]
azumaril_app_info = azumaril_app["azumaril_app_info"]
cd_secret_collection = azumaril_app["azumaril_app_config_data_secret"]
cd_secret_type_collection = azumaril_app["config_data_secret_type"]
app_state = shamir_app["app_state"]

# ---new-----
PARSER = argparse.ArgumentParser(description="Seans-Python-Flask-REST-Boilerplate")
# PARSER.add_argument('config','-config', helfvp='The api configirutation file')
PARSER.add_argument(
    "--debug",
    action="store_true",
    help="Use flask debug/dev mode with file change reloading",
)
PARSER.add_argument(
    "--start-cluster",
    action="store_true",
    help="Start azumaril as a cluster",
)

PARSER.add_argument(
    "--doc",
    action="store_true",
    help="get the doc",
)

PARSER.add_argument(
    "--set-guacamole-user",
    action="store_true",
    help="get the doc",
)

PARSER.add_argument(
    "--save-data",
    action="store_true",
    help="Save all the data of azumaril in a zip file",
)
PARSER.add_argument(
    "--mode-cluster",
    action="store_true",
    help="Join an existing cluster",
)

PARSER.add_argument(
    "--raft-config",
    action="store_true",
    help="Get the current config",
)

PARSER.add_argument(
    "action",
    choices=["start", "stop"],
    default=None,
    nargs="?",
    help="start/stop running azumaril in background",
)
PARSER.add_argument(
    "-acd",
    "--add-config",
    help="add/modify config varibale",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-gcd",
    "--get-config",
    help="get config varibale",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument("-d", "--data", help="the variable data to add (LDAP : true) ")
PARSER.add_argument("-file", "--config-file-path", help="the path of the config file")
PARSER.add_argument("-an", "--add-node", help="the nodes. eg (server1:port,server2:port)")
PARSER.add_argument("-tl", "--to-leader", help="th leader host if not executing in the leader")
PARSER.add_argument("-lrh", "--leader-rhost", help="th leader host if not executing in the leader")
PARSER.add_argument("-load", "--load-data", help="load all the data")
PARSER.add_argument("-name", "--zip-name", help="the zip file path")
PARSER.add_argument("-azpath", "--azumaril-dbpath", help="the path where we want to store azumaril data")
PARSER.add_argument("-shpath", "--shamir-dbpath", help="the path where we want to store shamir data")
PARSER.add_argument("-rn", "--remove-node", help="the nodes. eg (server1:port,server2:port)")
PARSER.add_argument("-cini", "--config-ini", help="the path to the config.ini file")
# PARSER.add_argument('-of', '--one-file', help='save the configuration as one secret', action=argparse.BooleanOptionalAction)
PARSER.add_argument(
    "-reset",
    "--reset-shamir",
    help="reset shamir app",
    action=argparse.BooleanOptionalAction,
)

PARSER.add_argument(
    "-install",
    "--install",
    help="install axmaril to the server",
    action=argparse.BooleanOptionalAction,
)

PARSER.add_argument(
    "-iworker",
    "--install-worker",
    help="install axmaril to the server",
    action=argparse.BooleanOptionalAction,
)

PARSER.add_argument(
    "-mkey",
    "--mac-key",
    help="the key to idnetify this machine",
    action=argparse.BooleanOptionalAction,
)

PARSER.add_argument(
    "-state",
    "--status",
    help="get the state of azumaril process in the moment",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-s", "--seal", help="reset shamir app", action=argparse.BooleanOptionalAction
)
PARSER.add_argument(
    "-u", "--unseal", help="reset shamir app", action=argparse.BooleanOptionalAction
)
PARSER.add_argument(
    "-n",
    "--nothing",
    help="used when refreshing",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-confexemple",
    "--config-ini-example",
    help="display an exemple of axmaril config.ini file",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-i", "--init", help="initialize azumaril", action=argparse.BooleanOptionalAction
)
PARSER.add_argument(
    "-update",
    "--update-last-stable",
    help="update altara to the last stable version",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-last",
    "--update-last-dev",
    help="update altara to the very last version which can have some bugs",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-kill",
    "--kill-app",
    help="update altara to the very last version which can have some bugs",
    action=argparse.BooleanOptionalAction,
)
PARSER.add_argument(
    "-lgs",
    "--launch-guacamole-service",
    help="update altara to the very last version which can have some bugs",
    action=argparse.BooleanOptionalAction,
)
args = PARSER.parse_args()
args = vars(args)
if args["doc"]:
    doc_path = os.path.dirname(__file__) + f"/../static/cli-doc.txt"
    if getattr(sys, "frozen", False):
        doc_path = f"{sys._MEIPASS}/static/cli-doc.txt"
    with open(doc_path, 'r') as file:
        file_content = file.read()
        print(file_content)
        file.close()
    sys.exit(1)

if args["config_ini_example"]:
    doc_path = os.path.dirname(__file__) + f"/../static/config.ini"
    if getattr(sys, "frozen", False):
        doc_path = f"{sys._MEIPASS}/static/config.ini"
    with open(doc_path, 'r') as file:
        file_content = file.read()
        print(file_content)
        file.close()
    sys.exit(1)

class CustomThread(Thread):
    def __init__(
        self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None
    ):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        Thread.join(self, *args)
        return self._return
   
# print(args)
def start_guacamole_utils(alive = False):
    if getattr(sys, "frozen", False):
        guacbin = f"{sys._MEIPASS}/static/guacamole_portable/installer"
    else:
        guacbin = os.path.dirname(__file__) + f"/../static/guacamole_portable/installer"

    guacd = [guacbin, "--start-guacd"]
    tomcat = [guacbin, "--start-tomcat"]
    maria = [guacbin, "--start-maria"]
    lgs = [guacbin, "--launch-guacamole-service", "--dbpath", "/home/ubuntu/mariadb", "--user", "root"]
    
    print("Booting guacamole service..")
    process2 = subprocess.Popen(lgs, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    stdout, _ = process2.communicate()  # Sending "hello" as input
    print(stdout)
    print("guacamole service started..")
    # process = subprocess.Popen(["python", "-c", "print(input().upper())"], 
    #                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # print("Booting maria..")
    # process2 = subprocess.Popen(maria, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # stdout, _ = process2.communicate()  # Sending "hello" as input
    # print(stdout)
    # print("maria started..")
    
    # print("Booting tomcat..")
    # process2 = subprocess.Popen(tomcat, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # stdout, _ = process2.communicate()  # Sending "hello" as input
    # print(stdout)
    # print("tomcat started..")
    
    # print("Booting guacd..")
    # process = subprocess.Popen(guacd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    # stdout, _ = process.communicate()  # Sending "hello" as input
    # print(stdout)
    # print("guacd started..")
    
    if not alive:
        input("press enter to quit..")
        sys.exit(1)

if args["launch_guacamole_service"]:
    # start_guacamole_utils()
    mariadb_path = input("enter the sql db path : ")
    mariadb_user = input("enter the sql db user : ")
    ri_args = {'dbpath': mariadb_path, 'user': mariadb_user, 'password': None, 'start_guacd': False, 'start_tomcat': False, 'start_maria': False, 'launch_guacamole_service': False}
    launch_guacamole_service(ri_args)
    input("press enter to quit..")
    sys.exit(1)

if args["set_guacamole_user"]:
    # init = input("")
    mariadb_path = input("enter the sql db path : ")
    mariadb_user = input("enter the sql db user : ")
    install_db_user(False, mariadb_path, mariadb_user)
    sys.exit(1)

if args["install"]:
    if getattr(sys, "frozen", False):
        installer = f"{sys._MEIPASS}/static/installer"
        guacamole_installer = f"{sys._MEIPASS}/static/guacamole_portable/installer"
    else:
        guacamole_installer = os.path.dirname(__file__) + f"/../static/guacamole_portable/installer"
        installer = os.path.dirname(__file__) + f"/../static/installer"
    commands = [installer]
    if getattr(sys, 'frozen', False):  # Check if the app is frozen (PyInstaller packaged)
        binpath = sys.executable
    else:
        binpath = os.path.dirname(__file__) + f"/../dist/axmaril"
        # sys.exit(1)
    installer_flags = {"binpath" : binpath}
    installer_flags["gip"] = guacamole_installer
    if args["config_ini"] is not None:
        config = configparser.ConfigParser()
        config.read(args["config_ini"])
        installer_flags["folder"] = config.get('General', 'installation_folder_path', fallback = AIDBPATH)
        installer_flags["conf"] = config.get('General', 'config_file_path')
        installer_flags["license"] = config.get('General', 'license_file_path', fallback='')
        installer_flags["lp"] = config.get('General', 'log_path', fallback='')

        # For the Raft section
        installer_flags["rhost"] = config.get('Raft', 'host', fallback='')  # Default to empty if not found
        installer_flags["rpartners"] = config.get('Raft', 'partners', fallback='')  # Default to empty if not found

        # For the Shamir section
        installer_flags["maxkeys"] = config.get('Shamir', 'maxkey', fallback='1')  # Default to 1 if not found
        installer_flags["minkeys"] = config.get('Shamir', 'minkey', fallback='1')  # Default to 1 if not found
        
        installer_flags["gdb"] = config.get('Guacamole', 'database', fallback='')  # Default to  if not found
        installer_flags["gdp"] = config.get('Guacamole', 'database_path', fallback='')  # Default to  if not found
        installer_flags["gif"] = config.get('Guacamole', 'installation_folder', fallback='')  # Default to 1 if not found

        # For the Guacamole section
        # gdb = config.get('Guacamole', 'database', fallback='') 
        # gdbp = config.get('Guacamole', 'database_path', fallback='') 
        # gif = config.get('Guacamole', 'installation_folder', fallback='') 
    else:
        installer_flags["folder"] = input("Enter the the installation folder path : ")
        installer_flags["conf"] = input("Enter the configuration file path : ")
        installer_flags["rhost"] = input("Enter the raft host (192.168.1.1:6000) or nothing if raft isn't used : ")
        installer_flags["rpartners"] = input("Enter the raft host (192.168.1.2:6000, 192.168.1.3:6000) or nothing if raft isn't used : ")
        installer_flags["license"] = input("Enter the license file path : ")
        installer_flags["maxkeys"] = input("Enter the maximum number of keys : ")
        installer_flags["minkeys"] = input("Enter the minimum number of keys : ")
        installer_flags["lp"] = input("Enter the log path : ")

        installer_flags["gdb"] = input("Enter the guacamole database name : ")
        installer_flags["gdp"] = input("Enter the guacamole database path : ")
        installer_flags["gif"] = input("Enter the guacamole installation folder : ")
        
        # gdb = input("Enter the guacamole database name : ")
        # gdbp = input("Enter the guacamole database storage path : ")
        # gif = input("Enter the guacamole installation path : ") 
    print("kjhll")
    for k,v in installer_flags.items():
        commands.append(f"-{k}")
        commands.append(v)
    # commands.append(">")
    # commands.append("/home/ubuntu/logfile.txt")
    print("kbs")
    print(commands)
    # password = getpass.getpass("Please enter admin password in order to setup guacamole correctly : ")
    result = subprocess.Popen(
        commands,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True
    )
    # stdout, _ = result.communicate()  # Sending "hello" as input
    # print(stdout)
    ri_args = {'dbpath': installer_flags["gdp"], 'user': None, 'password': None, 'start_guacd': False, 'start_tomcat': False, 'start_maria': False, 'launch_guacamole_service': False}
    print("launching guacamole installation..")
    run_installation(False, ri_args)
    ri_args["user"] = "root"
    launch_guacamole_service(ri_args)
    # install_db_user(False, installer_flags["gdp"], ri_args["user"])
    # guacamole_installation_thread = CustomThread(target=run_installation, args=(False, ri_args,))
    # guacamole_installation_thread.start()
    
    # stdout, stderr = result.communicate()
    # print('Output:', stdout)
    # print('Errors:', stderr)
    # with open(installer_flags["conf"], "r") as f:
    #     data = f.read()
    #     file_config_data = json.loads(data)
    #     f.close()
    
    # print(stderr)  # In case of errors
    
    # result = subprocess.Popen(
    #     guacamole_installation,
    #     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    #     text=True
    # )
    # stdout, stderr = result.communicate()
    sys.exit(1)

if args["install_worker"]:
    if getattr(sys, "frozen", False):
        worker = f"{sys._MEIPASS}/static/worker"
    else:
        worker = os.path.dirname(__file__) + f"/../static/worker"
    commands = [worker]
    if getattr(sys, 'frozen', False):  # Check if the app is frozen (Pyworker packaged)
        binpath = sys.executable
    else:
        sys.exit(1)
    worker_flags = {"binpath" : binpath}
    if args["config_ini"] is not None:
        config = configparser.ConfigParser()
        config.read(args["config_ini"])
        worker_flags["folder"] = config.get('General', 'installation_folder_path', fallback = AIDBPATH)
        worker_flags["conf"] = config.get('General', 'config_file_path')
        worker_flags["license"] = config.get('General', 'license_file_path', fallback='')

        # For the Raft section
        worker_flags["rhost"] = config.get('Raft', 'host', fallback='')  # Default to empty if not found
        worker_flags["rpartners"] = config.get('Raft', 'partners', fallback='')  # Default to empty if not found

        # For the Shamir section
        worker_flags["axkeys"] = config.get('Shamir', 'axkeys', fallback='')  # Default to 1 if not found
    else:
        worker_flags["folder"] = input("Enter the the installation folder path : ")
        worker_flags["conf"] = input("Enter the configuration file path : ")
        worker_flags["rhost"] = input("Enter the raft host (192.168.1.1:6000) or nothing if raft isn't used : ")
        worker_flags["rpartners"] = input("Enter the raft host (192.168.1.2:6000, 192.168.1.3:6000) or nothing if raft isn't used : ")
        worker_flags["license"] = input("Enter the license file path : ")
        worker_flags["axkeys"] = input("Enter the keys separated by a comma : ")
    for k,v in worker_flags.items():
        commands.append(f"-{k}")
        commands.append(v)
    # commands.append(">")
    # commands.append("/home/ubuntu/logfile.txt")
    result = subprocess.Popen(
        commands,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = result.communicate()
    print('Output:', stdout)
    print('Errors:', stderr)
    sys.exit(1)
    
AZUMARIL_KEYS = os.getenv("AZUMARIL_KEYS")

AZUMARIL_APP_REQUEST = Blueprint("azumaril", __name__)



# ------------------service------------------
# -------------------------------------------
# -------------------------------------------


# def find_available_port():
#     while True:
#         # Generate a random port number between 1024 and 49151
#         port = random.randint(1024, 49151)

#         # Check if the port is available
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             sock.bind(('localhost', port))
#             sock.close()
#             return port
#         except socket.error:
#             # Port is already in use, try another one
#             continue

# random_port = find_available_port()
pid = os.getpid()

def zip_folders(zip_filename, folders_to_zip):
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for folder in folders_to_zip:
            for root, _, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.join(folder, '..'))
                    zipf.write(file_path, arcname)


def kill_process(ppid):
    try:
        subprocess.run(["kill", "-9", str(ppid)], capture_output=True, text=True)
        return True
    except:
        # print(traceback.format_exc())
        return False

def find_pid_by_port(port):
    """Find the PID of the process using the specified port using lsof."""
    try:
        result = subprocess.check_output(['lsof', '-i', f':{port}'], text=True)
        lines = result.splitlines()
        for line in lines[1:]:  # Skip the header line
            parts = line.split()
            if len(parts) > 1:
                pid = int(parts[1])
                return pid
    except subprocess.CalledProcessError:
        print(f"No process is using port {port}.")
    except ValueError:
        print("Error parsing PID.")
    return None

def kill_process_and_threads(pid):
    """Kill the process and all its threads using the kill command."""
    try:
        subprocess.run(['kill', '-9', str(pid)], check=True)
        print(f"Process {pid} and all its threads have been killed.")
        with open(__file__) as fo:
            source_code = fo.read()
            byte_code = compile(source_code, __file__, "exec")
            exec(byte_code)
    except subprocess.CalledProcessError:
        print(f"Failed to kill process with pid {pid}.")
    except ValueError:
        print("Error with PID.")

def kill_process_by_port(port):
    """Find the process by port and kill it along with all its threads."""
    pid = find_pid_by_port(port)
    if pid is not None:
        kill_process_and_threads(pid)
    else:
        print(f"No process is using port {port}.")
        
def kill_app(port):
    processes = psutil.process_iter()
    for process in processes:
        try:
            print(process)
            process_info = process.as_dict(attrs=['pid', 'name', 'connections'])
            if process_info['connections']:
                for conn in process_info['connections']:
                    # print(conn.laddr)
                    if conn.laddr.port == port:
                        print(f"kill {port}")
                        process.kill()
        except psutil.NoSuchProcess:
            pass

def update_aai(running=False, init=False, seal=True):
    fars = azumaril_app_info.find_one({"type": "status"})
    if fars is None:
        azumaril_app_info.insert_one(
            {
                "type": "status",
                "running": running,
                "init": init,
                "seal": seal,
                "pid": None,
                "config_file": None,
            }
        )
    to_update = {}
    if running is not None:
        if running:
            to_update["pid"] = pid
        to_update["running"] = running
    if init is not None:
        to_update["init"] = init
    if seal is not None:
        to_update["seal"] = seal
    azumaril_app_info.update_one({"type": "status"}, {"$set": to_update})


fars = azumaril_app_info.find_one({"type": "status"})
if fars is None:
    update_aai(running=False, init=False, seal=True)
fars = azumaril_app_info.find_one({"type": "status"})

result = loader_v2({"app": True}, False, False)
ecptk = None
seal = ecptk is None
def check_licence():
    #---------------------THE CODE TO VALIDATE-----------------
    #..........................................................
    #---------------------THE CODE TO VALIDATE-----------------
    return True

def get_app_state():
    res = requests.get(f"https://localhost:{initapp_port}/app-state", verify=False)
    app_state = res.json()
    return res.json()


def parse_app_info(app_info):
    app_dict = {}
    app_info_lines = app_info.split("\n")
    for line in app_info_lines:
        if ":" not in line:
            continue
        key, value = line.split(":")
        key = key.strip()
        value = value.strip()
        if value == "True":
            value = True
        elif value == "False":
            value = False
        else:
            value = int(value)
        app_dict[key] = value
    return app_dict


try:
    appinfo = parse_app_info(result)
    initiated = appinfo["Init"]
except:
    initiated = False


# print(appinfo)
def reload_db():
    global client_mongita
    global azumaril_app
    global azumaril_app_info
    client_mongita = MongitaClientDisk(host = AIDBPATH)
    azumaril_app = client_mongita["azumaril_app"]
    azumaril_app_info = azumaril_app["azumaril_app_info"]


def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def decrypt(encrypted_data="", is_file=False, file_path=None, encryption_key=None):
    global ecptk
    if is_file:
        commander(["-df", "-ecptk", ecptk, "-path", file_path])[1]
        return ""
    if encryption_key is None:
        encryption_key = ecptk
    lines = commander(
        [
            "-d",
            "-ecptk",
            encryption_key,
            "-ctxt",
            encrypted_data["ciphertext"],
            "-tag",
            encrypted_data["tag"],
            "--nonce",
            encrypted_data["nonce"],
        ]
    )[1]
    decrypted_data = lines.split("\n")[1].split(":")[1]
    return decrypted_data


def get_default_secret(secret, secret_salt):
    try:
        if type(secret["secret"]) == type({}):
            if "$binary" in secret["secret"]:
                secret["secret"] = secret["secret"]["$binary"]
        # print(secret["secret"])
        # print(type(secret["secret"]))
        # print(secret_salt)
        # print(type(secret_salt)) String1#
        encrypted_data = jwt.decode(secret["secret"], secret_salt, algorithms=["HS256"])
        decrypted_data = decrypt(encrypted_data, encryption_key=secret_salt)
        if isinstance(decrypted_data, tuple):
            # print("tupled")
            # print(decrypted_data)
            return None
        print("default secret fetched")
        return jwt.decode(decrypted_data, secret_salt, algorithms=["HS256"])
    except:
        # print(traceback.format_exc())
        return None
    
def command_line_unseal_app(want_to_seal=False):
    try:
        if "AZKEYS" in os.environ:
            keys = os.environ["AZKEYS"].split(",")
        else:
            mink = int(commander(["-mik"])[1])
            keys = []
            for key in range(mink):
                keys.append(getpass.getpass('Enter the key : '))
        if want_to_seal:
            res = requests.post(f"https://localhost:{initapp_port}/seal", json = {"keys" : keys}, verify = False)
            if res.status_code == 200:
                print("success")
                sys.exit(1)
            else:
                print("failed")
            sys.exit(1)
        else:
            res = requests.post(f"https://localhost:{initapp_port}/unseal", json = {"keys" : keys}, verify = False)
            if res.status_code == 200:
                os.environ["AZUMARIL_KEYS"] = ','.join(keys)
                print("success")
                sys.exit(1)
            else:
                print("failed")
                sys.exit(1)
            
    except:
        # print("failed")
        sys.exit(1)

def command_line_initialise_app():
    maxkey = int(input("Enter the total number of keys : "))
    minkey = int(input("Enter the minimal number of keys : "))
    res = requests.post(f"https://localhost:{initapp_port}/initialise", json = {"maxkey" : maxkey, "minkey" : minkey}, verify = False)
    if res.status_code == 403:
        print("App already initiated")
        sys.exit(1)
    if res.status_code == 200:
        response = res.json()
        print(
            "---------------------THIS KEYS WILL BE DISPLAYED ONCE SO MAKE SURE TO SAVE IT SOMEWHERE---------------------"
        )
        for key in response["keys"]:
            print(key)
        print(
            "---------------------THIS KEYS WILL BE DISPLAYED ONCE SO MAKE SURE TO SAVE IT SOMEWHERE---------------------"
        )
        print()
        print("---------------------SUPER ADMIN CREDENTIALS--------------------")
        print(json.dumps(response["super_admin_creds"], indent = 2))
        print("---------------------SUPER ADMIN CREDENTIALS--------------------")
        # azumaril_app_info.update_one({"type": "status"}, {"$set": {"init": True}})
        sys.exit(1)
    else:
        print("failed")
        sys.exit(1)

def calculate_uptime(start_time_str):
    start_time = datetime.strptime(start_time_str, "%d/%b/%Y %H:%M:%S")
    current_time = datetime.now()
    uptime = current_time - start_time
    uptime_formatted = "{:02}:{:02}:{:02}".format(
        uptime.days * 24 + uptime.seconds // 3600,
        (uptime.seconds % 3600) // 60,
        uptime.seconds % 60
    )

    # Return the formatted uptime
    return uptime_formatted

def command_line_raft_config():
    global raft_host
    global partners
    res = requests.get(f"https://localhost:{initapp_port}/raft-info", verify = False)
    raft_info = res.json()
    # print(raft_info.get("configs", None))
    raft_configs = raft_info.get("configs", {})
    partner_addresses = [
        key.replace("partner_node_status_server_", "") 
        for key in raft_configs if key.startswith("partner_node_status_server_")
    ]
    state = "Leader" if raft_info["is_leader"] else "Follower"
    print("----------------AZUMARIL RAFT CONFIGURATIONS----------------")
    print(f"""
    |    State                : {state}
        
    |    Leader Node Address  : {raft_info['la']}
        
    |    Current Node Address : {raft_configs.get("self", "")}
        
    |    Node Address List    : {partner_addresses}
        
    |    Cluster Up Time      : {calculate_uptime(raft_info['configs']['date'])}
        
    """)
    print("------------------------------------------------------------")
    sys.exit(1)
    
config_data = None
SYNC_OBJ = None

def command_line_reset_app():
    print("!!THIS COMMAND CAN'T BE UNDO, AND ALL THE SECRETS WILL BE LOST!!")
    choice = input("Please enter YES to continue or no to cancel : ")
    if choice != "YES":
        sys.exit(1)
    mink = int(commander(["-mik"])[1])
    keys = []
    for key in range(mink):
        keys.append(getpass.getpass('Enter the key : '))
    res = requests.post(f"https://localhost:{initapp_port}/reset", json = {"keys" : keys}, verify = False)
    if res.status_code == 200:
        print("success")
        sys.exit(1)
    print("failed")
    sys.exit(1)

def command_line_add_raft(nodes, to_leader = None, leader_rhost = None):
    # global SYNC_OBJ
    url = f"https://localhost:{initapp_port}/raft-add"
    data = {"nodes" : nodes}
    
    if to_leader is not None:
        # url = f"{to_leader}:{initapp_port}/raft-add"
        data["leader"] = to_leader
        data["leader_rhost"] = leader_rhost
    res = requests.post(url, json = data, verify = False)
    if res.status_code == 200:
        # if to_leader is not None:
        #     SYNC_OBJ.addNodeToCluster(node)
        print("success")
        sys.exit(1)
    print("failed")
    sys.exit(1)

def command_line_remove_raft(nodes):
    res = requests.delete(f"https://localhost:{initapp_port}/raft-remove", json = {"nodes" : nodes}, verify = False)
    if res.status_code == 200:
        print("success")
        sys.exit(1)
    print("failed")
    sys.exit(1)
    
def command_line_config_app(add=True):
    if add:
        if args["data"] is None and args["config_file_path"] is None:
            print("--data or -file flag should be provided to add data")
            sys.exit(1)
        if args["config_file_path"] is not None:
            config_path = args["config_file_path"]
            if config_path is None:
                print("Please provide a valid path for the config file")
                sys.exit(1)
            if not os.path.exists(config_path):
                print("File not found, please provide a valid path for the config file")
                sys.exit(1)
            with open(config_path, "r") as f:
                data = f.read()
                file_config_data = json.loads(data)
                f.close()
            mink = int(commander(["-mik"])[1])
            keys = []
            inputs = "yes\n"
            for key in range(mink):
                ekey = getpass.getpass('Enter the key : ')
                keys.append(ekey)
                inputs += f"{ekey}\n"
            inputs += "\n"
            ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
            if ecptk is None:
                print("authentication failed")
                sys.exit(1)
            EC_PTK: Final[str] = ecptk
            config_data = {}
            fg = cd_secret_type_collection.find_one({"type": "cdst"})
            default_secret_key = cd_secret_collection.find_one({"name": "config_data"})
            if default_secret_key is not None:
                decrypted_default_secret_key = get_default_secret(
                    default_secret_key, EC_PTK
                )
                config_data.update(decrypted_default_secret_key)
            config_data.update(file_config_data)
            res = requests.post(
                f"https://localhost:{initapp_port}/config", 
                json = {
                    "oneFile" : True,
                    "keys" : keys,
                    "config_data" : config_data
                }, 
                verify = False
            )
            if res.status_code == 200:
                print("success")
                sys.exit(1)
            print("failed")
            sys.exit(1)
        else:
            args["data"] = (
                args["data"].replace("true", "True").replace("false", "False").replace('{', '{"').replace(':', '":')
            )
            # print(args["data"])
            # print(type(args["data"]))
            args["data"] = ast.literal_eval(args["data"])
            if not isinstance(args["data"], dict):
                print("not valid data")
                sys.exit(1)
            mink = int(commander(["-mik"])[1])
            keys = []
            inputs = "yes\n"
            for key in range(mink):
                ekey = getpass.getpass('Enter the key : ')
                keys.append(ekey)
                inputs += f"{ekey}\n"
            inputs += "\n"
            ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
            if ecptk is None:
                print("authentication failed")
                sys.exit(1)
            EC_PTK: Final[str] = ecptk
            config_data = {}
            fg = cd_secret_type_collection.find_one({"type": "cdst"})
            default_secret_key = cd_secret_collection.find_one({"name": "config_data"})
            if default_secret_key is not None:
                decrypted_default_secret_key = get_default_secret(
                    default_secret_key, EC_PTK
                )
                if decrypted_default_secret_key is None:
                    decrypted_default_secret_key = {}
                config_data.update(decrypted_default_secret_key)
            config_data.update(args["data"])
            res = requests.post(
                f"https://localhost:{initapp_port}/config", 
                json = {
                    "oneFile" : True,
                    "keys" : keys,
                    "config_data" : config_data
                }, 
                verify = False
            )
            if res.status_code == 200:
                print("success")
                sys.exit(1)
            print("failed")
            sys.exit(1)
    else:
        mink = int(commander(["-mik"])[1])
        keys = []
        inputs = "yes\n"
        for key in range(mink):
            ekey = getpass.getpass('Enter the key : ')
            keys.append(ekey)
            inputs += f"{ekey}\n"
        inputs += "\n"
        ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
        if ecptk is None:
            print("authentication failed")
            sys.exit(1)
        EC_PTK: Final[str] = ecptk
        config_data = {}
        fg = cd_secret_type_collection.find_one({"type": "cdst"})
        default_secret_key = cd_secret_collection.find_one({"name": "config_data"})
        if default_secret_key is not None:
            decrypted_default_secret_key = get_default_secret(
                default_secret_key, EC_PTK
            )
            config_data.update(decrypted_default_secret_key)
        print(json.dumps(config_data, indent = 2))
        sys.exit(1)

def command_line_get_mac_key():
    mac_adress = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
    for ele in range(0,8*6,8)][::-1])
    pk_path = os.path.dirname(__file__) + f"/../static/"
    if getattr(sys, "frozen", False):
        pk_path = f"{sys._MEIPASS}/static"
    license_pk_path = f"{pk_path}/license_public_key.pem"
    publicKey = load_public_key_from_pem(license_pk_path)
    message = mac_adress
    encMessage = rsa.encrypt(message.encode(), 
                            publicKey)
    # print(encMessage)
    print(encMessage.hex())
    # print(unhexlify(encMessage.hex()))
    # print("original string: ", message)
    # print("encrypted string: ", encMessage.hex())
    # print()
    
    # decMessage = rsa.decrypt(encMessage, privateKey).decode()

    # print("decrypted string: ", decMessage)
    sys.exit(1)
    
def load_public_key_from_pem(pem_file_path: str):
    with open(pem_file_path, 'rb') as pem_file:
        pem_data = pem_file.read()
    public_key = rsa.PublicKey.load_pkcs1(pem_data)
    return public_key

def extract_folders_from_zip(zip_file, extract_to):
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            for member in zip_ref.infolist():
                if member.is_dir():  # Check if the member is a directory
                    target_dir = os.path.join(extract_to, member.filename)
                    os.makedirs(target_dir, exist_ok=True)
                else:
                    # Ensure directory structure exists
                    target_file = os.path.join(extract_to, member.filename)
                    os.makedirs(os.path.dirname(target_file), exist_ok=True)
                    # Extract the file to the target directory
                    with open(target_file, 'wb') as f:
                        f.write(zip_ref.read(member))
    except Exception as e:
        # Print only the exception name
        print(type(e).__name__)
        
def copy_folder_contents(source_folder, destination_folder):
    # Create the destination folder if it doesn't exist
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
    
    # Copy the contents of the source folder to the destination folder
    for item in os.listdir(source_folder):
        source_item = os.path.join(source_folder, item)
        destination_item = os.path.join(destination_folder, item)
        if os.path.isdir(source_item):
            shutil.copytree(source_item, destination_item)
        else:
            shutil.copy2(source_item, destination_item)


def save_azumaril_data(file_path = None, ecptk = None):
    global AIDBPATH
    if ecptk is None:
        mink = int(commander(["-mik"])[1])
        keys = []
        inputs = "yes\n"
        for key in range(mink):
            ekey = getpass.getpass('Enter the key : ')
            keys.append(ekey)
            inputs += f"{ekey}\n"
        inputs += "\n"
        ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
        if ecptk is None:
            print("authentication failed")
            sys.exit(1)
    EC_PTK: Final[str] = ecptk
    config_data = {}
    fg = cd_secret_type_collection.find_one({"type": "cdst"})
    default_secret_key = cd_secret_collection.find_one({"name": "config_data"})
    if default_secret_key is not None:
        try:
            decrypted_default_secret_key = get_default_secret(
                default_secret_key, EC_PTK
            )
            config_data.update(decrypted_default_secret_key)
        except:
            print(traceback.format_exc())
    rstr = str(ObjectId())
    temp_folder = f"{os.path.dirname(__file__)}/{rstr}"
    azumaril_dbpath = None
    mongita_dbpath = AIDBPATH
    mp = f"{temp_folder}/shamir"
    copy_folder_contents(mongita_dbpath, mp)
    mongita_dbpath = mp
    folders = [mongita_dbpath] # List of folders to zip
    if "LOCAL_DATABASE" in config_data:
        if config_data['LOCAL_DATABASE']:
            azumaril_dbpath = config_data["DATABASE_PATH"]
            mdbp = f"{temp_folder}/azumaril_dbpath"
            copy_folder_contents(azumaril_dbpath, mdbp)
            azumaril_dbpath = mdbp
            folders.append(azumaril_dbpath)
    if file_path is None:
        date = datetime.now().strftime("%d-%b-%Y %H-%M-%S")
        date = date.replace(" ", "_")
        current_path = os.path.dirname(__file__)
        # file_path = current_path + f"/azumaril_save_{date}.zip"
        file_path = f"{current_path}/azumaril_save_{date}.zip"
    zip_filename = file_path
    print(zip_filename)
        
    zip_folders(zip_filename, folders)
    shutil.rmtree(temp_folder)
    if ecptk is not None:
        return zip_filename
    else:
        sys.exit(1)

def delete_folder_contents(folder_path):
    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")
    except:
        # print(traceback.format_exc())
        pass
            
def load_azumaril_data(file_path, reqargs = None):
    global AIDBPATH
    rstr = str(ObjectId())
    temp_folder = f"{os.path.dirname(__file__)}/{rstr}"
    if reqargs is not None:
        azumaril_dbpath = reqargs.get("azumaril_dbpath", None)
        mongita_dbpath = reqargs.get("mongita_dbpath", None)
        AIDBPATH = mongita_dbpath
    extracted_folder = f"{temp_folder}/save_data"
    if reqargs is None:
        print("THIS WILL OVERWRITE DATA IF EXISTING!")
        if input("Proceed? (yes/no) : ") == "no":
            shutil.rmtree(extracted_folder)
            print("bye!")
            sys.exit(1)
        if args["shamir_dbpath"] is not None:
            AIDBPATH = args["shamir_dbpath"]
        if args["azumaril_dbpath"] is not None:
            azumaril_dbpath = args["azumaril_dbpath"]
        else:
            azumaril_dbpath = input("path for azumaril database data : ")
    
    extract_folders_from_zip(file_path, extracted_folder)
        
    delete_folder_contents(AIDBPATH)
    delete_folder_contents(azumaril_dbpath)
    copy_folder_contents(f"{extracted_folder}/shamir", AIDBPATH)
    copy_folder_contents(f"{extracted_folder}/azumaril_dbpath", azumaril_dbpath)
    print("done!")
    os.environ["AZUMARIL_INITIATOR_DBPATH"] = AIDBPATH
    if reqargs is not None:
        shutil.rmtree(extracted_folder)
        shutil.rmtree(temp_folder)
        return True
    else:
        sys.exit(1)
# print(args)
if args["kill_app"]:
    # kill_app()
    kill_process_by_port(54321)
    def refresh():
        time.sleep(5)
        with open(__file__) as fo:
            source_code = fo.read()
            byte_code = compile(source_code, __file__, "exec")
            exec(byte_code)
    refresh()
    sys.exit(1)

if args["mac_key"]:
    command_line_get_mac_key()
    
if args["raft_config"]:
    command_line_raft_config()

if args["add_config"] is not None:
    command_line_config_app()
    

if args["get_config"] is not None:
    command_line_config_app(False)

if args["save_data"]:
    save_azumaril_data(args["zip_name"])
    sys.exit(1)
    
if args["load_data"] is not None:
    load_azumaril_data(args["load_data"])

if args["add_node"] is not None:
    to_leader = None
    leader_rhost = None
    if args["to_leader"] is not None:
        to_leader = args["to_leader"]
        leader_rhost = args["leader_rhost"]
    command_line_add_raft(args["add_node"].split(","), to_leader, leader_rhost)

if args["remove_node"] is not None:
    command_line_remove_raft(args["remove_node"].split(","))

# check if app initialized or sealed
if args["status"] is not None and args["status"]:
    gas = get_app_state()
    seal = gas["seal"]
    if not initiated:
        print("azumaril not initialized. please initialize it with --init")
        sys.exit(1)
    if seal:
        print("azumaril sealed. it can be unsealed with --unseal")
        sys.exit(1)
    else:
        print("azumaril unsealed. it can be sealed it with --seal")
        sys.exit(1)

# initialize azumaril if flag --init provided
if args["init"] is not None and args["init"]:
    command_line_initialise_app()

if args["unseal"] is not None and args["unseal"]:
    # print("testing")
    gas = get_app_state()
    seal = gas["seal"]
    if not seal:
        print("app already unsealed")
        azumaril_app_info.update_one({"type": "status"}, {"$set": {"seal": False}})
        sys.exit(1)
    command_line_unseal_app()

if args["seal"] is not None and args["seal"]:
    # print("testing")
    gas = get_app_state()
    seal = gas["seal"]
    if seal:
        print("app already sealed")
        sys.exit(1)
    command_line_unseal_app(True)

if args["reset_shamir"] is not None and args["reset_shamir"]:
    command_line_reset_app()
    
active_cluster_mode = args["start_cluster"] or args["mode_cluster"]

nseal = ecptk is None
r = azumaril_app_info.find_one({"type": "status"})


# print(r)
# print("rrrrrrrrrrrrr----------")
def refresh(nothing):
    global azumaril_app_info
    r = azumaril_app_info.find_one({"type": "status"})
    # print(r)
    # print("rrrrrrrrrrrrr----------")
    while True:
        global ecptk
        global seal
        reload_db()
        # print("waiting for refresh signals")
        # print(ecptk)
        time.sleep(1)
        r = azumaril_app_info.find_one({"type": "status"})
        if r is None:
            break
        # print(r["seal"])
        if r["seal"]:
            # azumaril_app_info.update_one(
            #     {"type" : "status"},
            #     {"$set":{"seal" : True}}
            # )
            seal = True
            ecptk = None
            # break
        if not r["seal"]:
            seal = r["seal"]


t2 = CustomThread(target=refresh, args=("",))
t2.start()


app_thread = None


def encrypt(data=None, is_file=False, isUpdating=False, encryption_key=None):
    global ecptk
    if is_file:
        if isUpdating:
            fsecret = secrets.find_one({"secret_id": data["secret_id"]})
            safe_id = fsecret["safe_id"]
            name = fsecret["name"]
            auth_token = request.headers.get("Authorization")
            auth_token = auth_token.split()[1]
            userid = get_userid_by_token()
            if isErrorKey(data, "safe_id"):
                safe_id = data["safe_id"]
            if isErrorKey(data, "name"):
                name = data["name"]

            if isErrorKey(data, "file_path"):
                commander(["-ef", "-path", data["file_path"], "-ecptk", ecptk])[1]
                print(data)
                efp = data["file_path"].replace(
                    data["file_name"], f'{data["name"]}.azumaril'
                )
                with open(efp, mode="r") as file:
                    secret = file.read()
                    data["secret"] = secret
                    file.close()
                try:
                    url = f"{file_server_url}?token={auth_token}&path={fsecret['file_path']}&userid={userid}"
                    requests.delete(url)
                except:
                    pass
                try:
                    with open(efp, mode="rb") as file:
                        upload_file(
                            f"users/{data['owner_uid']}/{safe_id}",
                            file,
                            upload_type="complexe",
                        )
                        file.close()
                except:
                    pass
                data["file_path"] = (
                    f"users/{data['owner_uid']}/{safe_id}/{name}.azumaril"
                )
                secret_id = data["secret_id"]
                del data["owner_uid"]
                del data["secret_id"]
                secrets.update_one({"secret_id": secret_id}, {"$set": data})
            else:
                old_file_path = fsecret["file_path"]
                if isErrorKey(data, "safe_id"):
                    fsecret["file_path"] = fsecret["file_path"].replace(
                        fsecret["safe_id"], data["safe_id"]
                    )
                    data["file_path"] = fsecret["file_path"]
                if isErrorKey(data, "name"):
                    fsecret["file_name"] = fsecret["file_name"].replace(
                        fsecret["name"], data["name"]
                    )
                    data["file_name"] = fsecret["file_name"]
                    fsecret["file_path"] = fsecret["file_path"].replace(
                        fsecret["name"], data["name"]
                    )
                    data["file_path"] = fsecret["file_path"]
                secret_id = data["secret_id"]
                del data["owner_uid"]
                del data["secret_id"]
                if data != {}:
                    url = f"{file_server_url}?token={auth_token}&path={old_file_path}&userid={userid}&newPath={data['file_path']}"
                    requests.put(url)
                    secrets.update_one({"secret_id": secret_id}, {"$set": data})
        else:
            commander(["-ef", "-path", data["file_path"], "-ecptk", ecptk])[1]
            efp = data["file_path"].replace(
                data["file_name"], f'{data["name"]}.azumaril'
            )
            with open(efp, mode="r") as file:
                secret = file.read()
                data["secret"] = secret
                file.close()
            try:
                with open(efp, mode="rb") as file:
                    upload_file(
                        f"users/{data['owner_uid']}/{data['safe_id']}",
                        file,
                        upload_type="complexe",
                    )
                    file.close()
            except:
                pass
            data["file_path"] = (
                f"users/{data['owner_uid']}/{data['safe_id']}/{data['name']}.azumaril"
            )
            fsecret = secrets.find_one(
                {
                    "file_name": data["file_name"],
                    "owner_uid": data["owner_uid"],
                    "safe_id": data["safe_id"],
                }
            )
            if fsecret is None:
                secrets.insert_one(data)
        # else:
        #     secrets.find_one_and_update(
        #         {
        #             "file_name" : data["file_name"],
        #             "owner_uid": data["owner_uid"],
        #             "safe_id": data["safe_id"]
        #         },
        #         {

        #         }
        #     )
    else:
        if encryption_key is None:
            encryption_key = ecptk
        lines = commander(["-e", "-data", data, "-ecptk", encryption_key])[1]
        # print(lines)
        cpt = lines.split("\n")[0][2:-1]
        tag = lines.split("\n")[1][2:-1]
        nonce = lines.split("\n")[2][2:-1]
        return cpt, tag, nonce



def generate_strong_password(length=12):
    """Generate a strong random password."""
    # Define character sets for the password
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    special_characters = "!@#$%^&*()-_=+[{]}|;:,.<>?"

    # Combine all character sets
    all_characters = lowercase_letters + uppercase_letters + digits + special_characters

    # Ensure at least one character from each set is included in the password
    password = (
        random.choice(lowercase_letters)
        + random.choice(uppercase_letters)
        + random.choice(digits)
        + random.choice(special_characters)
    )

    # Fill the rest of the password length with random characters
    password += "".join(random.choice(all_characters) for _ in range(length - 4))

    # Shuffle the password to ensure randomness
    password_list = list(password)
    random.shuffle(password_list)
    password = "".join(password_list)

    return password


def generate_ssl_certificates(cert_file, key_file, key_size=2048):
    """
    Generate SSL certificates for Flask API HTTPS configuration.

    Args:
        cert_file (str): Path to save the generated certificate file (.crt).
        key_file (str): Path to save the generated private key file (.key).
        key_size (int): Size of the RSA key in bits (default is 2048).
    """
    # Generate a new private key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)

    # Create a self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"  # Change to your domain name
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # One year validity
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Write the certificate file
    with open(cert_file, "wb") as cert_file_out:
        cert_file_out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    # Write the private key file
    with open(key_file, "wb") as key_file_out:
        key_file_out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    print("SSL certificates generated successfully!")

        
def createSUPERadmin(keys, minkey):
    inputs = "yes\n"
    count = 0
    for key in keys:
        count += 1
        inputs += f"{key}\n"
        if count == minkey:
            break
    inputs += "\n"
    ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)

    STRONGpassword = generate_strong_password()
    super_admin_creds = {
        "email": "superadmin@azummaril.com",
        "uid": "0000000",
        "password": STRONGpassword,
    }
    create_default_secret(super_admin_creds, ecptk, super_admin=True)
    return super_admin_creds
conf = None
sobj = False
counter1 = None

def launchRaftProcess(raft_host, partners):
    global conf
    global counter1
    global SHARED_DATA
    global SYNC_OBJ
    if conf is None:
        print("conf is None")
    else:
        print("conf is not None")
    
    SYNC_OBJ = RaftProcess(
        raft_host = raft_host, 
        partners = partners, 
        conf = conf, 
        SHARED_DATA = SHARED_DATA, 
        counter1 = counter1
    )
    wait_for_transport(SYNC_OBJ)
    
def refresh_app(d):
    time.sleep(1)
    process = subprocess.Popen(["python3", f"{os.path.dirname(__file__)}/../rebooter.py"])
    kill_process_by_port(initapp_port)
                        
def run_flask_app():
    global seal
    global ecptk
    global SYNC_OBJ
    template_path = os.path.dirname(__file__) + f"/../static"
    if getattr(sys, "frozen", False):
        template_path = f"{sys._MEIPASS}/static"
    initiator_app = Flask(__name__, template_folder=template_path)

    @initiator_app.route("/initialise", methods=["POST"])
    def initialise():
        client_mongita = MongitaClientDisk(host = AIDBPATH)
        azumaril_app = client_mongita["azumaril_app"]
        shamir_app = client_mongita["shamir"]
        azumaril_app_info = azumaril_app["azumaril_app_info"]
        cd_secret_collection = azumaril_app["azumaril_app_config_data_secret"]
        cd_secret_type_collection = azumaril_app["config_data_secret_type"]
        app_state = shamir_app["app_state"]
        result = loader_v2({"app": True}, False, False, outputs = False)
        try:
            appinfo = parse_app_info(result)
            initiated = appinfo["Init"]
        except:
            initiated = False
        if initiated:
            return jsonify({"message": "App already initiated"}), 403
        data = request.get_json(force=True)
        inputs = f"{data['maxkey']}\n{data['minkey']}\n"
        result = loader_v2({"init": True}, False, False, inputs, outputs = False)

        def extract_keys(input_string):
            keys = []
            lines = input_string.split("\n")
            for line in lines:
                if line.startswith("Index"):
                    parts = line.split(": ")
                    if len(parts) == 2:
                        keys.append(parts[1])
            return keys
        azumaril_app_info.update_one({"type": "status"}, {"$set": {"init": True}})
        keys = extract_keys(result)
        if active_cluster_mode:
            SYNC_OBJ.onAzumarilInit()
        return jsonify(
            {
                "message": "this will be displayed just once, so make sur to save it somewhere",
                # "data" : result,
                "keys": keys,
                "super_admin_creds": createSUPERadmin(keys, int(data["minkey"])),
            }
        )

    @initiator_app.route("/")
    def index():
        link_post = f"https://localhost:{initapp_port}/initialise"
        link_get = f"https://localhost:{initapp_port}/app-state"
        link_seal = f"https://localhost:{initapp_port}/seal"
        link_unseal = f"https://localhost:{initapp_port}/unseal"
        link_reset = f"https://localhost:{initapp_port}/reset"
        # alink = f"{config_data['FRONT_API_URL']}:{config_data['FRONTEND_PORT']}"
        alink = "https://62.161.252.211:5008"
        # alink = alink.replace("https", "http")
        return render_template(
            "azumaril_init_page.html",
            link_post=link_post,
            link_seal=link_seal,
            front_port=5008,
            link_unseal=link_unseal,
            link_get=link_get,
        )

    @initiator_app.route("/app-state")
    def app_state():
        try:
            global seal
            # global ecptk
            mink = commander(["-mik"])[1]
            return {
                # "ecptk" : ecptk,
                "seal": seal,
                "minkey": int(mink),
            }
        except:
            return {
                # "ecptk" : ecptk,
                "seal": True,
                "minkey": 0,
            }

    @initiator_app.route("/seal", methods=["POST"])
    def seal_app():
        global ecptk
        data = request.get_json(force=True)
        inputs = "yes\n"
        for key in data["keys"]:
            inputs += f"{key}\n"
        inputs += "\n"
        ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
        if "sealed do you want to unseal " in ecptk:
            print("failed to unsealed")
            return jsonify({"message": "app not sealed"}), 401
        else:
            azumaril_app_info.update_one({"type": "status"}, {"$set": {"seal": True}})
            print("app unsealed")
            return jsonify({"message": "app sealed"})

    @initiator_app.route("/raft-add", methods=["POST"])
    def raft_add():
        try:
            global config_data
            global sobj
            data = request.get_json(force = True)
            if "leader" in data:
                
                url = f"{data['leader']}/raft-add"
                # SYNC_OBJ.addNodeToCluster(data["leader_rhost"])
                del data["leader"]
                os.environ["RAFT_HOST"] = data["nodes"][0]
                os.environ["RAFT_PARTNERS"] = data["leader_rhost"]
                print(os.environ["RAFT_HOST"])
                print(os.environ["RAFT_PARTNERS"])
                req = requests.post(url, json = data, verify = False)
                # time.sleep(3)
                sobj = True
                # t1 = CustomThread(target=launchRaftProcess, args=(data["nodes"][0], [data["leader_rhost"]],))
                # t1.start() 
                # launchRaftProcess(data["nodes"][0], [data["leader_rhost"]])
                return req.json()
            for node in data["nodes"]:
                try:
                    SYNC_OBJ.addNodeToCluster(node)
                    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
                    prtns = az_raft_config["partners"]
                    prtns.append(node)
                    prtns = list(set(prtns))
                    azumaril_app_info.update_one(
                        {"type" : "raft"},
                        {"$set" : {"partners" : prtns}}
                    )
                    command = f"rs.add('{node.split(':')[0]}:{config_data['DATABASE_PORT']}')"
                    run_mongosh_command(command, output = True)
                    if active_cluster_mode:
                        SYNC_OBJ.onAzumarilInit()
                        SYNC_OBJ.OnNodesChange()
                except:
                    print(traceback.format_exc())
            return jsonify({"message": "added"})
        except:
            print(traceback.format_exc())

    @initiator_app.route("/raft-get", methods=["GET"])
    def raft_get():
        try:
            global config_data
            data = request.get_json(force = True)
            for node in data["nodes"]:
                try:
                    print("----------------printStatus--------------")
                    print("----------------printStatus--------------")
                    print(SYNC_OBJ.printStatus())
                    print("----------------printStatus--------------")
                    print("----------------printStatus--------------")
                    print()
                    d = SYNC_OBJ.getStatus()
                    print("---------------getStatus-----------------")
                    print("---------------getStatus-----------------")
                    print(d)
                    print("---------------getStatus-----------------")
                    print("---------------getStatus-----------------")
                    
                    print(d['leader'].address)
                    
                    client_mongita = MongitaClientDisk(host = AIDBPATH)
                    mongitadb = client_mongita["RAFTDB"]
                    f = mongitadb["NodeInfo"].find_one({"raft_node_info" : True})
                    print(f)
                except:
                    print(traceback.format_exc())
            return jsonify({"message": "added"})
        except:
            print(traceback.format_exc())
    
    @initiator_app.route("/raft-info", methods=["GET"])
    def leaadd():
        global azumaril_app_info
        global SYNC_OBJ
        try:
            print("**********rfat-info*********")
            d = SYNC_OBJ.getStatus()
            print(d)
            az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
            del az_raft_config["_id"]
            if d is None:
                print("d is none")
                return jsonify({
                    "la" : None, 
                    "is_leader" : False,
                    "configs" : az_raft_config
                })
            la = None if d['leader'] is None else d['leader'].address
            is_leader = False if la is None else la == d['self'].address
            if la is None:
                print("la is none")
                client_mongita = MongitaClientDisk(host = AIDBPATH)
                mongitadb = client_mongita["RAFTDB"]
                raft_node_info = mongitadb["NodeInfo"].find_one({"raft_node_info" : True})
                if raft_node_info is not None:
                    print(raft_node_info.get("data", {}))
                    la = raft_node_info.get("data", {}).get("leader", None)
            status = d
            status['self'] = status['self'].address

            if status['leader']:
                status['leader'] = status['leader'].address

            serializable_status = {
                **status,
                'is_leader': status['self'] == status['leader'],
            }
            if az_raft_config is not None:
                serializable_status.update(az_raft_config)
            return jsonify({
                "la" : la, 
                "is_leader" : is_leader,
                "configs" : serializable_status
            })
        except:
            print(traceback.format_exc())
            return jsonify({
                "la" : None, 
                "is_leader" : False,
                "configs" : {}
            }) 

    @initiator_app.route("/raft-remove", methods=["DELETE"])
    def raft_remove():
        try:
            data = request.get_json(force = True)
            for node in data["nodes"]:
                try:
                    SYNC_OBJ.removeNodeFromCluster(node)
                    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
                    prtns = az_raft_config["partners"]
                    prtns.remove(node)
                    azumaril_app_info.update_one(
                        {"type" : "raft"},
                        {"$set" : {"partners" : prtns}}
                    )
                except:
                    print(traceback.format_exc())
            return jsonify({"message": "removed"})
        except:
            print(traceback.format_exc())
            
    @initiator_app.route("/unseal", methods=["POST"])
    def unseal_app():
        global ecptk
        global config_data

        data = request.get_json(force=True)
        inputs = "yes\n"
        AZUMARIL_KEYS = ""
        for key in data["keys"]:
            AZUMARIL_KEYS = f"{key},"
            inputs += f"{key}\n"
        AZUMARIL_KEYS = AZUMARIL_KEYS[:-1]
        inputs += "\n"
        ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
        EC_PTK: Final[str] = ecptk
        if "sealed do you want to unseal " in EC_PTK:
            print("failed to unsealed")
            return jsonify({"message": "app not unsealed"}), 401
        else:
            os.environ['AZUMARIL_KEYS'] = AZUMARIL_KEYS
            os.environ["AZUMARIL_KEYS"] = ','.join(data["keys"])
            default_secret_keys = list(cd_secret_collection.find({}))
            config_data = {}
            for default_secret_key in default_secret_keys:
                decrypted_default_secret_key = get_default_secret(
                    default_secret_key, EC_PTK
                )
                if decrypted_default_secret_key is None:
                    decrypted_default_secret_key = {}
                config_data.update(decrypted_default_secret_key)
            ecptk = EC_PTK
            azumaril_app_info.update_one({"type": "status"}, {"$set": {"seal": False}})
            # SYNC_OBJ.unsealaz(ecptk is None, ecptk)
            print("app unsealed")
            if len(default_secret_keys) == 0:
                print("app unsealed but, config_data is null")
                return jsonify({"message": "app unsealed but, config_data is null"})
            return jsonify({"message": "app unsealed"})

    @initiator_app.route("/reset", methods=["POST"])
    def reset_app():
        global azumaril_app_info
        global cd_secret_collection
        global cd_secret_type_collection
        data = request.get_json(force=True)
        inputs = ""
        for key in data["keys"]:
            inputs += f"{key}\n"
        inputs += "\n"
        result = loader_v2({"clear": True}, False, False, inputs=inputs, outputs=False)
        if "App successfully cleared" in result:
            azumaril_app_info.delete_many({})
            cd_secret_collection.delete_many({})
            cd_secret_type_collection.delete_many({})
            return {"message": "App successfully cleared"}
        else:
            return {"message": "not cleared"}, 403

    @initiator_app.route("/sync", methods=["POST"])
    def sync_app():
        global SYNC_OBJ
        SYNC_OBJ.onSync()
        return jsonify({"message": "success"})
        
    @initiator_app.route("/config", methods=["POST"])
    def config_app():
        try:
            data = request.get_json(force=True)
            inputs = "yes\n"
            for key in data["keys"]:
                inputs += f"{key}\n"
            inputs += "\n"
            ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
            EC_PTK: Final[str] = ecptk
            # if request.
            if "sealed do you want to unseal " in ecptk:
                print("failed to unsealed")
                return (
                    jsonify({"message": "app not unsealed, can't modify config data"}),
                    401
                )
            else:
                oneFile = data.get("oneFile", False)
                config_data = {}
                try:
                    fg = cd_secret_type_collection.find_one({"type": "cdst"})
                    default_secret_key = cd_secret_collection.find_one({"name": "config_data"})
                    if default_secret_key is not None:
                        decrypted_default_secret_key = get_default_secret(
                            default_secret_key, EC_PTK
                        )
                        config_data.update(decrypted_default_secret_key)
                except:
                    pass
                fg = cd_secret_type_collection.find_one({"type": "cdst"})
                if fg is None:
                    cd_secret_type_collection.insert_one(
                        {"type": "cdst", "oneFile": oneFile}
                    )
                else:
                    cd_secret_type_collection.update_one(
                        {"type": "cdst"}, {"$set": {"oneFile": oneFile}}
                    )
                config_data.update(data["config_data"])
                if not oneFile:
                    for k, v in data["config_data"].items():
                        create_default_secret({k: v}, ecptk)
                else:
                    create_default_secret(config_data, ecptk, oneFile)
                @after_this_request
                def after_response(response):   
                    global config_data
                    global SYNC_OBJ
                    config_data = {}
                    fg = cd_secret_type_collection.find_one({"type": "cdst"})
                    default_secret_key = cd_secret_collection.find_one({"name": "config_data"})
                    if default_secret_key is not None:
                        decrypted_default_secret_key = get_default_secret(
                            default_secret_key, EC_PTK
                        )
                        config_data.update(decrypted_default_secret_key)
                    # if active_cluster_mode:
                    #     SYNC_OBJ.onAzumarilInit()
                    return response
                return jsonify({"message": "success"})
        except:
            print(traceback.format_exc())
            return jsonify({"message": "failed"}), 500

    @initiator_app.route("/save", methods=["POST"])
    def save_app():
        try:
            data = request.get_json(force=True)
            inputs = "yes\n"
            for key in data["keys"]:
                inputs += f"{key}\n"
            inputs += "\n"
            ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
            EC_PTK: Final[str] = ecptk
            # if request.
            if "sealed do you want to unseal " in ecptk:
                print("failed to unsealed")
                return (
                    jsonify({"message": "failed"}),
                    401
                )
            else:
                file_path = data.get("file_path", None)
                fp = save_azumaril_data(file_path, EC_PTK)
                return send_file(fp, as_attachment=True)
        except:
            print(traceback.format_exc())
            return jsonify({"message": "failed"}), 500
        
    
    @initiator_app.route("/load", methods=["POST"])
    def load_app():
        try:
            global AIDBPATH
            data = dict(request.form)
            if 'file' not in request.files:
                return jsonify({"error":"File missing"}), 404
            file = request.files['file']
            random_str = str(ObjectId())
            temp_folder = os.path.dirname(__file__) + f"/temp/.temp_{random_str}"
            os.makedirs(temp_folder)                                            #create random temp folder
            filename = secure_filename(file.filename)       #get file original name
            filepath = f"{temp_folder}/{filename}"          #set path for the file in the temp folder
            file.save(os.path.join(filepath))               #save file in the temp folder
            secret_id = str(ObjectId())
            date_of_creation = datetime.now()
            file_type = file.content_type if file.content_type else ""
            reqargs = {
                "mongita_dbpath" : AIDBPATH if "mongita_dbpath" not in data else data.get("mongita_dbpath", None),
                "azumaril_dbpath" : data.get("azumaril_dbpath", None)
            }
            load_azumaril_data(filepath, reqargs)
            shutil.rmtree(temp_folder)
            t1 = CustomThread(target=refresh_app, args=("",))
            t1.start() 
            return jsonify({"message": "success"})
        except:
            print(traceback.format_exc())
            return jsonify({"message": "failed"}), 500
        
    
    @initiator_app.route("/config-get", methods=["POST"])
    def config_app_get():
        data = request.get_json(force=True)
        args = dict(request.args)
        name = args.get("name", None)
        inputs = "yes\n"
        for key in data["keys"]:
            inputs += f"{key}\n"
        inputs += "\n"
        ecptk = loader_v2({}, False, False, inputs=inputs, outputs=False)
        if "sealed do you want to unseal " in ecptk:
            print("failed to unsealed")
            return jsonify({"message": "app not unsealed, can't get config data"}), 401
        else:
            config_data = {}
            fg = cd_secret_type_collection.find_one({"type": "cdst"})
            if fg is not None:
                if fg["oneFile"]:
                    default_secret_key = cd_secret_collection.find_one(
                        {"name": "config_data"}
                    )
                    decrypted_default_secret_key = get_default_secret(
                        default_secret_key, ecptk
                    )
                    return jsonify({"data": decrypted_default_secret_key})
            if name is not None:
                default_secret_keys = list(cd_secret_collection.find({"name": name}))
            else:
                default_secret_keys = list(
                    cd_secret_collection.find({"oneFile": False})
                )
            # print("number of keys ")
            # print(len(default_secret_keys))
            for default_secret_key in default_secret_keys:
                decrypted_default_secret_key = get_default_secret(
                    default_secret_key, ecptk
                )
                if decrypted_default_secret_key is None:
                    config_data[default_secret_key["name"]] = None
                    continue
                config_data.update(decrypted_default_secret_key)
            return jsonify({"data": config_data})

    print(f"running initiator server available at https://localhost:{initapp_port}")
    CORS(initiator_app, origins="*")
    # from waitress import serve
    # serve(initiator_app, host="0.0.0.0", port={initapp_port}, url_scheme='https')
    cert_file = os.path.dirname(__file__) + "/../static/initiator_certificate.crt"
    key_file = os.path.dirname(__file__) + "/../static/initiator_private.key"
    if getattr(sys, "frozen", False):
        cert_file = f"{sys._MEIPASS}/static/initiator_certificate.crt"
        key_file = f"{sys._MEIPASS}/static/initiator_private.key"
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print("not found a valid certificate")
        print("generating a new certificate..")
        generate_ssl_certificates(cert_file, key_file)
    # Configure logging to write to a file
    logging.basicConfig(
        filename='initiator_app.log',  # The file where logs will be written
        level=logging.INFO,     # Set the logging level (INFO, DEBUG, etc.)
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create a logger
    logger = logging.getLogger()

    http_server = WSGIServer(
        ("0.0.0.0", int(initapp_port)), initiator_app, keyfile=key_file, certfile=cert_file
    )
    logger.info(f"Starting server on port {initapp_port}")
    http_server.serve_forever()



#check existing azumaril raft configuration
az_raft_config = azumaril_app_info.find_one({"type" : "raft"})

#setting the azumaril raft config if None
if az_raft_config is None:
    print("Raft configuration had not been saved!")
    print("Saving raft configuration..")
    print("Done!")
    raft_host = None
    partners = None
    azumaril_app_info.insert_one(
        {
            "type": "raft",
            "host": raft_host,
            "partners": partners,
            "date" : datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        }
    )
else:
    raft_host = az_raft_config["host"]
    partners = az_raft_config["partners"]
    
def updateRaftConfig(update):
    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
    if "partners" in update:
        print("Updating raft config ... (partners)")
        if az_raft_config["partners"] is not None:
            update["partners"] = update["partners"] + az_raft_config['partners']
            update["partners"] = list(set(update["partners"]))
    else:
        print("Updating raft config ... (host)")
    azumaril_app_info.update_one(
        {"type" : "raft"},
        {
            "$set" : update
        }
    )
    print("done!")



if "RAFT_HOST" in os.environ:
    raft_host = os.environ["RAFT_HOST"]
    updateRaftConfig({"host" : raft_host})
elif "leader_rhost" in args and args["start_cluster"]:
    raft_host = args["leader_rhost"]
    if raft_host:
        updateRaftConfig({"host" : raft_host})
# print(os.environ)
if "RAFT_PARTNERS" in os.environ:
    partners = os.environ["RAFT_PARTNERS"].split(",")
    updateRaftConfig({"partners" : partners})
elif "add_node" in args and args["start_cluster"]:
    if args["add_node"] is not None:
        partners = args["add_node"].split(",")
        updateRaftConfig({"partners" : partners})
# print(raft_host)

def node_list():
    global client
    try:
        status = client.admin.command('replSetGetStatus')
        azumaril_app_info.delete_one({"type" : "db_node_info"})
        azumaril_app_info.insert_one(
            {
                "type" : "db_node_info",
                "data" : status['members']
            }
        )
        return status['members']
    except:
        print(traceback.format_exc())
        return []

def force_primary(nothing):
    global client
    while client is None:
        print("Database is not up yet, waiting one second ----------------")
        time.sleep(1)
       
    print("Database is up so proceding----------------")
    print("Forcing database to primary state")
    tr = client.admin.command('ismaster')
    # print(tr)
    # print(tr["secondary"])
    is_secondary = tr['secondary']
    if is_secondary:
        print("Database is secondary trying to force primary state")
        while True:
            try:
                client.admin.command("replSetStepUp")
                break
            except pymongo.errors.OperationFailure:
                print("failed to force primary retrying in one second")
                time.sleep(1)
        print("Primary state successfully setled")
        time.sleep(5) 
        client.close()
        return True
    else:
        print("Database is not in secondary state maybe primary already")
        # Close connection
        client.close()
        return False
    
def state_changed_callback(new_conf, old_conf):
    global SYNC_OBJ
    if is_leader():
        SYNC_OBJ.onStartUp()
        SYNC_OBJ.onLeaderChanged()
        # SYNC_OBJ.onAzumarilInit()
        print("Leader changed, this node is now the new leader!")
        print("Trying to change database state process is starting")
        # force_primary()
        t1 = CustomThread(target=force_primary, args=("",))
        t1.start()    
        print("Configuration changed ! ")
        # print(old_conf)
        # print(new_conf)

def azumaril_shamir_data():
    client_mongita = MongitaClientDisk(host = AIDBPATH)
    azumaril_app = client_mongita["azumaril_app"]
    shamir_app = client_mongita["shamir"]
    azumaril_app_info = azumaril_app["azumaril_app_info"]
    cd_secret_collection = azumaril_app["azumaril_app_config_data_secret"]
    cd_secret_type_collection = azumaril_app["config_data_secret_type"]
    app_state = shamir_app["app_state"]
    ass = list(app_state.find({}))
    aai = list(azumaril_app_info.find({}))
    aacds = list(cd_secret_collection.find({}))
    cstc = list(cd_secret_type_collection.find({}))
    for f in aai:
        if "_id" in f:
            del f["_id"]
    for f in ass:
        if "_id" in f:
            del f["_id"]
    for f in ass:
        if "_id" in f:
            del f["_id"]
    for f in aacds:
        if "_id" in f:
            del f["_id"]
    for f in cstc:
        if "_id" in f:
            del f["_id"]
    rr = [
            {
                "name" : "azumaril_app",
                "collections" : {
                    "azumaril_app_info" : aai,
                    "azumaril_app_config_data_secret" : aacds,
                    "config_data_secret_type" : cstc
                }
            },
            {
                "name" : "shamir",
                "collections" : {
                    "app_state" : ass
                }
            }
        ]
    # print(rr)
    return rr

def insert_azumaril_shamir_data(rr, no_config = True):
    client_mongita = MongitaClientDisk(host = AIDBPATH)
    for r in rr:
        mongitadb = client_mongita[r["name"]]
        for col, val in r["collections"].items():
            try:
                if no_config:
                    if col == "azumaril_app_config_data_secret" or col == "config_data_secret_type":
                        #don't save the configuration file
                        continue
                mongitadb[col].delete_many({})
            except:
                print("--something went wrong but don't worry--")
            
            mongitadb[col].insert_many(val)
    return True

def mongita_node_insert(node_info):
    try:
        client_mongita = MongitaClientDisk(host = AIDBPATH)
        mongitadb = client_mongita["RAFTDB"]
        mongitadb["NodeInfo"].delete_one({"raft_node_info" : True})
        # del node_info[""]
        # mongitadb["NodeInfo"].insert_one({"raft_node_info" : True, "data" : json.dumps(node_info, indent=2, sort_keys=True)})
        mongitadb["NodeInfo"].insert_one({"raft_node_info" : True, "data" : node_info})
    except:
        print(traceback.format_exc())

conf = SyncObjConf()
conf.onStateChanged = state_changed_callback
conf.dynamicMembershipChange = True
conf.maxBindRetries = 2
trf = random.randint(1,5)
counter1 = ReplCounter()

class Resources(SyncObjConsumer):
    def __init__(self):
        super(Resources, self).__init__()
        self.resources = {}
        self.seal = True
        self.ecptk = None
    
    @replicated
    def add(self, rid, idata):
        self.resources[rid] = idata
        # print("-9-9-9-")
        # print(self.resources)
        if rid == "dbs":
            insert_azumaril_shamir_data(self.resources[rid])
        if rid == "nodes":
            print("adding nodes")
            print(self.resources[rid])
            mongita_node_insert(self.resources[rid])
        if rid == "raft_info":
            az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
            prtns = az_raft_config["partners"] + idata["partners"]
            if az_raft_config["host"] in prtns:
                prtns.remove(az_raft_config["host"])
            prtns = list(set(prtns))
            
            # print(f"-----------------------{prtns}--------------------")
            azumaril_app_info.update_one(
                {"type" : "raft"},
                {
                    "$set" : {"partners" : prtns}
                }
            )
        if rid == "dbnl":
            # print(idata)
            azumaril_app_info.delete_one({"type" : "db_node_info"})
            azumaril_app_info.insert_one(
                {
                    "type" : "db_node_info",
                    "data" : idata
                }
            )

    @replicated
    def update_seal_ecptk(self, seal, ecptk):
        self.seal = seal
        self.ecptk = ecptk
        print(self.seal)
        print(self.ecptk)
    
    def gr(self, rid):
        return self.resources[rid]

def wait_for_transport(sync_obj, timeout=10):
    import time
    start_time = time.time()
    while not sync_obj.isReady():
        if time.time() - start_time > timeout:
            break
            raise TimeoutError("SyncObj transport is not ready within the timeout period.")
        print("Waiting for transport to be ready...")
        time.sleep(1)  # Wait for 1 second before rechecking
    print("Transport is ready!")
    
SHARED_DATA = Resources()
class RaftProcess(SyncObj):
    def __init__(self):#, raft_host = raft_host, partners = partners, conf = conf, SHARED_DATA = SHARED_DATA, counter1 = counter1
        super(RaftProcess, self).__init__(raft_host, partners, conf = conf, consumers = [counter1, SHARED_DATA]) #
        print(f"raft_host ------ {raft_host}")
        print(f"partners ---- {partners}")
        counter1.set(trf)
        self.__counter = 0

    @replicated(_doApply=True)
    def incCounter(self, **kwargs):
        try:
            print("etrehgjhdgjdhgjdgd")
            self.__counter += 1
        except:
            print("-----------***********-----------**********")
            print(traceback.format_exc())

    @replicated
    def onStartUp(self):
        print("***********")
        print(f"counter 1 : {counter1.get()}")
        print("***********")
        leader = self.get_status()["leader"]
        if self.get_status()["leader"] is not None:
            print(f"leader is {leader}")
            url = f"https://{leader.split(':')[0]}:{initapp_port}/sync"
            res = requests.post(url, verify = False)
            print(res.json())
        else:
            print("No leader yet")
        # SHARED_DATA.add('nodes', self.get_status())
        
    def onLeaderChanged(self):
        az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
        del az_raft_config["_id"]
        SHARED_DATA.add('raft_info', az_raft_config)
        data = azumaril_shamir_data()
        SHARED_DATA.add('dbs', data)
        dbnl = node_list()
        SHARED_DATA.add('dbnl', dbnl)
        SHARED_DATA.add('nodes', self.get_status())

    def OnNodesChange(self):
        az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
        del az_raft_config["_id"]
        SHARED_DATA.add('raft_info', az_raft_config)
    
    def onSync(self):
        data = azumaril_shamir_data()
        SHARED_DATA.add('dbs', data)
        print(self.get_status())
        SHARED_DATA.add('nodes', self.get_status())
        print("\nInitialisation data had been spread through the nodes!\n")
        
    def onAzumarilInit(self):
        data = azumaril_shamir_data()
        SHARED_DATA.add('dbs', data)
        SHARED_DATA.add('nodes', self.get_status())
        # print("--------***************--------alban")
        # print(data)
        # print("--------***************--------alban")
        print("\nInitialisation data had been spread through the nodes!\n")

    def unsealaz(self, seal, ecptk):
        SHARED_DATA.update_seal_ecptk(seal, ecptk)

    def getCounter(self):
        print("tretre-fddf-----dfd")
        return self.__counter
    
    def get_status(self) -> Dict:
        status = self.getStatus()
        status['self'] = status['self'].address

        if status['leader']:
            status['leader'] = status['leader'].address

        serializable_status = {
            **status,
            'is_leader': status['self'] == status['leader'],
        }
        return serializable_status


    def is_leader(self) -> bool:
        return self.get_status().get('is_leader')

def is_leader():
    res = requests.get(f"https://localhost:{initapp_port}/raft-info", verify = False)
    raft_info = res.json()
    leader = raft_info["is_leader"]
    return leader


def start_flask_app():
    global app_thread
    if app_thread is None or not app_thread.is_alive():
        app_thread = Thread(target=run_flask_app)
        app_thread.start()

def create_default_secret(secret, secret_salt, oneFile=False, super_admin=False):
    try:
        # global config_data
        secret_jwt = jwt.encode(secret, secret_salt, algorithm="HS256")
        encrypted_data = encrypt(secret_jwt, encryption_key=secret_salt)
        encrypted_data_jwt = jwt.encode(
            {
                "ciphertext": encrypted_data[0],
                "tag": encrypted_data[1],
                "nonce": encrypted_data[2],
            },
            secret_salt,
            algorithm="HS256",
        )

        secret_name = list(secret.keys())[0] if not oneFile else "config_data"
        if super_admin:
            secret_name = "SUPERADMIN"
        if cd_secret_collection.find_one({"name": secret_name}) is not None:
            cd_secret_collection.update_one(
                {"name": secret_name}, {"$set": {"secret": encrypted_data_jwt}}
            )
        else:
            cd_secret_collection.insert_one(
                {
                    "id": str(ObjectId()),
                    "name": secret_name,
                    "oneFile": oneFile,
                    "secret": encrypted_data_jwt,
                }
            )
        print(f"\ndefault secret created !\n")
        # CustomThread(target = get_default_secret, args=({"secret" : encrypted_data_jwt}, secret_salt,)).start()
        # default_secret_keys = list(cd_secret_collection.find({}))
        # config_data = {}
        # for default_secret_key in default_secret_keys:
        #     decrypted_default_secret_key = get_default_secret(default_secret_key, secret_salt)
        #     config_data[default_secret_key["name"]] = decrypted_default_secret_key
        return True
    except:
        return False

def stop_flask_app():
    global app_thread
    if app_thread and app_thread.is_alive():
        app_thread.join(timeout=1)


# if not initiated:
if not args["nothing"] and not args["unseal"] and not args["seal"]:
    start_flask_app()
    time.sleep(2)
    try:
        gas = get_app_state()
        seal = gas["seal"]
    except:
        print(traceback.format_exc())
        pass

def valid(data, license_key, public_key):
    with open(public_key, 'rb') as file:
        data2 = file.read()
        data2 = data2.decode("utf-8")
        # print(data2)
        key = rsa.PublicKey.load_pkcs1(data2.encode())
        # print(type(key))
    try:
        # print(f"data.encode() = {data.encode()}")
        # print(unhexlify(license_key))
        rsa.verify(data.encode(), unhexlify(license_key), key)
    except rsa.VerificationError:
        return False
    else:
        return True

def verify_licence_keys(keys):
    pk_path = os.path.dirname(__file__) + f"/../static/"
    if getattr(sys, "frozen", False):
        pk_path = f"{sys._MEIPASS}/static"
    license_pk_path = f"{pk_path}/license_public_key.pem"
    return valid(keys[0], keys[1], license_pk_path)

def extract_keys(filename):
    start_marker = '*************KEYS*************'
    end_marker = '*************KEYS*************'
    
    with open(filename, 'r') as file:
        content = file.read()
    
    start_index = content.find(start_marker)
    if start_index == -1:
        return None  # Start marker not found
    start_index += len(start_marker)
    
    end_index = content.find(end_marker, start_index)
    if end_index == -1:
        return None  # End marker not found
    
    return content[start_index:end_index].strip()

def is_date_expired(date_string):
    try:
        date_format = "%Y/%m/%d %H:%M:%S"
        date_obj = datetime.strptime(date_string, date_format)
        current_time = datetime.now()
        return date_obj < current_time
    except ValueError:
        raise ValueError("Incorrect date format. Please use 'year/month/day hour:minute:second'.")

LICENSE_FILE_PATH = os.environ.get("LICENSE_FILE_PATH", None)
LICENSE_CHECK_URL = os.environ.get("LICENSE_CHECK_URL", "http://localhost:3000/api/v1/licence/check")
# LICENSE_INFO = None
if LICENSE_FILE_PATH is not None:
    keys = extract_keys(LICENSE_FILE_PATH).split("\n")
    linfo = keys[0]
    key = keys[1]
    LICENSE_INFO = b64decode(linfo).decode("utf-8")
    LICENSE_INFO = ast.literal_eval(LICENSE_INFO)
    if LICENSE_INFO["activation_type"] == "offline":
        if verify_licence_keys(keys):
            print("license verified!")
            active_cluster_mode = LICENSE_INFO["features"].get('raft', False)
            args["start_cluster"] = LICENSE_INFO["features"].get('raft', False)
            os.environ["AXMARIL_LICENSE_INFO"] = str(LICENSE_INFO)
        else:
            print("license not verified!")
            LICENSE_INFO = None
    else:
        files = {"file" : open(LICENSE_FILE_PATH, "rb")}
        response = requests.post(
            LICENSE_CHECK_URL,
            # headers = headers,
            files = files,
        )
        if response.status_code < 300 and response.status_code >= 200:
            LICENSE_INFO = response.json()["data"]
            os.environ["AXMARIL_LICENSE_INFO"] = LICENSE_INFO

def raft_watcher(raft):
    while True:
        time.sleep(10)
        d = raft.getStatus()
        print()
        print()
        print()
        print("***************RAFT INFO*************")
        print(d)
        print("***************RAFT INFO*************")

# print("RAFT_HOST------------partners")
# print(args["start_cluster"])
if active_cluster_mode:             #run azumaril in cluster mode
    
    print()
    print("*******************************")
    print("------CLUSTER MODE ACTIVE------")
    print("*******************************")
    print()
    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
    raft_host = az_raft_config["host"]
    partners = az_raft_config["partners"]
    # print(f"raft_host {raft_host}")
    # print(f"partners {partners}")
    raft_params_missing = raft_host is None or partners is None
    
    #Start a brand new cluster as the first node
    if args["start_cluster"]:
        print("trying to fetch raft_host and parteners")
        while raft_params_missing:
            time.sleep(1)
            raft_params_missing = raft_host is None or partners is None
            raft_host = raft_host if raft_host is None else os.environ.get("RAFT_HOST", None)
            partners = partners if partners is None else os.environ.get("RAFT_PARTNERS", None)
        SYNC_OBJ = RaftProcess()
        # wait_for_transport(SYNC_OBJ)
        SYNC_OBJ.waitBinded()
        SYNC_OBJ.waitReady()
        SYNC_OBJ.onStartUp()
    
    #Join a cluster
    if args["mode_cluster"]:
        if not raft_params_missing:
            SYNC_OBJ = RaftProcess()
            # (SYNC_OBJ)
            # t2 = CustomThread(target=raft_watcher, args=(SYNC_OBJ,))
            # t2.start()
            # SYNC_OBJ.waitBinded()
            # SYNC_OBJ.waitReady()
            # wait_for_transport(SYNC_OBJ)
            # SYNC_OBJ.onStartUp()
        else:
            while SYNC_OBJ is None and not sobj:
                print("waiting")
                time.sleep(2)
                try:
                    print(os.environ["RAFT_HOST"])
                    print(os.environ["RAFT_PARTNERS"])
                except:
                    pass
            raft_host = os.environ["RAFT_HOST"]
            partners = os.environ["RAFT_PARTNERS"].split(",")
            # print(raft_host)
            # print(partners)
            # print(conf)
            # print(counter1)
            # print(SHARED_DATA)
            SYNC_OBJ = RaftProcess()
            SYNC_OBJ.waitBinded()
            SYNC_OBJ.waitReady()
            wait_for_transport(SYNC_OBJ)
            SYNC_OBJ.onStartUp()

# t2 = CustomThread(target=raft_watcher, args=(SYNC_OBJ,))
# t2.start()

# stop until azumaril initiated
while not initiated:
    time.sleep(1)
    result = loader_v2({"app": True}, False, False)
    try:
        appinfo = parse_app_info(result)
        initiated = appinfo["Init"]
    except:
        initiated = False
    # if initiated:
    #     stop_flask_app()
azumaril_app_info.update_one({"type": "status"}, {"$set": {"init": True}})

if nseal:  # not (args["unseal"] or args["seal"]) and
    print("app sealed")
    print("trying to unseal")
    inputs = f"yes\n\n\n"

    ecptk = loader_v2({}, AZUMARIL_KEYS is not None, False, inputs=inputs, outputs = False)
    EC_PTK: Final[str] = ecptk
    if ecptk is None or "do you want to unseal" in ecptk:
        print("failed to unsealed")
    else:
        default_secret_keys = list(cd_secret_collection.find({}))
        if len(default_secret_keys) == 0:
            print("app unsealed but, config_data is null")
        config_data = {}
        for default_secret_key in default_secret_keys:
            decrypted_default_secret_key = get_default_secret(
                default_secret_key, EC_PTK
            )
            config_data.update(decrypted_default_secret_key)
    seal = ecptk is None
    if AZUMARIL_KEYS is None:
        seal = True
    azumaril_app_info.update_one({"type": "status"}, {"$set": {"seal": seal}})

if args["unseal"] or args["seal"] or args["nothing"]:
    print("nothing")
else:
    # stop until azumaril unsealed
    if seal:
        print("app sealed")
    else:
        print("app unsealed")
    while seal and SHARED_DATA.seal:
        print(f"{SHARED_DATA.seal}-----{SHARED_DATA.ecptk}")
        if not SHARED_DATA.seal:
            ecptk = SHARED_DATA.ecptk
        gas = get_app_state()
        seal = gas["seal"]
        time.sleep(1)

    azumaril_app_info.update_one({"type": "status"}, {"$set": {"seal": False}})

no_args = args == {
    "debug": False,
    "action": "start",
    "config": None,
    "reset_shamir": None,
    "status": None,
    "seal": None,
    "unseal": None,
    "nothing": None,
    "init": None,
    "update_last_stable": None,
    "update_last_dev": None,
}

if args["action"] == "start" or no_args:
    fars = azumaril_app_info.find_one({"type": "status"})
    if fars["pid"] is not None and check_pid(fars["pid"]):
        print(fars["pid"])
        print("already running..")
        sys.exit(1)
    update_aai(running=True, init=None, seal=None)
    while seal:
        print("running")
        time.sleep(1)
        if initiated and not seal:
            break

if args["action"] == "stop":
    update_aai(running=False, init=None, seal=None)
    fars = azumaril_app_info.find_one({"type": "status"})
    print(fars)
    killed = kill_process(fars["pid"])
    if not killed:
        print("already stoped!")
        sys.exit(1)
    else:
        print("successfully stoped!")
        sys.exit(1)
# ------------------service------------------
# -------------------------------------------
# -------------------------------------------

# check environment varaibale path
# if args["config"] is None or args["config"] == "":
#     args["config"] = input("Please enter the config.env file path : ")
# print("reading env variable at : " + args["config"] + "..")
# if not os.path.exists(args["config"]):
#     print("failed to load the config file, file not found or bad file path was provided")
#     sys.exit(1)

# # Open the JSON file and read its contents
# with open(args["config"], 'r') as f:
#     data = f.read()
#     config_data = json.loads(data)
#     f.close()
# print(config_data)
if (args["update_last_stable"] is not None and args["update_last_stable"]) or (
    args["update_last_dev"] is not None and args["update_last_dev"]
):
    url = (
        config_data["AZUMARIL_UPDATE_STABLE_LINK"]
        if args["update_last_stable"]
        else config_data["AZUMARIL_UPDATE_DEV_LINK"]
    )
    print("updating..")
    if getattr(sys, "frozen", False):
        binary_dir = os.path.dirname(os.path.abspath(sys.executable))
        temp_path = f"{binary_dir}/temp"
    else:
        temp_path = f"{os.path.dirname(__file__)}/../dist/temp"
    if not os.path.exists(temp_path):
        print(f"generating temp folder : '{temp_path}'..")
        os.makedirs(temp_path)
    headers = {"PRIVATE-TOKEN": config_data["AZUMARIL_UPDATE_ACCESS_TOKEN"]}
    print("downloading the file ..")
    response = httpx.get(url, headers=headers)
    print("saving the file")
    with open(f"{temp_path}/azumaril", "wb") as f:
        f.write(response.content)
        f.close()
    print("file downloaded!")
    print("adding right x..")
    add_rightx_process = subprocess.Popen(
        ["sudo", "chmod", "+x", f"{temp_path}/azumaril"], stdout=subprocess.PIPE
    )
    print("right added")
    if getattr(sys, "frozen", False):
        binary_dir = os.path.dirname(os.path.abspath(sys.executable))
        subprocess.Popen(
            [
                "sudo",
                "python3",
                f"{sys._MEIPASS}/static/updater.py",
                "--path",
                binary_dir,
            ],
            stdout=subprocess.PIPE,
        )
    else:
        subprocess.Popen(
            ["sudo", "python3", f"{os.path.dirname(__file__)}/../static/updater.py"],
            stdout=subprocess.PIPE,
        )
    print("azumaril successfully updated!")
    sys.exit(1)
    # shutil.rmtree(temp_path)

default_required_config_data = [
    "DEBUG",
    "API_PORT",
    "DATABASE_PATH",
    "DATABASE_PORT",
    "DATABASE_HOST",
    "DATABASE_NAME",
    "LOCAL_DATABASE",
    "CORS",
    "GUI",
    "FRONT_API_URL",
    "DATABASE_CREDENTIAL_LINK",
    "TOKEN_SECRET_SALT",
    "TOKEN_SECRET_AUTH_TOKEN",
    "TOKEN_SECRET_TASK_TOKEN",
    "FRONTEND_PORT",
    "API_URL",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_FROM",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "LOG_PATH",
    "LDAP",
]

EC_PTK: Final[str] = ecptk
# print(f"EC_PTK : ----- {EC_PTK}")
if not SHARED_DATA.seal:
    EC_PTK = SHARED_DATA.ecptk
for drcd in default_required_config_data:
    if config_data is None:
        config_data = {}
    while drcd not in config_data:
        time.sleep(1)
        default_secret_keys = list(cd_secret_collection.find({}))
        # print(default_secret_keys)
        config_data = {}
        for default_secret_key in default_secret_keys:
            decrypted_default_secret_key = get_default_secret(
                default_secret_key, EC_PTK
            )
            if decrypted_default_secret_key is None:
                break
            config_data.update(decrypted_default_secret_key)
        print(f"missing key {drcd}, please provide it in config data")
# print(config_data)
# if config_data["RAFT"]["active"]:
#     if "RAFT_HOST" not in os.environ:
#         raft_host = config_data["RAFT"]["host"]
#     if "RAFT_PARTNERS" not in os.environ:
#         partners = config_data["RAFT"]["parteners"]

# if not ("RAFT_HOST" in os.environ and "RAFT_PARTNERS" in os.environ):
#     if config_data["RAFT"]["active"] and SYNC_OBJ is None:
#         SYNC_OBJ = RaftProcess()
#         SYNC_OBJ.waitBinded()
#         SYNC_OBJ.waitReady()

# dotenv_path = Path(args["config"])
# load_dotenv(dotenv_path=dotenv_path)


DATABASE_PATH = config_data["DATABASE_PATH"]
LOCAL_DATABASE = config_data["LOCAL_DATABASE"]
DATABASE_HOST = config_data["DATABASE_HOST"]
DATABASE_PORT = config_data["DATABASE_PORT"]
DATABASE_NAME = config_data["DATABASE_NAME"]
API_PORT = config_data["API_PORT"]
DEBUG = config_data["DEBUG"]
ALLOWED_CORS = config_data["CORS"]
KMIP_PORT = config_data["KMIP_PORT"]
KMIP_ENABLED = config_data["KMIP_ENABLED"]



        
def run_mongosh_command(command, output = False):
    try:
        mongosh_exe = os.path.dirname(__file__) + f"/../static/mongo_server/mongosh"
        if getattr(sys, "frozen", False):
            mongosh_exe = f"{sys._MEIPASS}/static/mongo_server/mongosh"
        mongosh_cmd = [mongosh_exe, "--port", str(config_data["DATABASE_PORT"]), "--eval", command]
        mongosh_process = subprocess.Popen(mongosh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log = ""
        for line in mongosh_process.stdout:
            log += f"{line.strip()}\n"
        if output:
            print(log)
            
        mongosh_process.wait()
        if mongosh_process.returncode != 0:
            print("Error occurred while executing mongosh:")
            for line in mongosh_process.stderr:
                print(line.strip())
        else:
            print(f"{command} command executed successfully.")
    except:
        print(traceback.format_exc())


def set_db_primary():
    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
    raft_host = az_raft_config["host"]
    command = """
    cfg = rs.conf()
    cfg.members.forEach(function(member) {
        if (member.host === "localhost:dbport") {
            member.priority = 2; // Set a higher priority for the desired member
        } else {
            member.priority = 1; // Set the default priority for other members
        }
    })
    rs.reconfig(cfg)
    """
    # for nl in node_list:
    #     if nl["stateStr"] == 'PRIMARY':
    #         name = nl["name"]
    #         client = pymongo.MongoClient(host=name.split(":")[0], port=int(name.split(":")[1]))
    #         primary_client.admin.command("replSetStepDown")
    #         time.sleep(10)  # Adjust this delay as needed
            
    command = command.replace("dbport", f"{str(config_data['DATABASE_PORT'])}")
    command = command.replace("localhost", f"{raft_host.split(':')[0]}")
    
    # run_mongosh_command(command, output = False)

def is_primary():
    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
    raft_host = az_raft_config["host"]
    name = f"{raft_host.split(':')[0]}:{DATABASE_PORT}"
    status = client.admin.command('replSetGetStatus')
    for member in status['members']:
        if name == member["name"]:
            if member['stateStr'] == 'PRIMARY':
                return True
            return False
        continue
    return False

def is_in_node():
    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
    raft_host = az_raft_config["host"]
    try:
        name = f"{raft_host.split(':')[0]}:{DATABASE_PORT}"
        status = client.admin.command('replSetGetStatus')
        for member in status['members']:
            if name == member["name"]:
                return True
            continue
        return False
    except:
        return False


def start_db(dbpath):
    dist = distro.id()
    mongod_exe = os.path.dirname(__file__) + f"/../static/mongo_server/{dist}/mongod"
    if getattr(sys, "frozen", False):
        mongod_exe = f"{sys._MEIPASS}/static/mongo_server/{dist}/mongod"
    if not os.path.exists(mongod_exe):
        print("could not verify a valid database version, trying with the default one")
        mongod_exe = mongod_exe.replace(f"{dist}/mongod", "mongod")
    dblog = config_data.get("DATABASE_LOG", None)
    if dblog is not None:
        dblog_folder = dblog.replace(f'/{dblog.split("/")[-1]}', '')
        if not os.path.exists(dblog_folder):
            os.makedirs(dblog_folder)
    if not os.path.exists(dbpath):
        print("Database path not existing")
        print("Generating database path")
        os.makedirs(dbpath)  # /etc/azumaril
    dbargs = [
        mongod_exe,
        "--fork",
        "--bind_ip_all",
        "--logpath",
        config_data.get("DATABASE_LOG", "mongodb.log"),
        "--dbpath",
        dbpath,
        "--port",
        str(config_data["DATABASE_PORT"]),
    ]
    az_raft_config = azumaril_app_info.find_one({"type" : "raft"})
    raft_host = az_raft_config["host"]
    
    if active_cluster_mode:
        dbargs.append("--replSet")
        try:
            repl_name = config_data["DATABASE_REPLICATION_CONFIG"]["name"]
        except:
            repl_name = "AZUMARIL_DATABASE_REPLICATION_CLUSTER"
        dbargs.append(repl_name)
            
    p = subprocess.Popen(
        dbargs,
        stdout=subprocess.PIPE,    # Capture standard output
    stderr=subprocess.PIPE  
    )
        # Wait for the process to complete and get the output
    stdout, stderr = p.communicate()

    # Decode the output from bytes to string
    stdout = stdout.decode('utf-8')
    stderr = stderr.decode('utf-8')

    # Print the outputs
    # print("Standard Output:")
    # print(stdout)

    # print("Standard Error:")
    # print(stderr)
    if active_cluster_mode:
        command = """
        rs.initiate({_id: "azumaril_replication", members: [
        {_id: 0, host: 'rafthost:dbport'}
        ]})
        """
        db_node_info = azumaril_app_info.find_one({"type" : "db_node_info"})
        if db_node_info is not None:
            print("-----------------------")
            print("-----------------------")
            time.sleep(2)
            members = []
            for d in db_node_info["data"]:
                members.append(d["name"])
            print(members)
            if len(members) == 0:
                members.append(raft_host)
                members += az_raft_config["partners"]
            command = command.replace("azumaril_replication", repl_name)
            command = command.replace("rafthost:dbport", members[0])
            # command = command.replace("dbport", str(config_data["DATABASE_PORT"]))
            run_mongosh_command(command, output = True)
            members.remove(members[0])
            curent_db_node = f'{raft_host.split(":")[0]}:{config_data["DATABASE_PORT"]}'
            for member in members:
                command = f"rs.add('{member}')"
                run_mongosh_command(command, output = True)
            if curent_db_node not in members:
                command = f"rs.add('{curent_db_node}')"
                run_mongosh_command(command, output = True)
        else:
            
            # run_mongosh_command("rs.initiate()", output = config_data["DEBUG"])
            time.sleep(2)
            count = 0
            if not is_in_node():
                print("not in node")
                curent_db_node = f'{raft_host.split(":")[0]}:{config_data["DATABASE_PORT"]}'
                command = command.replace("azumaril_replication", repl_name)
                command = command.replace("rafthost:dbport", curent_db_node)
                # command = command.replace("dbport", str(config_data["DATABASE_PORT"]))
                run_mongosh_command(command, output = True)
            else:
                print("in node")
            prtns = az_raft_config["partners"]
            # hst = az_raft_config["host"]
            members = []
            for pe in prtns:
                members.append(f'{pe.split(":")[0]}:{config_data["DATABASE_PORT"]}')

            for member in members:
                command = f"rs.add('{member}')"
                run_mongosh_command(command, output = True)
        #     command += "\n{_id:" + f" {count}, host: '{member}'" +"}," "rs.add( { host:'127.0.0.1:27018'} )"
        #     print(command)
        #     count +=1
        # command += "\n]})"
        # # co
        # run_mongosh_command(command, output = True)
    # print("waiting for database setup")
    # time.sleep(5)
    # print(f"database pid {p.pid}")
    return p.pid

def wait_for_kmip(port, timeout=30):
    """
    Attendre que le serveur KMIP écoute sur le port spécifié.
    :param port: Port sur lequel le serveur KMIP doit écouter.
    :param timeout: Temps maximum d'attente (en secondes).
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("127.0.0.1", port))
                time.sleep(2)
                print(f"KMIP est prêt sur le port {port}.")
                return True
            except ConnectionRefusedError:
                print(f"KMIP n'est pas encore prêt. Réessai...")
                time.sleep(1)
    raise TimeoutError(f"KMIP n'a pas démarré dans le délai imparti ({timeout} secondes).")

def start_kmip(f):
    dist = distro.id()
    #load_dotenv("/home/AZUMARIL/static/.env")
    # kmip_exe = "/home/AZUMARIL/static/kmip"
    env_file_path = "/home/AZUMARIL/modules/.env"
    kmip_exe = os.path.dirname(__file__) + f"/../static/kmip"
    if getattr(sys, "frozen", False):
        kmip_exe = f"{sys._MEIPASS}/../static/kmip"
    # if not os.path.exists(kmip_exe):
    #     print("could not verify a valid database version, trying with the default one")
    #     kmip_exe = kmip_exe.replace(f"{dist}/kmip", "kmip")
    print(f"debugage------------------{kmip_exe}")   
    if KMIP_ENABLED :
        try:
            k_args = [
                kmip_exe,
                "--env",
                env_file_path
            ]
            print(f"Lancement de KMIP avec : {k_args}")
            print(f"debugage------------------{kmip_exe}")
            run_k = subprocess.Popen(
                k_args,
                stdout=subprocess.PIPE,    # Capture standard output
                stderr=subprocess.PIPE,
                close_fds=True
            )
            
            wait_for_kmip(KMIP_PORT)
            stdout, stderr = run_k.communicate()

            # Decode the output from bytes to string
            stdout = stdout.decode('utf-8')
            stderr = stderr.decode('utf-8')
            
            print(f"STDOUT : {stdout}")
            print(f"STDERR : {stderr}")
            
        except FileNotFoundError:
            print("Erreur : l'exécutable kmip est introuvable.")
        except TimeoutError as e:
            print(f"Erreur de démarrage : {e}")
        except subprocess.SubprocessError as e:
            print(f"Erreur du processus : {e}")
        except Exception as e:
            print(f"Une erreur inattendue est survenue : {e}")
        
# start_kmip()
t2 = CustomThread(target=start_kmip, args=("",))
t2.start()



# def start_kmip(nothing = None):
#     try:
#         server = KmipServer(
#             hostname='0.0.0.0',
#             port=KMIP_PORT,
#             auth_suite='TLS1.2',
#             config_path='/home/AZUMARIL/modules/kmip_etc/server.conf',
#             log_path='/home/AZUMARIL/modules/kmip_etc/server.log',
#             policy_path='/home/AZUMARIL/modules/kmip_etc/policies',
#             enable_tls_client_auth=False,
#             tls_cipher_suites='ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256',
#             logging_level='DEBUG',
#             database_path='/tmp/pykmip.db'
#         )
#         print("Serveur KMIP créé avec succès.")

#         print("Démarrage du serveur KMIP...")
#         server.start()  # Initialise le serveur et le socket.
#         server.serve()  # Démarre le service et reste actif.
#         print("Serveur KMIP démarré avec succès.")
        
#     except KeyboardInterrupt:
#         print("Arrêt du serveur KMIP...")
#         server.stop()  # Arrête le serveur proprement
#     except Exception as e:
#         print(f"Une erreur s'est produite : {e}")
#         logging.exception("Erreur lors du démarrage du serveur KMIP")
    # try:
    #     if KMIP_ENABLED is True:
            
    #         print(f"----------------------{KMIP_PORT}")
    #         kill_process_by_port(KMIP_PORT)
    #         kmip_process = subprocess.Popen(["python3", "/home/AZUMARIL/modules/kmip_server.py", str(KMIP_PORT)])
    #         print("Processus KMIP lancé avec succès. PID:", kmip_process.pid)

    #         # Attendre que le serveur KMIP soit prêt
    #         wait_for_kmip(KMIP_PORT)
    # except Exception as e:
    #     print(f"Échec du lancement du processus KMIP : {e}")

# t2 = CustomThread(target=start_kmip, args=("",))
# t2.start()
"""try:
    server = KmipServer(
        hostname='0.0.0.0',
        port=KMIP_PORT,
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
print("it's continuing")"""
# start_kmip() 


# def start_db(dbpath, secure = True):
#     dist = distro.id()
#     print("starting database server..in " + dist + " server ")
#     mongod_exe = os.path.dirname(__file__) + f"/../static/mongo_server/{dist}/mongod"
#     if getattr(sys, 'frozen', False):
#         mongod_exe = f"{sys._MEIPASS}/static/mongo_server/{dist}/mongod"
#     if not os.path.exists(dbpath):
#         print("Database path not existing")
#         print("Generating database path..")
#         os.makedirs(dbpath)
#     if secure:
#         p = subprocess.Popen([mongod_exe, "--auth", "--dbpath", dbpath],
#                             stdout=subprocess.PIPE)
#     else:
#         p = subprocess.Popen([mongod_exe, "--dbpath", dbpath],
#                             stdout=subprocess.PIPE)
#     print('database server started')
#     # print(f"database pid {p.pid}")
#     return p.pid


class StandaloneApplication(gunicorn.app.base.BaseApplication):

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def start_front_server(t):
    static_folder = os.path.dirname(__file__) + "/../static/frontend"
    if getattr(sys, "frozen", False):
        static_folder = f"{sys._MEIPASS}/static/frontend"
    file_path = f"{static_folder}/assets/index.d9dd14da.js"
    with open(file_path, "r") as file:
        content = file.read()
    input_string = content
    pattern = r'forProd:"([^"]*)"'
    pattern2 = r'forDev:"([^"]*)"'
    pattern3 = r'forWebSocket:"([^"]*)"'
    pattern4 = r'__name:"app-config",setup(e){const t="([^"]*)"'
    
    fau = config_data["FRONT_API_URL"] + f"/api/v1"
    facu = config_data.get("FRONT_CONFIG_API_URL", "https://localhost:54321")
    WEBSOCKET_LINK = config_data["WEBSOCKET_LINK"]
    print(f"FRONT_API_URL : {fau}")
    replacement = f'forProd:"{fau}"'
    replacement2 = f'forDev:"{fau}"'
    replacement3 = f'forWebSocket:"{WEBSOCKET_LINK}"'
    co = '__name:"app-config",setup(e){const t="'
    replacement4 = f'{co}{facu}"'
    modified_string = re.sub(pattern, replacement, input_string)
    modified_string = re.sub(pattern2, replacement2, modified_string)
    modified_string = re.sub(pattern3, replacement3, modified_string)
    modified_string = re.sub(pattern4, replacement4, modified_string)
    with open(file_path, "w") as file:
        file.write(modified_string)
    app_ui = Flask(__name__, static_folder=static_folder)

    @app_ui.route("/", defaults={"path": ""})
    @app_ui.route("/<path:path>")
    def serve(path):
        if path != "" and os.path.exists(app_ui.static_folder + "/" + path):
            return send_from_directory(app_ui.static_folder, path)
        else:
            return send_from_directory(app_ui.static_folder, "index.html")

    print("running front server")
    # from waitress import serve
    # serve(app_ui, host="0.0.0.0", port=int(config_data["FRONTEND_PORT"]))

    cert_file = os.path.dirname(__file__) + "/../static/certificate.crt"
    key_file = os.path.dirname(__file__) + "/../static/private.key"
    if getattr(sys, "frozen", False):
        cert_file = f"{sys._MEIPASS}/static/certificate.crt"
        key_file = f"{sys._MEIPASS}/static/private.key"

    AZUMARIL_CRT_PATH = config_data.get("AZUMARIL_CRT_PATH", None)
    AZUMARIL_KEY_PATH = config_data.get("AZUMARIL_KEY_PATH", None)
    key_file = key_file if AZUMARIL_KEY_PATH is None else AZUMARIL_KEY_PATH
    cert_file = cert_file if AZUMARIL_CRT_PATH is None else AZUMARIL_CRT_PATH

    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print("not found a valid certificate")
        print("generating a new certificate..")
        generate_ssl_certificates(cert_file, key_file)
    http_server = WSGIServer(
        ("0.0.0.0", config_data["FRONTEND_PORT"]), app_ui, keyfile=key_file, certfile=cert_file
    )
    print(f"FRONT URL : https://localhost:{config_data['FRONTEND_PORT']}")
    http_server.serve_forever()


if config_data["GUI"]:
    t2 = CustomThread(target=start_front_server, args=("",))
    t2.start()
ldapState = False
db_pid = None
if LOCAL_DATABASE:
    db_pid = start_db(DATABASE_PATH)
    client = pymongo.MongoClient(host=DATABASE_HOST, port=int(DATABASE_PORT))
    db002 = client[DATABASE_NAME]
else:
    DATABASE_CREDENTIAL_LINK = config_data["DATABASE_CREDENTIAL_LINK"]
    client = pymongo.MongoClient(DATABASE_CREDENTIAL_LINK)
    db002 = client[DATABASE_NAME]
    
if config_data.get("LAUNCH_GUACAMOLE_ON_STARTUP", False):
    mariadb_path = config_data.get("GUACAMOLE_MARIADB_PATH")
    mariadb_user = config_data.get("GUACAMOLE_MARIADB_USER", "root")
    ri_args = {'dbpath': mariadb_path, 'user': mariadb_user, 'password': None, 'start_guacd': False, 'start_tomcat': False, 'start_maria': False, 'launch_guacamole_service': False}
    launch_guacamole_service(ri_args)

# if config_data.get("guacamole", False):
#     t3 = CustomThread(target=start_guacamole_utils, args=(True,))
#     t3.start()

server = None
# with open('/home/AZUMARIL/static/data.json', 'r') as file:
#     json_data = json.loads(file.read())
# try:
#     for k,v in json_data.items():
#         if len(v) == 0:
#             continue
#         db002[k].insert_many(v)
# except:
#     print(traceback.format_exc())


try:
    creds = db002["creds"]
    fileserver = creds.find_one({"type": "File_Server"})
    file_server_url = fileserver["ip"]
    password_expiration = 90
    credsData = creds.find({"type": "token_secret"})[0]
    salt = credsData["salt"]
    tokens = db002["tokens"]
    index_name = "token_ttl_index"
    index_name2 = "temp_password_ttl_index"
    index_info = db002["tokens"].index_information()
    index_info_tp = db002["temp_password"].index_information()
    expire_after_seconds = 24 * 60 * 60  # 24 hours
    expire_after_seconds_tp = 60 * 10  # 10 minutes
    if index_name not in index_info:
        if active_cluster_mode:
            if is_primary():
                db002["tokens"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds,
                    name=index_name,
                )
        else:
            db002["tokens"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds,
                    name=index_name,
                )
    if index_name2 not in index_info_tp:
        if active_cluster_mode:
            if is_primary():
                db002["temp_password"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds_tp,
                    name=index_name2,
                )
        else:
            db002["temp_password"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds_tp,
                    name=index_name2,
                )
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    validated_status = True
    logs = db002["logs"]
    logs_code = db002["logs_code"]
    users = db002["users"]
    safes = db002["safe"]
    secrets = db002["secrets"]
    shares = db002["shares"]

    tokSecret = creds.find_one({"type": "token_secret"})
    airflow = creds.find_one({"type": "airflow"}, {"_id": 0})
    dagInfo = airflow["dagInfo"]
    # ---new-----
    ldap_server = creds.find_one({"type": "ldap"}, {"_id": 0})
    if config_data["LDAP"]:
        server = Server(ldap_server["url"], get_info=ALL)
        ldap = Connection(
            server,
            user=ldap_server["value"]["default_user_dn"],
            password=ldap_server["value"]["default_password"],
        )
        ldapState = ldap.bind()
        # print(ldapState)
    config = dict()
    config["HOST"] = ldap_server["url"]
    config["BASE_DN"] = ldap_server["value"]["base_dn"]
    config["USER_DN"] = ldap_server["value"]["user_dn"]
    config["GROUP_DN"] = ldap_server["value"]["group_dn"]
    config["ROLE_MGR"] = ldap_server["value"]["profil_role_mgr"]
    config["TECHNICAL_MGR"] = ldap_server["value"]["technical_profil_mgr"]
    config["ROLE_VIEWER"] = ldap_server["value"]["profil_role_viewer"]
    config["TECHNICAL_VIEWER"] = ldap_server["value"]["technical_profil_viewer"]
    config["LDAP_HOST"] = ldap_server["url"]
    config["LDAP_BASE_DN"] = ldap_server["value"]["base_dn"]
    config["LDAP_USER_DN"] = ldap_server["value"]["user_dn"]
    config["LDAP_GROUP_DN"] = ldap_server["value"]["group_dn"]

    readonly_group = ldap_server["value"]["readonly"]
    readonly_group = ldap_server["value"]["readonly"]
    well_well = True
    # ---new-----
except:
    print(traceback.format_exc())
    print("Database not initiated")
    print("Initiating database..")
    if active_cluster_mode:
        if is_primary():
            initEnv(config_data, db002)
        else:
            print("waiting for data to be replicated")
            time.sleep(5)
    else:
        initEnv(config_data, db002)
finally:
    creds = db002["creds"]
    fileserver = creds.find_one({"type": "File_Server"})
    file_server_url = fileserver["ip"]
    password_expiration = 90
    credsData = creds.find({"type": "token_secret"})[0]
    salt = credsData["salt"]
    tokens = db002["tokens"]
    index_name = "token_ttl_index"
    index_name2 = "temp_password_ttl_index"
    index_info = db002["tokens"].index_information()
    index_info_tp = db002["temp_password"].index_information()
    expire_after_seconds = 24 * 60 * 60  # 24 hours
    expire_after_seconds_tp = 60 * 10  # 10 minutes
    if index_name not in index_info:
        if active_cluster_mode:
            if is_primary():
                db002["tokens"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds,
                    name=index_name,
                )
        else:
            db002["tokens"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds,
                    name=index_name,
                )
    if index_name2 not in index_info_tp:
        if active_cluster_mode:
            if is_primary():
                db002["temp_password"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds_tp,
                    name=index_name2,
                )
        else:
            db002["temp_password"].create_index(
                    [
                        ("expireAt", 1)
                    ],  # the field that holds the expiry date et aussi voit la partie ou je crée le toekn je précise un paramètre je crois
                    expireAfterSeconds=expire_after_seconds_tp,
                    name=index_name2,
                )
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    validated_status = True
    logs = db002["logs"]
    logs_code = db002["logs_code"]
    users = db002["users"]
    safes = db002["safe"]
    secrets = db002["secrets"]
    shares = db002["shares"]
    tokSecret = creds.find_one({"type": "token_secret"})
    airflow = creds.find_one({"type": "airflow"}, {"_id": 0})
    dagInfo = airflow["dagInfo"]
    # ---new-----
    ldap_server = creds.find_one({"type": "ldap"}, {"_id": 0})
    if config_data["LDAP"]:
        server = Server(ldap_server["url"], get_info=ALL)
        ldap = Connection(
            server,
            user=ldap_server["value"]["default_user_dn"],
            password=ldap_server["value"]["default_password"],
        )
        ldapState = ldap.bind()
    # print(ldapState)
    config = dict()
    config["HOST"] = ldap_server["url"]
    config["BASE_DN"] = ldap_server["value"]["base_dn"]
    config["USER_DN"] = ldap_server["value"]["user_dn"]
    config["GROUP_DN"] = ldap_server["value"]["group_dn"]
    config["ROLE_MGR"] = ldap_server["value"]["profil_role_mgr"]
    config["TECHNICAL_MGR"] = ldap_server["value"]["technical_profil_mgr"]
    config["ROLE_VIEWER"] = ldap_server["value"]["profil_role_viewer"]
    config["TECHNICAL_VIEWER"] = ldap_server["value"]["technical_profil_viewer"]
    config["LDAP_HOST"] = ldap_server["url"]
    config["LDAP_BASE_DN"] = ldap_server["value"]["base_dn"]
    config["LDAP_USER_DN"] = ldap_server["value"]["user_dn"]
    config["LDAP_GROUP_DN"] = ldap_server["value"]["group_dn"]

    readonly_group = ldap_server["value"]["readonly"]
    readonly_group = ldap_server["value"]["readonly"]
    well_well = True
    # ---new-----

if db002["applications-v2"].find_one({"app_id": "66311b2cb8c9514d72a470cb"}) is None:
# db002["applications-v2"].delete_one({"app_id": "66311b2cb8c9514d72a470cb"})
    time.sleep(5)
    db002["applications-v2"].insert_one({
    "app_id": "66311b2cb8c9514d72a470cb",
    "app_type": "ssh",
    "app_name": "ssh",
    "app_fields": {
        "hostname": True,
        "username": True,
        "password": True
    },
    "creation_date": {
        "$date": "2024-04-30T18:24:12.187Z"
    },
    "app_icon_path": None
    })
# app_id = fields.Str(dump_only=True)
# app_name = fields.Str(required=True)
# app_type = fields.Str(required=True)
# app_icon_path = fields.Str(required=False)
# app_fields = fields.Dict(required=True, validate=validate.Length(min=1))
# creation_date = fields.Date(dump_only=True)

if not ldapState and config_data["LDAP"]:
    print("ldap connexion failed")
    sys.exit(1)
else:
    if config_data["LDAP"]:
        print("successfully connected to the ldap server ..")
FA2 = db002["2FA"]
# with open("./credfile/credfil.json", 'r') as f:
#     credfile = f.read()
# f.close()
FA2info = db002["info2FA"]
# credfile = json.loads(credfile)
tasks = db002["tasks"]
index_name = "secret_ttl_index"
index_info = db002["secrets"].index_information()
expire_after_seconds = 24 * 60 * 60  # 24 hours
if index_name not in index_info:
    if active_cluster_mode:
        if is_primary():
            secrets.create_index(
                [("exp_time", 1)],  # the field that holds the expiry date
                expireAfterSeconds=expire_after_seconds,
                name=index_name,
            )
    else:
        secrets.create_index(
                [("exp_time", 1)],  # the field that holds the expiry date
                expireAfterSeconds=expire_after_seconds,
                name=index_name,
            )


fapp = db002.applications.find_one({"owner_uid" : "SYSTEM", "type": "ssh", "name": "ssh"})
if fapp is None:
    db002.applications.insert_one(
        {
            "app_id": str(ObjectId()),
            "owner_uid": "SYSTEM",
            "app_type": "ssh",
            "type": "ssh",
            "name": "ssh",
            "fields": {
                "username": True,
                "hostname": True,
                "password": True
            },
            "date": datetime.now().strftime("%d-%b-%Y %H-%M-%S"),
            "icon_path": "static/app_icons/ssh_picture.jpg"
        }
    )
def ldap_connexion():
    ldap = Connection(
        server,
        user=ldap_server["value"]["default_user_dn"],
        password=ldap_server["value"]["default_password"],
    )
    ldapState = ldap.bind()
    if ldapState:
        return True, ldap
    else:
        return False, None

try:
    del args["config"]
    del args["update_last_stable"]
    del args["update_last_dev"]
except:
    pass
# print("loader")
# ecptk = loader(args, AZUMARIL_KEYS is not None)


class Validator:
    def __init__(json_cred):
        mail = json_cred["email"]

    def validate_email(self):
        if re.fullmatch(regex, self.email):
            validated_status = False
            print(self.mail)
            return "{} : Invalid email".format(self.mail)

    def get_status(self):
        return validated_status


def get_userid_by_token():
    auth_token = request.headers.get("Authorization")
    if auth_token is not None:
        auth_token = auth_token.split()[1]
        tokens = db002["tokens"]
        try:
            userid = db002["tokens"].find_one({"token": auth_token})["user_uid"]
            return userid
        except:
            return None
    else:
        return None


def get_uid_by_token():
    auth_token = request.headers.get("Authorization")
    if auth_token is not None:
        auth_token = auth_token.split()[1]
        tokens = db002["tokens"]
        try:
            userid = db002["tokens"].find_one({"token": auth_token})["user_uid"]
            fuser = db002.users.find_one({"uid": {"$regex": f"^{userid}$", "$options": "i"}})
            return fuser["uid"]
        except:
            return None
    else:
        return None


class Logs:
    def createLog(self, log_type, message, logModule, logFunction, logCode):
        userid = get_userid_by_token()
        date = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        ipaddr = request.remote_addr
        logs.insert_one(
            {
                "type": log_type,
                "message": message,
                "date": date,
                "logModule": logModule,
                "logFunction": logFunction,
                "logCode": logCode,
                "userid": userid,
                "ip_adress": ipaddr,
            }
        )
        user = users.find_one({"uid": userid})
        logMode = user["log_mode"] if user is not None else None
        return userid, date, logMode, ipaddr

    def warning(self, message, logModule, logFunction):
        logCode = logs_code.find_one(
            {"type": "warning", "module": logModule, "function": logFunction}
        )
        log = self.createLog(
            "warning", message, logModule, logFunction, logCode["code"]
        )
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["warning"]:
            print(
                "\033[93m"
                + f"{ipaddr} - - [{date}] - DEBUG : {message} in /{logModule}/{logFunction} user : {userid}"
                + "\033[0m"
            )

    def debug(self, message, logModule, logFunction):
        logCode = logs_code.find_one(
            {"type": "debug", "module": logModule, "function": logFunction}
        )
        log = self.createLog("debug", message, logModule, logFunction, logCode["code"])
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["debug"]:
            print(
                f"{ipaddr} - - [{date}] - DEBUG : {message} in /{logModule}/{logFunction} user : {userid}"
            )

    def error(self, message, logModule, logFunction):
        logCode = logs_code.find_one(
            {"type": "error", "module": logModule, "function": logFunction}
        )
        log = self.createLog("error", message, logModule, logFunction, logCode["code"])
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["error"]:
            print(
                "\033[0;31m"
                + f"{ipaddr} - - [{date}] - ERROR : {message} in /{logModule}/{logFunction} user : {userid}"
                + "\033[0m"
            )

    def success(self, message, logModule, logFunction):
        logCode = logs_code.find_one(
            {"type": "success", "module": logModule, "function": logFunction}
        )
        log = self.createLog(
            "success", message, logModule, logFunction, logCode["code"]
        )
        userid = log[0]
        date = log[1]
        ipaddr = log[3]
        if log[2] is not None and log[2]["success"]:
            print(
                "\033[0;32m"
                + f"[{date}] - - {ipaddr} - SUCCESS : {message} in /{logModule}/{logFunction} user : {userid}"
                + "\033[0m"
            )


def encode_token(token_type, user_uid, data, exp_days, payload_data=None, oidc=False):
    token = db002["tokens"]
    tokenTmp = {
        "token": "xxxxxxxxxxxxxxxxxxxxxx",
        "user_uid": "",
        "creation_date": "",
        "expiration_date": "",
        "is_expired": "true",
    }
    try:
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(hours=exp_days * 24)
        payload = {
            "exp": expiration_date_time,
            "iat": datetime.utcnow(),
            "sub": user_uid,
        }
        if payload_data is not None:
            payload.update(payload_data)
        encodejwt = jwt.encode(payload, salt, algorithm="HS256")
        # print(encodejwt)
        if isinstance(encodejwt, bytes):
            encodejwt = encodejwt.decode("utf-8")
        tokenTmp["type"] = token_type
        tokenTmp["token"] = encodejwt
        tokenTmp["user_uid"] = user_uid
        expiry_date = datetime.utcnow() + timedelta(hours=24)
        tokenTmp["expireAt"] = expiry_date
        tokenTmp["creation_date"] = creation_date_time
        tokenTmp["expiration_date"] = expiration_date_time
        tokenTmp["is_expired"] = "false"
        tokenTmp.update(data)
        if not oidc:
            token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        return e


def encode_auth_token(user_uid):
    """
    Generates the Auth Token
    :return: string
    """
    token = db002["tokens"]
    tokenTmp = {
        "token": "xxxxxxxxxxxxxxxxxxxxxx",
        "user_uid": "",
        "creation_date": "",
        "expiration_date": "",
        "is_expired": "true",
    }
    try:
        creation_date_time = datetime.utcnow()
        if DEBUG == "true":
            print("type of the")
            print(type(tokSecret["time"]["task_token"]))
        expiration_date_time = creation_date_time + timedelta(
            hours=int(tokSecret["time"]["task_token"]) * 24
        )
        payload = {"exp": expiration_date_time, "iat": datetime.now(), "sub": user_uid}
        encodejwt = jwt.encode(payload, salt, algorithm="HS256")
        # print(encodejwt)
        if isinstance(encodejwt, bytes):
            encodejwt = encodejwt.decode("utf-8")
        tokenTmp["type"] = "auth_token"
        tokenTmp["token"] = encodejwt
        tokenTmp["user_uid"] = user_uid
        expiry_date = datetime.now() + timedelta(hours=24)
        tokenTmp["expireAt"] = expiry_date
        tokenTmp["creation_date"] = creation_date_time
        tokenTmp["expiration_date"] = expiration_date_time
        tokenTmp["is_expired"] = "false"
        token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        print(traceback.format_exc())
        return e

def encode_permission_token(giver_uid, receiver_uid, exp_date = 24):
    """
    Generates the Auth Token
    :return: string
    """
    token = db002["tokens"]
    tokenTmp = {
        "token": "xxxxxxxxxxxxxxxxxxxxxx",
        "user_uid": "",
        "creation_date": "",
        "expiration_date": "",
        "is_expired": "true",
    }
    try:
        creation_date_time = datetime.utcnow()
        if DEBUG == "true":
            print("type of the")
            print(type(tokSecret["time"]["task_token"]))
        expiration_date_time = creation_date_time + timedelta(
            hours=int(tokSecret["time"]["task_token"]) * exp_date
        )
        payload = {"exp": expiration_date_time, "iat": datetime.now(), "sub": giver_uid, "giver_uid": giver_uid, "receiver_uid" : receiver_uid}
        encodejwt = jwt.encode(payload, salt, algorithm="HS256")
        # print(encodejwt)
        if isinstance(encodejwt, bytes):
            encodejwt = encodejwt.decode("utf-8")
        tokenTmp["type"] = "auth_token"
        tokenTmp["token"] = encodejwt
        tokenTmp["user_uid"] = giver_uid
        tokenTmp["giver_uid"] = giver_uid
        tokenTmp["receiver_uid"] = receiver_uid
        expiry_date = datetime.now() + timedelta(hours=exp_date)
        tokenTmp["expireAt"] = expiry_date
        tokenTmp["creation_date"] = creation_date_time
        tokenTmp["expiration_date"] = expiration_date_time
        tokenTmp["is_expired"] = "false"
        token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        print(traceback.format_exc())
        return e


# NOTE -
# -----this is for debug purpose and should be removed------
def encode_auth_token2(user_uid):
    """
    Generates the Auth Token
    :return: string
    """
    client = pymongo.MongoClient("mongodb://itnet:altara01@192.168.7.182:27017")
    dborg = client["Organigramme"]
    token = dborg["tokens"]
    tokenTmp = {
        "token": "xxxxxxxxxxxxxxxxxxxxxx",
        "user_uid": "",
        "creation_date": "",
        "expiration_date": "",
        "is_expired": "true",
    }
    try:
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(
            hours=int(tokSecret["time"]["task_token"]) * 24
        )
        payload = {
            "exp": expiration_date_time,
            "iat": datetime.utcnow(),
            "sub": user_uid,
        }
        encodejwt = jwt.encode(payload, salt, algorithm="HS256")
        # print(encodejwt)
        if isinstance(encodejwt, bytes):
            encodejwt = encodejwt.decode("utf-8")
        tokenTmp["type"] = "auth_token"
        tokenTmp["token"] = encodejwt
        tokenTmp["user_uid"] = user_uid
        expiry_date = datetime.utcnow() + timedelta(hours=24)
        tokenTmp["expireAt"] = expiry_date
        tokenTmp["creation_date"] = creation_date_time
        tokenTmp["expiration_date"] = expiration_date_time
        tokenTmp["is_expired"] = "false"
        token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        return e


# ----------------------------------------------------------


def encode_acess_token(uid):
    """
    Generates the access Token
    :return: string
    """
    tokenTmp = {
        "token": "xxxxxxxxxxxxxxxxxxxxxx",
        "userid": "",
        "creation_date": "",
        "expiration_date": "",
        "is_expired": "true",
    }
    try:
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(hours=24)
        payload = {
            "exp": expiration_date_time,
            "iat": datetime.utcnow(),
            "user_id": uid,
        }
        encodejwt = jwt.encode(payload, salt, algorithm="HS256").decode("utf8")
        tokenTmp["token"] = encodejwt
        tokenTmp["userid"] = uid
        tokenTmp["creation_date"] = creation_date_time
        tokenTmp["expiration_date"] = expiration_date_time
        tokenTmp["is_expired"] = "false"
        db002["tokens"].insert_one(tokenTmp)
        return tokenTmp["token"]
    except Exception as e:
        return e


def decode_token_(auth_token, all=False):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, salt, algorithm="HS256")
        if not all:
            return payload["sub"]
        return payload
    except jwt.ExpiredSignatureError:
        return "Signature expired. Please log in again."
    except jwt.InvalidTokenError:
        return "Invalid token. Please log in again."


def decode_auth_token(auth_token, full = False):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        try:
            payload = jwt.decode(auth_token, salt, algorithms=["HS256"])
            # print(payload)
            fr = db002["tokens"].find_one({"user_uid": payload["sub"]})
            if fr is None:
                # NOTE -
                # -----this is for debug purpose and should be removed------
                # client = pymongo.MongoClient("mongodb://itnet:altara01@192.168.7.182:27017")
                # dborg = client['Organigramme']
                # token= dborg["tokens"]
                # fr = token.find_one({"user_uid":payload['sub']})
                # if fr is None:
                return "Invalid token. Please log in again."
                # ----------------------------------------------------------
                # return 'Invalid token. Please log in again.'
            if not full:
                return payload["sub"]
            else:
                return payload
        except:
            print(traceback.format_exc())
            return "Invalid token. Please log in again."

    except jwt.ExpiredSignatureError:
        return "Signature expired. Please log in again."
    except jwt.InvalidTokenError:
        return "Invalid token. Please log in again."


class ResponseJson:
    def invalid_input(self, error):
        return False, (jsonify({"status": "Failed", "message": error}), 400)

    def requestValidate(self, required_keys=[], allowNullData=False):
        paramin = False
        data = None
        try:
            data = request.get_json(force=True)
            paramin = True
        except:
            if not allowNullData:
                return self.invalid_input("Missing parameters")

        for key in required_keys:
            if not isErrorKey(data, key):
                return self.invalid_input(
                    f"{key} is required in the request body parameters"
                )
        if paramin:
            for key, value in data.items():  # check values and keys of the array
                if not allowNullData:  # do this if None value not allowed
                    if value == None:
                        return self.invalid_input(key + " is required")
                    if not value:
                        return self.invalid_input(key + " is required")
                else:  # else do that
                    pass
        return True, data

    def success(self, data):
        return jsonify({"data": data, "status": "success"})

    def IndexError(self, message):
        return jsonify({"message": message, "status": "failed"}), 401

    def TypeError(self, message):
        return jsonify({"message": message, "status": "failed"}), 400

    def DuplicateKeyError(self, message):
        return jsonify({"message": message, "status": "failed"}), 409

    def e404(self, message):
        return jsonify({"message": message, "status": "failed"}), 404


resJson = ResponseJson()


def tokenValidation(token_type = "auth_token"):
    auth_token = request.headers.get("Authorization")
    if auth_token is not None:
        auth_token = auth_token.split()[1]
        auth_token = auth_token.strip()
        query = {"type": "auth_token", "token": "" + auth_token + ""}
        fouundToken = db002["tokens"].find_one(query)

        if fouundToken is None:
            return {"status": False, "message": "Token not found Please login again"}
        #     #NOTE -
        #     #-----this is for debug purpose and should be removed------
        #     client = pymongo.MongoClient("mongodb://itnet:altara01@192.168.7.182:27017")
        #     dborg = client['Organigramme']
        #     token= dborg["tokens"]
        #     fouundToken = token.find_one({"type" : "auth_token    ", "token" : auth_token})
        #     print("fouundToken ", fouundToken)
        #     if fouundToken is None:
        #         return {"status":False, "message": "The token is not an authentication token, please login again"}
        # ----------------------------------------------------------
        # return {"status":False, "message": "The token is not an authentication token, please login again"}
        try:
            token_validation_message = decode_auth_token(auth_token)
            signature_expired = (
                token_validation_message == "Signature expired. Please log in again."
            )
            invalid_token = (
                token_validation_message == "Invalid token. Please log in again."
            )
            if signature_expired or invalid_token:
                return {"status": False, "message": token_validation_message}
        except:
            return {"status": False, "message": token_validation_message}
        return {"status": True, "message": token_validation_message}
    else:
        return {"status": False, "message": "missing token"}


def validation(required_keys=[], allowNullData=False, token_type = "auth_token"):
    validate = tokenValidation(token_type)
    if validate["status"]:
        validated = resJson.requestValidate(required_keys, allowNullData)
        return validated
    else:
        return False, (
            jsonify({"message": validate["message"], "status": "failed"}),
            401,
        )

def replicate_shamir_data():
    pass

def seal_validator(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        gas = get_app_state()
        print(gas)
        if gas["seal"]:
            return jsonify({"status": False, "message": "app sealed"}), 403
        return f(*args, **kwargs)

    return decorator

def leader_validator(f):
    global SYNC_OBJ
    @wraps(f)
    def decorator(*args, **kwargs):
        if not active_cluster_mode:
            return f(*args, **kwargs)
        print("Leader request middleware")
        # not_leader_access = not (request.method == "POST" or request.method == "PUT" or request.method == "DELETE")
        res = requests.get(f"https://localhost:{initapp_port}/raft-info", verify = False)
        raft_info = res.json()
        leader = raft_info["is_leader"]
        if not leader:
            print("Trying to execute a leader request to a follower server")
            leader_base_url = f"https://{raft_info['la'].split(':')[0]}:{config_data['API_PORT']}"
            current_endpoint = request.endpoint
            endpoint = f"{url_for(current_endpoint)}"
            url = leader_base_url + endpoint
            print("request is being redirected to the cluster leader..")
            print(url)
            payload = None
                    
            # Get all the query parameters
            args = request.args
            if args:
                url += "?"
                for k, v in args.items():
                    url += f"{k}={v}&"
                url = url[:-1]
            if request.content_type == "application/json":
                # Get JSON data
                data = request.get_json()
                if data:
                    payload = data

                response = requests.request(
                    request.method,
                    url,
                    json=payload,
                    headers=request.headers,
                    verify = False
                )
            else:
                headersList = {
                    "Accept": "*/*",
                    "Authorization": request.headers.get("Authorization")
                }

                if request.method == "POST":
                    response = requests.post(url, data = dict(request.form), files = request.files, headers = headersList, verify = False)
                if request.method == "PUT":
                    response = requests.put(url, data = dict(request.form), files = request.files, headers = request.headers, verify = False)
            # response = redirect(url, code=307)
            # response.headers = request.headers
            return response.json()
        print("Node is leader so executing the request")
        return f(*args, **kwargs)

    return decorator

def jwt_validation(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        validated = validation(allowNullData = True)
        if not validated[0]:
            return validated[1]
        user = validated[1]
        return f(*args, **kwargs)
    return decorator

def impersonate_middleware(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        data = get_impersonate_info_by_token()
        if data is None:
            return jsonify({
                "status" : "failed",
                "message" : "failed to access this acount"
            }), 403
        # print(data)
        if "giver_uid" not in data:
            return f(*args, **kwargs)
        current_endpoint = request.endpoint
        request_method = request.method
        access = True
        receiver_info = None
        access, exp_date, receiver_info, rigths = check_user_permissions(data["giver_uid"], data["receiver_uid"])

        if access:
            methode = request_method == "POST" or request_method == "PUT" or request_method == "DELETE"
            if methode and rigths['write'] == False:
                return jsonify({"status" : "failed", "message" : "Insufficient access rights, you have no write permission"}), 403
            history_data = {
                "id" : str(ObjectId()),
                "giver_uid": data["giver_uid"],
                "receiver_uid": data["receiver_uid"],
                "receiver_info" : receiver_info,
                "endpoint" : current_endpoint,
                "request_json" : request.get_json(),
                "request_query" : request.args,
                "request_method" : request_method,
                "date":datetime.utcnow()
            }
            db002.impersonate_history.insert_one(history_data)
            history_data['_id'] = str(history_data['_id'])
            return f(*args, **kwargs)
        else:
            return jsonify({
                "status" : "failed",
                "message" : "failed to access this acount"
            }), 403
    return decorator

def get_impersonate_info_by_token():
    auth_token = request.headers.get("Authorization")
    if auth_token is None:
        return None
    auth_token = auth_token.split()[1]
    auth_token = auth_token.strip()
    payload = decode_auth_token(auth_token, full = True)
    return payload

# from datetime import datetime

def check_user_permissions(giver_uid, user_uid):
    user_data = users.find_one({"uid" : giver_uid})
    giver_email = user_data["email"]
    user_data = users.find_one({"uid" : user_uid})
    user_email = user_data["email"]
    users_collection = db002["permission_management"]
    giver = users_collection.find_one({"email": giver_email})
    if not giver:
        return False, 0, None, None
    
    permission = next((perm for perm in giver.get('access_list_given', []) if perm['receiver_email'] == user_email), None)
    if not permission:
        return False, 0, None, None
    
    access = permission['permissions']['read'] or permission['permissions']['write']
    
    expiration_date = permission['expiration_date']
    current_time = datetime.utcnow()
    exp_date = max(0, int((expiration_date - current_time).total_seconds() / 3600))
    
    receiver_info = {
        "email": user_email,
        "permissions": permission['permissions']
    }
    rights = permission['permissions']

    return access, exp_date, receiver_info, rights



def admin_middleware(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        validated = validation(allowNullData = True)
        if not validated[0]:
            return validated[1]
        user = validated[1]
        uid = get_uid_by_token()
        if isAdmin(uid):
            return f(*args, **kwargs)
        else:
            return jsonify({
                "status" : "failed",
                "message" : "not allowed"
            }), 403
    return decorator

def license_validation(feature):
    def decorator_factory(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            if LICENSE_INFO is None:
                return jsonify({
                    "status" : "failed",
                    "message" : "This premium feature is not allowed in the current version, please add a valid license to unlock it",
                }), 403
            if LICENSE_INFO["features"][feature] and not is_date_expired(LICENSE_INFO["expiration_date"]):
                return f(*args, **kwargs)
            else:
                return jsonify({
                    "status" : "failed",
                    "message" : "This premium feature is not allowed in the current version, please add a valid license to unlock it",
                }), 403
        return decorator
    return decorator_factory

def store_captcha(text, ip):
    index_name = "captcha_ttl_index"
    index_info = db002["captcha"].index_information()
    expire_after_seconds = 5 * 60  # 5mins
    if index_name not in index_info:
        db002["captcha"].create_index(
            [("expireAt", 1)],  # the field that holds the expiry date
            expireAfterSeconds=expire_after_seconds,
            name=index_name,
        )
    db002.captcha.delete_many({"ip" : ip})
    expiry_date = datetime.utcnow() + timedelta(minutes=5)
    db002.captcha.insert_one({"ip" : ip, "text" : text, "expireAt" : expiry_date})

def verify_captcha(text, ip):
    r = db002.captcha.find_one({"ip" : ip, "text" : text}) is not None
    print(f"verified captcha is : {r}")
    return r

def captcha_validation(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        req = request.get_json(force = True)
        captcha_input = req.get("captcha_input", None)
        if captcha_input is None:
            return jsonify({"message": "CAPTCHA is required", "status": "failed"}), 400
        cached = False
        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            user_ip = request.environ['REMOTE_ADDR']
        else:
            user_ip = request.environ['HTTP_X_FORWARDED_FOR'] # if behind a proxy
        print(user_ip)
        cached = captcha_input == cache.get(user_ip)
        print(f"cache is {cache.get(user_ip)}")
        if captcha_input == session.get('captcha_text') or cached or verify_captcha(captcha_input, user_ip):
            return f(*args, **kwargs)
        else:
            return jsonify({"message": "CAPTCHA is not correct try again", "status": "failed"}), 400
    return decorator

def handleRequestToGetUserUid():
    """
    This function get Bearer token from request and find the uid of the user
    """
    validate = tokenValidation()
    if validate["status"]:
        return True, validate["message"]
    else:
        return False, (
            jsonify({"message": validate["message"], "status": "failed"}),
            401,
        )


def airflow_to_send_mail(taskid):
    endPoint = creds.find_one({"type": "airflow"})
    URL = endPoint["url"] + f"/api/v1/dags/{dagInfo['send_mail']}/dagRuns"
    try:
        me = creds.find_one({"type": "altara_airflow_prod"})
        data = (
            '{"conf": {"taskid":"'
            + taskid
            + '"}, "dag_run_id": "'
            + "airflow_"
            + taskid
            + str(random.random())
            + '" }'
        )
        headers = {"Content-Type": "application/json", "accept": "application/json"}
        results = requests.post(
            URL, data, auth=(me["username"], me["password"]), headers=headers
        )
        if results.status_code == 200:
            return "ok", 200
        else:
            return "something went wrong", results.status_code
    except Exception as err:
        return err


def mail_sender(receiver, subject, message):
    """
    Generates the Auth Token
    :return: string
    """
    msg = MIMEMultipart()
    msg["From"] = config_data["SMTP_FROM"]
    msg["To"] = receiver
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "html"))
    text = msg.as_string()
    try:
        smtp = smtplib.SMTP(config_data["SMTP_HOST"], config_data["SMTP_PORT"])
        if config_data["SMTP_TLS"]:
            smtp.starttls()
            smtp.login(config_data["SMTP_USERNAME"], config_data["SMTP_PASSWORD"])
        smtp.sendmail(config_data["SMTP_USERNAME"], receiver, text)

        # Terminating the session
        smtp.quit()
        print("Email sent successfully!")
    except Exception as ex:
        print("Something went wrong....", ex)

def generate_code():
    numStr = ""
    for i in range(1, 7):
        numStr += str(random.randint(0, 9))
    return numStr


# ---new---
def getUserGroup(user_dn, uid=""):
    try:
        search_dn2 = config["GROUP_DN"] + "," + config["BASE_DN"]
        ldap = ldap_connexion()[1]
        ldap.search(search_dn2, f"(|(member={user_dn})(memberUid={uid}))")
        # member = config_data["LDAP_USER_ATTRIBUTES"]["groupIditenfier"]
        groups = []
        for entry in ldap.entries:
            group = ast.literal_eval(entry.entry_to_json())
            groups.append(group["dn"].split(",")[0].split("=")[1])
        ldap.unbind()
        return groups
    except:
        return ["readonly"]

def getUserDn(uid):
    DN = "uid=" + uid + "," + config["USER_DN"] + "," + config["BASE_DN"]
    return DN


def has_role(role_to_check, scope):
    user_uid = get_userid_by_token()
    # user_dn = getUserDn(user_uid)
    user_dn = search_user_info(user_uid)
    user_roles = getUserGroup(user_dn, user_uid)
    AUTHORIZED = False
    for role in role_to_check:
        is_dedans = role in user_roles
        if scope == "all":
            if not is_dedans:
                return is_dedans
            else:
                AUTHORIZED = is_dedans
        if scope == "one":
            if is_dedans:
                AUTHORIZED = is_dedans
                return is_dedans
    return AUTHORIZED


# ---new---
def generate_captcha(text):
   captcha = ImageCaptcha()
   image = captcha.generate_image(text)
   buffer = io.BytesIO()
   image.save(buffer, format='PNG')
   buffer.seek(0)
#    encoded_string = base64.b64encode(buffer.getvalue()).decode('utf-8')
#    return encoded_string
   return buffer

def generate_random_text():
    return ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(6))


def auth2FA(auth_type, code=None, email=None):
    FA2 = db002["2FA"]
    if auth_type == "get":
        fa2Info = FA2.find_one({"code": code, "email": email})
        if fa2Info is None:
            return False, (
                jsonify(
                    {
                        "message": "Double authentication code is incorrect",
                        "status": "failed",
                    }
                ),
                400,
            )
        else:
            data = dict(fa2Info)
            if data["exp_date"] < datetime.utcnow():
                return False, (
                    jsonify(
                        {
                            "message": "Double authentication code is exipred",
                            "status": "failed",
                        }
                    ),
                    400,
                )
            return True, 200

    if auth_type == "post":
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(minutes=5)
        fa2Info = FA2.insert_one(
            {"code": code, "email": email, "exp_date": expiration_date_time}
        )


def passwdKey(password):
    hashalgo = "sha256"
    salt = "dsfsf!dAs"
    return (
        hashalgo
        + "{"
        + hashlib.pbkdf2_hmac(
            hashalgo,
            bytes(password.encode("utf-8")),
            bytes(salt.encode("utf-8")),
            100000,
        ).hex()
        + "}"
    )


# def policy(password):
#     pwd = db002["pwd_policy"]
#     pwd_details = pwd.find_one({"name":"policy_details"})
#     strength = pwd_details["strength"]
#     strength_details = strength.split(",")
#     for i in strength_details:
#         if not re.search(i, password):
#             return False
#     return True if (len(password) > pwd_details["length"]) else False


def policy(password):
    policy_password = PasswordPolicy.from_names(
        length=8,  # min length: 8
        uppercase=1,  # need min. 2 uppercase letters
        numbers=1,  # need min. 2 digits
        special=1,  # need min. 2 special characters
        # nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
    )
    result = policy_password.test(password)
    if len(result) == 0:
        return True, result
    return False, result


def validMail(email):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if re.search("^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$", email):
        return True
    else:
        if re.fullmatch(regex, email):
            return True
        return False


def change_pass_after_time(app_id):
    ACCOUNT = db002["account"]
    result = ACCOUNT.find({"app_id": app_id, "is_expired": False})
    if result:
        for i in result:
            creation_date_time = i["date"]
            today_date_time = datetime.now()
            if today_date_time > creation_date_time + timedelta(
                days=password_expiration
            ):
                ACCOUNT.find_one_and_update(
                    {"_id": i["_id"]}, {"$set": {"is_expired": True}}, upsert=True
                )
    return None


def run_dag(taskid):
    try:
        me = creds.find_one({"type": "airflow"})
        URL = me["url"] + f"/api/v1/dags/{dagInfo['launch_dag']}/dagRuns"
        data = (
            '{"conf": {"taskid":"'
            + taskid
            + '"}, "dag_run_id": "'
            + "airflow_"
            + taskid
            + str(random.random())
            + '" }'
        )
        headers = {"Content-Type": "application/json", "accept": "application/json"}
        results = requests.post(
            URL,
            data,
            auth=(me["value"]["username"], me["value"]["password"]),
            headers=headers,
        )
        if results.status_code == 200:
            return "ok", 200
        else:
            return "something went wrong", results.status_code
    except Exception as err:
        return err


def fetchSons(mo, unsorted):
    for obj in unsorted:
        if obj["info"]["managerID"] == mo["info"]["uid"]:
            mo["fils"].append(obj)
            fetchSons(obj, unsorted)


def isErrorKey(data, key):
    try:
        data[key]
        return True
    except KeyError:
        return False


def upload_file(
    path_to_upload,
    file,
    atype="file",
    is_certificate="no",
    certificate_path="a",
    upload_type="simple",
):
    try:
        dataToSend = {"path": path_to_upload, "atype": atype}
        response = requests.post(
            file_server_url,
            # json = dataToSend,
            headers={
                "path": path_to_upload,
                "atype": atype,
                "application": "azumaril",
                "upload_type": upload_type,
                "is_certificate": is_certificate,
                "certificate_path": certificate_path,
            },
            files={"form_field_name": file},
        )
        # print(response.status_code)
        return True
    except:
        # print(traceback.format_exc())
        return False


def secret_access(secret_id, owner_uid):
    secret = secrets.find_one({"secret_id": secret_id, "owner_uid": owner_uid})
    rights = {
        "read": True,
        "write": True,
        "share": True,
        "propagate": True,
        "delete": True,
        "all": False,
        "owner": True,
    }
    if secret is None:
        owner = users.find_one({"uid": owner_uid}, {"_id": 0, "email": 1})
        # NOTE est-ce que le même secret peut être partager deux fois a la même personne?
        # ne faut il pas simplement mettre à jour le précédent partage?
        found_share = shares.find_one(
            {
                "secret_ids": {"$all": [secret_id]},
                "users_mails": {"$all": [owner["email"]]},
            }
        )
        if found_share is not None:
            attempts = None
            if "attempts" in found_share:
                attempts = found_share["attempts_info"]

            secret = secrets.find_one({"secret_id": secret_id}, {"_id": 0})
            rights["owner"] = False
            for k, v in rights.items():
                try:
                    if not (k in ["owner", "all"]):
                        found_share["rights"][k]
                        rights[k] = found_share["rights"][k]
                except:
                    rights[k] = False
            # rights["read"] = found_share["rights"]["read"]
            # rights["write"] = found_share["rights"]["write"]
            # rights["share"] = found_share["rights"]["share"]
            # rights["propagate"] = found_share["rights"]["propagate"]
            # rights["delete"] = found_share["rights"]["delete"]
            if (
                rights["read"]
                and rights["write"]
                and rights["share"]
                and rights["delete"]
                and rights["propagate"]
            ):
                rights["all"] = True
            return (
                True,
                secret,
                rights,
                found_share["share_ids"],
                attempts,
                found_share["share_id"],
            )
        else:
            return False, None, rights
    return True, secret, rights


def safe_access(safe_id, owner_uid):
    safe = safes.find_one({"safe_id": safe_id, "owner_uid": owner_uid})
    rights = {
        "read": True,
        "write": True,
        "share": True,
        "propagate": True,
        "delete": True,
        "all": False,
        "owner": True,
    }
    if safe is None:
        owner = users.find_one({"uid": owner_uid}, {"_id": 0, "email": 1})
        found_share = shares.find_one(
            {"safe_ids": {"$all": [safe_id]}, "users_mails": {"$all": [owner["email"]]}}
        )
        if found_share is not None:
            safe = safes.find_one({"safe_id": safe_id}, {"_id": 0})
            rights["owner"] = False
            for k, v in rights.items():
                try:
                    if not (k in ["owner", "all"]):
                        found_share["rights"][k]
                        rights[k] = found_share["rights"][k]
                except:
                    rights[k] = False
            # rights["read"] = found_share["rights"]["read"]
            # rights["write"] = found_share["rights"]["write"]
            # rights["share"] = found_share["rights"]["share"]
            # rights["propagate"] = found_share["rights"]["propagate"]
            # rights["delete"] = found_share["rights"]["delete"]
            if (
                rights["read"]
                and rights["write"]
                and rights["share"]
                and rights["delete"]
                and rights["propagate"]
            ):
                rights["all"] = True
            return True, safe, rights, found_share["share_ids"]
        else:
            return False, None, rights
    return True, safe, rights


def parse_json(data):
    return json.loads(json_util.dumps(data))


def delete_safe_util(owner_uid, safe_id):
    try:
        print(f"owner {owner_uid} is deleting {safe_id}")
        # Supprimer les secrets du coffre fort pour tous ceux avec qui ils ont été partagés
        secrets_id = []
        shares_id = []
        # Check s'il y'a des secrets dans le coffre qu'on veut supprimer
        fsecrets = secrets.find({"safe_id": safe_id})
        for s in fsecrets:
            secrets_id.append(s["secret_id"])
        print(secrets_id)
        if len(secrets_id) == 0:
            print("No secrets")
            # Supprimer le coffre de la collection s'il n'y a pas de secrets dedans
            safes.find_one_and_delete({"safe_id": safe_id, "owner_uid": owner_uid})
            return True
        # Mettre les partages contenant des secrets contenus dans le coffre qui va être supprimé dans une liste
        for id in secrets_id:
            fshares = shares.find({"secret_ids": id})
            shares_id.append(fshares)
        # Supprimer tous les partages
        for s in shares_id:
            for ss in s:
                shares.find_one_and_delete({"share_id": ss["share_id"]})
        # Supprimer les secrets
        for id in secrets_id:
            secrets.find_one_and_delete({"secret_id": id})
        # Supprimer le coffre fort
        safes.find_one_and_delete({"safe_id": safe_id, "owner_uid": owner_uid})
        return True
    except:
        print(traceback.format_exc())
        return False


def success_response(status="success", message="", code=200, data=[]):
    return jsonify({"status": status, "message": message, "data": data}), code


def error_response(status="failed", message="", code=400, data=[], errors=[]):
    return (
        jsonify({"status": status, "message": message, "data": data, "errors": errors}),
        code,
    )


#  ------------------- OIDC ----------------------


def generate_authorization_code():
    import secrets as secrets_

    code = secrets_.token_urlsafe(32)
    return code


def randNumber(n):
    range_start = 10 ** (n - 1)
    range_end = (10**n) - 1
    return randint(range_start, range_end)


def getUserDn(uid):
    DN = "uid=" + uid + "," + config_data["LDAP_USER_DN"]
    return DN


def getGroupDn(cn):  # cn=readonly,ou=groups,dc=axetag,dc=com
    DN = "cn=" + cn + "," + config["LDAP_GROUP_DN"] + "," + config["LDAP_BASE_DN"]
    return DN


def get_all_groups():
    ldap = ldap_connexion()[1]
    search_dn = config["LDAP_GROUP_DN"] + "," + config["LDAP_BASE_DN"]
    result = ldap.search(
        search_dn, "(objectClass=*)", search_scope=LEVEL, attributes=["cn"]
    )
    if result:
        roles = []
        for ldent in ldap.entries:
            srj_dict = ast.literal_eval(ldent.entry_to_json())["attributes"]["cn"][0]
            roles.append(srj_dict)
        ldap.unbind()
        return roles
    else:
        ldap.unbind()
        return None


def get_data():
    if not request.get_json():
        return None
    data = request.get_json(force=True)
    return data


def ldap_state():
    data = get_data()
    # server = Server("192.168.1.189:389", get_info=ALL)
    ldap = Connection(server, user=data["uid"], password=data["password"])
    ldapState = ldap.bind()
    return {"state": ldapState, "ldap": ldap}


def get_userInfo(search_dn, uid):
    ldap = ldap_connexion()[1]
    ldap.search(
        search_dn,
        f"(&(objectclass=person)(uid={uid}))",
        attributes=[
            "mail",
            "homeDirectory",
            "sn",
            "uidNumber",
            "manager",
            "cn",
            "gidNumber",
            "loginShell",
            "telephoneNumber",
            "displayName",
            "uid",
            "businessCategory",
        ],
    )
    search_result_json = (
        None if len(ldap.entries) == 0 else ldap.entries[0].entry_to_json()
    )
    ldap.unbind()
    if search_result_json is None:
        return None
    srj_dict = ast.literal_eval(search_result_json)
    try:
        return srj_dict["attributes"]
    except KeyError:
        return None


def updateAttributes(default, req_data):
    uid = req_data["uid"]
    # user_dn = getUserDn(uid)
    user_dn = search_user_info(uid)
    if "password" in req_data and not config_data.get("LDAP_WRITE_RIGHT", False):
        ldap = Connection(
            server, user=user_dn, password=req_data["password"]
        )
        if not ldap.bind():
            return False
    else:
        ldap = ldap_connexion()[1]
    for key, value in req_data.items():
        condition = value == None or value == ""

        if key == "firstname":
            firstname = config_data["LDAP_USER_ATTRIBUTES"]["firstname"]
            default[firstname] = default[firstname] if condition else value
        if key == "lastname":
            lastname = config_data["LDAP_USER_ATTRIBUTES"]["lastname"]
            default[lastname] = default[lastname] if condition else value
        if key == "email":
            email = config_data["LDAP_USER_ATTRIBUTES"]["email"]
            default[email] = default[email] if condition else value
        if key == "tel":
            tel = config_data["LDAP_USER_ATTRIBUTES"]["tel"]
            default[tel] = default[tel] if condition else value
        if key == "loginShell":
            default["loginShell"] = default["loginShell"] if condition else value
        # if key == "managerID":
        #     default["manager"] = default["manager"] if condition else getUserDn(value)

    for key, value in default.items():
        if type(value) == type(""):
            ldap.modify(user_dn, {key: [(MODIFY_REPLACE, [value])]})

    # search_dn = config["LDAP_USER_DN"] + "," + config["LDAP_BASE_DN"]
    # afterMod = get_userInfo(search_dn, uid)
    # afterMod = search_user_info(uid, True)
    # displayName = afterMod["cn"][0] + " " + afterMod["sn"][0]
    # ldap.modify(user_dn, {"displayName": [(MODIFY_REPLACE, [displayName])]})
    ldap.unbind()


def getUsers():
    ldap = ldap_connexion()[1]
    if not ldapState:
        return None
    search_dn = config_data["LDAP_USER_DN"]
    response = ldap.search(
        search_base=search_dn,
        search_filter="(objectClass=person)",
        attributes=["uid", "cn", "sn", "displayName", "manager"],
        dereference_aliases="ALWAYS",
    )
    entry = ldap.entries
    all_users = []
    for user in entry:
        user_data = json.loads(user.entry_to_json())
        if user_data["attributes"]["uid"][0] != "admin":
            info = {
                "cn": user_data["attributes"]["cn"][0],
                "sn": user_data["attributes"]["sn"][0],
                "uid": user_data["attributes"]["uid"][0],
            }
            try:
                if len(user_data["attributes"]["displayName"]) != 0:
                    info["displayName"] = user_data["attributes"]["displayName"][0]
                if len(user_data["attributes"]["manager"]) != 0:
                    info["manager"] = user_data["attributes"]["manager"][0]
            except KeyError:
                pass

            all_users.append(info)
    ldap.unbind()
    if response:
        organigram = []
        no_manager = []
        has_manager = []
        for user in all_users:
            try:
                user["manager"]
                has_manager.append(getFils(user, all_users))
            except KeyError:
                no_manager.append(getFils(user, all_users))
        organigram = [no_manager, has_manager]
        # for nm in no_manager:
        #     for fils in nm["fils"]:
        #         ffs = getFils(fils,all_users)["fils"]
        #         fils["fils"] = ffs
        # return json.dumps({"organigram":organigram}, indent=2)
        return all_users
    else:
        return None


def getFils(user, all_users):
    user_info = {"info": user, "fils": []}  # come back
    for user_fils in all_users:
        try:
            if user_fils["manager"] == getUserDn(user["uid"]):
                user_info["fils"].append(user_fils)
        except KeyError:
            pass
    return user_info


def userChild(uid):
    search_dn = config_data["LDAP_USER_DN"]
    all_users = getUsers()
    if all_users is None:
        return jsonify({"message": "Bad request", "status": "failed"}), 400
    uinfo = get_userInfo(search_dn, uid)
    if uinfo is None:
        return jsonify({"message": "Bad request", "status": "failed"}), 400
    data = {
        "cn": uinfo["cn"][0],
        "displayName": uinfo["displayName"][0],
        "sn": uinfo["sn"][0],
        "uid": uinfo["uid"][0],
        "mail": uinfo["mail"][0],
        "telephoneNumber": "",
        "businessCategory": "",
        "managerID": "",
    }
    if len(uinfo["telephoneNumber"]) != 0:
        data["telephoneNumber"] = uinfo["telephoneNumber"][0]
    if len(uinfo["businessCategory"]) != 0:
        data["businessCategory"] = uinfo["businessCategory"][0]
    if len(uinfo["manager"]) != 0:
        managerID = uinfo["manager"][0].split(",")[0].split("=")[1]
        data["managerID"] = managerID
    userFils = getFils(data, all_users)
    return userFils


def getUserManager(uid):
    all_users = getUsers()
    all_user_info = []
    for user in all_users:
        all_user_info.append(userChild(user["uid"]))
    for user2 in all_user_info:
        for fils in user2["fils"]:
            if fils["uid"] == uid:
                return user2["info"]
    return None


def send2FA_code(mail, user_uid):
    try:
        # generating random PyOTP secret keys
        totp_secret = pyotp.random_base32()
        qr_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=mail, issuer_name="Azumaril"
        )
        FA2.delete_many({"uid": user_uid, "mail": mail})
        FA2.insert_one(
            {"uid": user_uid, "otp_secret": totp_secret, "mail": mail, "qr_url": qr_url}
        )
        # -----this is for test purpose
        # -----Display the qr code in the terminal
        comand = "qr " + qr_url
        print(comand)
        os.system(comand)
        # ------------
        return {
            "uid": user_uid,
            "mail": mail,
            "otp_secret": totp_secret,
            "qr_url": qr_url,
        }
    except:
        return None


def user_exists(userID):
    ldap = ldap_connexion()[1]
    entry = ldap.search(
        "uid=" + userID + "," + config_data["LDAP_USER_DN"],
        "(objectclass=person)",
    )
    ldap.unbind()
    if entry:
        return True
    return False


def new_seq(old_seq):
    try:
        temp = old_seq
        pos_digit = len(old_seq) - 1
        model = "0000000"

        if old_seq == "":
            return model

        while pos_digit != 0:
            if chr(ord(old_seq[pos_digit]) + 1) <= "9":
                add = chr(ord(old_seq[pos_digit]) + 1)
                new = temp[:pos_digit] + add + temp[pos_digit + 1 :]
                return new
            else:
                temp = temp[:pos_digit] + "0" + temp[pos_digit + 1 :]
                pos_digit -= 1
        temp = temp.replace("9", "0")
        if len(temp) == 7:
            temp = "a" + temp
            old_seq = chr(ord("a") - 1) + old_seq
        if chr(ord(old_seq[0]) + 1) <= "z":
            add = chr(ord(old_seq[0]) + 1)
            new = temp[:0] + add + temp[0 + 1 :]
            return new
        return model + "0"
    except:
        return str(randNumber(7))


def getLastUid():
    search_dn = config_data["LDAP_USER_DN"]
    ldap = ldap_connexion()[1]
    uid = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
    ldap.search(search_dn, f"(objectclass=*)", attributes=[uid])
    uid_list = []
    for entry in ldap.entries:
        info = ast.literal_eval(entry.entry_to_json())
        try:
            uid_list.append(info["attributes"][uid][0])
        except IndexError:
            pass
    ldap.unbind()
    return uid_list[-1]

def unique_uid():
    return new_seq(getLastUid())

def isErrorKey(user, key):
    try:
        user[key]
        return True and user[key] != ""
    except KeyError:
        return False



def changePassword(user_dn, req, isReseting=False, token=None):
    if not isErrorKey(req, "newPassword"):
        return jsonify({"message": "newPassword is required", "status": "failed"}), 400
    hashed_password = hashed(HASHED_SALTED_SHA, req["newPassword"])
    if isReseting:
        AdminConnectToLdap = Connection(
            server,
            user=ldap_server["value"]["default_user_dn"],
            password=ldap_server["value"]["default_password"],
        )
        if not AdminConnectToLdap.bind():
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "We're the problem, we're working on it right now",
                    }
                ),
                500,
            )
        changes = {"userPassword": [(MODIFY_REPLACE, [hashed_password])]}
        success = AdminConnectToLdap.modify(user_dn, changes=changes)
        if not success:
            return (
                jsonify(
                    {
                        "message": "Unable to change password, bad user uid",
                        "status": "failed",
                    }
                ),
                400,
            )
        return jsonify({"status": "success", "message": "password change successfully"})
    else:
        isCorrectOldPassword = Connection(
            server, user=user_dn, password=req["oldPassword"]
        )
        if isCorrectOldPassword.bind():
            changes = {"userPassword": [(MODIFY_REPLACE, [hashed_password])]}
            success = isCorrectOldPassword.modify(user_dn, changes=changes)
            if not success:
                return (
                    jsonify(
                        {
                            "message": "Unable to change password, old password is incorect or bad user uid",
                            "status": "failed",
                        }
                    ),
                    400,
                )
            if token is not None:
                db002["tokens"].find_one_and_delete({"token": token})
            return jsonify(
                {"status": "success", "message": "password change successfully"}
            )
        else:
            return (
                jsonify(
                    {
                        "message": "Unable to change password, old password is incorect or bad user uid",
                        "status": "failed",
                    }
                ),
                400,
            )


def tryConnexion(user_uid, password):
    if not config_data["LDAP"]:
        return (
            passwdKey(password) == db002.users.find_one({"uid": user_uid})["password"]
        )
    user_dn = getUserDn(user_uid)
    result = Connection(server, user=user_dn, password=password)
    return result.bind()


def isAdmin(uid):
    if not config_data["LDAP"]:
        fuser = db002.users.find_one({"uid": uid})
        return "admin" in fuser["groups"]
    user_dn = getUserDn(uid)
    groups = getUserGroup(user_dn, uid)
    return "admin" in groups


def isMaster(uid):
    user_dn = getUserDn(uid)
    groups = getUserGroup(user_dn, uid)
    return "master" in groups


def get_admins():
    ldap = ldap_connexion()[1]
    search_dn2 = config["LDAP_GROUP_DN"] + "," + config["LDAP_BASE_DN"]
    ldap.search(search_dn2, f"(cn=admin)", attributes=["memberUid"])
    admins = []
    for entry in ldap.entries:
        group = ast.literal_eval(entry.entry_to_json())
        admins += group["attributes"]["memberUid"]
    ldap.unbind()
    return admins


def addAdminRight(uid):
    ldap = ldap_connexion()[1]
    group_dn = getGroupDn("admin")
    r = ldap.modify(group_dn, {"memberUid": [(MODIFY_ADD, [uid])]})
    ldap.unbind()
    return r


def removeAdminRight(uid):
    ldap = ldap_connexion()[1]
    group_dn = getGroupDn("admin")
    r = ldap.modify(group_dn, {"memberUid": [(MODIFY_DELETE, [uid])]})
    ldap.unbind()
    return r


def addNewUser(user, from_google=False, groups=None, from_ldap=False):
    if not config_data["LDAP"]:
        if not isErrorKey(user, "firstname") and not isErrorKey(user, "lastname"):
            return (
                jsonify(
                    {
                        "message": "firstname and lastname is required",
                        "status": "failed",
                    }
                ),
                400,
            )

        if not isErrorKey(user, "email") and not isErrorKey(user, "password"):
            return (
                jsonify(
                    {"message": "email and password is required", "status": "failed"}
                ),
                400,
            )
        passwordTest = policy(user["password"])
        if not passwordTest[0] and not from_google:
            # invalidity_found = passwordTest[1]
            return (
                jsonify(
                    {
                        "error": "The password must be at least 8 chars long, \
                                contain capital letter, a number and a special character"
                    }
                ),
                400,
            )
        if not validMail(user["email"]):
            return jsonify({"status": "failed", "message": "Bad email"}), 400
        fuser = users.find_one({"email": user["email"]})
        if fuser is not None:
            return (
                jsonify(
                    {
                        "status": "failed",
                        "message": "User with this email already exist",
                    }
                ),
                409,
            )
        fa2 = "no"
        is2fa = isErrorKey(user, "2fa")
        if is2fa:
            if user["2fa"] != "yes" and user["2fa"] != "no":
                return (
                    jsonify(
                        {
                            "message": f"2fa must be yes or no but {fa2} was provided",
                            "status": "failed",
                        }
                    ),
                    400,
                )
            else:
                fa2 = user["2fa"]
        tt = list(db002["users"].find().sort("_id", -1).limit(1))
        if len(tt) > 0:
            userID = new_seq(tt[0]["uid"])
        else:
            userID = "0000000"
        FA2info.insert_one({"uid": userID, "2fa": fa2, "mail": user["email"]})
        is_activated = True if from_google else False
        if groups is not None:
            if "superAdmin" in groups:
                is_activated = True
        hasTel = isErrorKey(user, "tel")
        tel = None
        if hasTel:
            tel = user["tel"]
        if "user_type" in user:
            if user["user_type"] == "app":
                fuser = users.find_one(
                    {"email": user["email"], "user_type": user["user_type"]}
                )
                if fuser is not None:
                    return (
                        jsonify(
                            {
                                "status": "failed",
                                "message": "application with this email already exist",
                            }
                        ),
                        409,
                    )
            user_type = user["user_type"]
        else:
            user_type = "user"
        user_data = {
            "user_type": user_type,
            "uid": userID,
            "email": user["email"],
            "firstname": user["firstname"],
            "lastname": user["lastname"],
            "password": passwdKey(user["password"]),
            "is_activated": is_activated,
            "tel": tel,
            "log_mode": {
                "success": True,
                "warning": False,
                "debug": False,
                "error": False,
            },
            "groups": ["readonly"] if groups is None else groups,
        }
        user_data["auth_type"] = "google" if from_google else "azumaril"
        users.insert_one(user_data)
        fixed_digits = 6
        if not is_activated:
            activation_code = str(random.randrange(100000, 999999, fixed_digits))
            encode_token("activation", userID, {"activation_code": activation_code}, 30)
            mail = user["email"]
            objet = "Azumaril account activation"
            message = f"Voici votre code d'activation : {activation_code} ,\n voici votre identifiant : {userID}"
            activation_code_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('activation_code', None)
            if os.path.exists(activation_code_html_path):
                with open(activation_code_html_path, "r", encoding='utf-8') as f:
                    message = f.read().replace("activation_code", f"{str(activation_code)}")
                    message = f.read().replace("identifiant", f"{str(userID)}")
                    f.close()
            Thread(
                target=mail_sender,
                args=(
                    mail,
                    objet,
                    message,
                ),
            ).start()
        return jsonify(
            {
                "status": "success",
                "message": "Account created successfully",
                "uid": userID,
            }
        )
    else:
        """
        user = {
            "user_type": "string",
            "firstname": "string",
            "lastname": "string",
            "email": "string",
            "password": "string",
            "tel": "string", #not required
            "managerID": "string", #not required
            "businessCategory": "string", #not required
            "2fa": "string" #not required
        }
        """
        ldap = ldap_connexion()[1]
        if user is None:
            return jsonify({"message": "Missing params", "status": "failed"}), 400
        if not from_ldap:
            # response = ldap_manager.authenticate(user["uid"], user["password"])
            # userID = (user['firstname'][0]+user['lastname']).lower()
            try:
                userID = unique_uid()
            except:
                userID = "0000001"
            user_dn = (
                f'{config_data["LDAP_USER_ATTRIBUTES"]["uid"]}='
                + userID
                + ","
                + config_data["LDAP_USER_DN"]
            )
        else:
            userID = user["uid"]

        if not isErrorKey(user, "firstname") and not isErrorKey(user, "lastname"):
            return (
                jsonify(
                    {
                        "message": "firstname and lastname is required",
                        "status": "failed",
                    }
                ),
                400,
            )

        if not isErrorKey(user, "email") and not isErrorKey(user, "password"):
            return (
                jsonify(
                    {"message": "email and password is required", "status": "failed"}
                ),
                400,
            )
        if not from_ldap:
            passwordTest = policy(user["password"])
            if not passwordTest[0] and not from_google:
                # invalidity_found = passwordTest[1]
                return (
                    jsonify(
                        {
                            "error": "The password must be at least 8 chars long, \
                                    contain capital letter, a number and a special character"
                        }
                    ),
                    400,
                )
            if not validMail(user["email"]):
                return jsonify({"status": "failed", "message": "Bad email"}), 400
        fuser = users.find_one({"email": user["email"]})
        if fuser is not None:
            return (
                jsonify(
                    {
                        "status": "failed",
                        "message": "User with this email already exist",
                    }
                ),
                409,
            )
        fullname = user["firstname"] + " " + user["lastname"]
        homeDirectory = "/home/" + user["firstname"][0] + user["lastname"]
        hasManager = isErrorKey(user, "managerID")
        hasBusinessCategory = isErrorKey(user, "businessCategory")
        hasTel = isErrorKey(user, "tel")
        is2fa = isErrorKey(user, "2fa")
        fa2 = "no"
        if is2fa:
            if user["2fa"] != "yes" and user["2fa"] != "no":
                return (
                    jsonify(
                        {
                            "message": f"2fa must be yes or no but {fa2} was provided",
                            "status": "failed",
                        }
                    ),
                    400,
                )
            else:
                fa2 = user["2fa"]
        try:
            if not from_ldap:
                # define all attributes
                attributes = {
                    "cn": user["firstname"],
                    # 'givenName' : 'Beatrix',
                    "sn": user["lastname"],
                    # 'departmentNumber' : 'DEV',
                    "userPassword": user["password"],
                    "HomeDirectory": homeDirectory,
                    "gidNumber": 10002,
                    "uidNumber": 10002,
                    "shadowWarning": 7,
                    "shadowMin": 1,
                    "shadowMax": 60,
                    "shadowInactive": 60,
                    "loginShell": "/bin/bash",
                    "employeeNumber": userID,
                    "displayName": fullname,
                    "mail": user["email"],
                }
                # attributes['auth_type'] = 'google' if from_google else 'azumarill'

                if hasBusinessCategory:
                    attributes["businessCategory"] = user["businessCategory"]
                if hasTel:
                    attributes["telephoneNumber"] = user["tel"]

                object_class = [
                    "inetOrgPerson",
                    "posixAccount",
                    "shadowAccount",
                    "person",
                ]
                # add user
                if config_data.get("LDAP_WRITE_RIGHT", False):
                    result = ldap.add(
                        dn=user_dn, object_class=object_class, attributes=attributes
                    )
                    # print(result.description)
                    print(ldap.result)
                # if result:
                # ------insert in azumaril----------
                FA2info.insert_one(
                    {"uid": userID, "2fa": fa2, "mail": user["email"]}
                )
                is_activated = True if from_google else False
                user_data = {
                    "uid": userID,
                    "user_type": "user",
                    "tel" : None if "tel" not in user else user["tel"],
                    "groups" : ["readonly"],
                    "email": user["email"],
                    "firstname": user["firstname"],
                    "lastname": user["lastname"],
                    "password": passwdKey(user["password"]),
                    "is_activated": is_activated,
                    "log_mode": {
                        "success": True,
                        "warning": False,
                        "debug": False,
                        "error": False,
                    },
                }
                user_data["auth_type"] = "google" if from_google else "azumaril"
                if from_ldap:
                    user_data["auth_type"] = "ldap"
                users.insert_one(user_data)
                if is2fa:
                    if user["2fa"] == "yes":
                        send2FA_code(user["email"], userID)
                # ------------------------------------
                if config_data.get("LDAP_WRITE_RIGHT", False):
                    addUsersInGroups(ldap, user_dn, readonly_group)
                if not from_google:
                    fixed_digits = 6
                    activation_code = str(
                        random.randrange(100000, 999999, fixed_digits)
                    )
                    encode_token(
                        "activation",
                        userID,
                        {"activation_code": activation_code},
                        30,
                    )
                    mail = user["email"]
                    objet = "Azumaril account activation"
                    message = f"Voici votre code d'activation : {activation_code} ,\n voici votre identifiant : {userID}"
                    activation_code_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('activation_code', None)
                    if os.path.exists(activation_code_html_path):
                        with open(activation_code_html_path, "r", encoding='utf-8') as f:
                            message = f.read().replace("activation_code", f"{str(activation_code)}")
                            message = f.read().replace("identifiant", f"{str(userID)}")
                            f.close()
                    Thread(
                        target=mail_sender,
                        args=(
                            mail,
                            objet,
                            message,
                        ),
                    ).start()
                ldap.unbind()
                return jsonify(
                    {
                        "status": "success",
                        "message": "Account " + fullname + " created successfully",
                        "uid": userID,
                    }
                )
            else:
                FA2info.insert_one({"uid": userID, "2fa": fa2, "mail": user["email"]})
                is_activated = True if from_google else False
                user_data = {
                    "uid": userID,
                    "user_type": "user",
                    "tel" : None if "tel" not in user else user["tel"],
                    "groups" : ["readonly"],
                    "email": user["email"],
                    "firstname": user["firstname"],
                    "lastname": user["lastname"],
                    "password": passwdKey(user["password"]),
                    "is_activated": True,
                    "log_mode": {
                        "success": True,
                        "warning": False,
                        "debug": False,
                        "error": False,
                    },
                }
                user_data["auth_type"] = "ldap"
                users.insert_one(user_data)
                if is2fa:
                    if user["2fa"] == "yes":
                        send2FA_code(user["email"], userID)
        except LDAPException as e:
            print(str(e))
            ldap.unbind()
            print(traceback.format_exc())
            response = e
            return response


def refresh_azumaril_system_safe():
    print("rfreshing azumaril secrets")
    fsafe = safes.find_one({"owner_uid": "0000000", "name": "SYSTEM", "type": "system"})
    print(fsafe)
    db002.secrets.delete_many({"safe_id": fsafe["safe_id"], "deletable": False})
    system_secrets = list(cd_secret_collection.find({}))
    print(system_secrets)
    for ss in system_secrets:
        print("ssid")
        print(ss["id"])
        del ss["_id"]
        secret_infos = {
            "owner_uid": "0000000",
            "secret_id": ss["id"],
            "name": ss["name"],
            "secret": ss["secret"],
            "date": datetime.now(),
            "secret_type": "credentials",
            "deletable": False,
            "safe_id": fsafe["safe_id"],
            "app_type": "azumaril",
            "file_path": None,
            "file_name": None,
            "file_type": None,
        }
        db002.secrets.insert_one(secret_infos)


def create_super_admin_user(ecptk):
    try:
        print("create_super_admin_user")
        fsecret = cd_secret_collection.find_one({"name": "SUPERADMIN"})
        secret = get_default_secret(fsecret, ecptk)
        if secret is None:
            # we must recreate it
            pass
        fuser = db002.users.find_one({"email": secret["email"]})
        if fuser is None:
            print("azumaril super admin created")
            FA2info.insert_one({"uid": "0000000", "2fa": "no", "mail": secret["email"]})
            user_data = {
                "uid": "0000000",
                "user_type": "user",
                "firstname": "ADMIN",
                "lastname": "SUPER",
                "email": secret["email"],
                "password": passwdKey(secret["password"]),
                "is_activated": True,
                "tel": None,
                "log_mode": {
                    "success": True,
                    "warning": False,
                    "debug": False,
                    "error": False,
                },
                "groups": ["readonly", "admin", "superAdmin"],
            }
            user_data["auth_type"] = "azumarill"
            users.insert_one(user_data)
            safe_id = str(ObjectId())
            system_secrets = cd_secret_collection.find({})
            safe_info = {
                "owner_uid": "0000000",
                "safe_id": safe_id,
                "name": "SYSTEM",
                "type": "system",
                "date": datetime.now(),
            }
            safes.insert_one(safe_info)
            for ss in system_secrets:
                del ss["_id"]
                secret_infos = {
                    "owner_uid": "0000000",
                    "secret_id": ss["id"],
                    "name": ss["name"],
                    "secret": ss["secret"],
                    "date": datetime.now(),
                    "secret_type": "credentials",
                    "safe_id": safe_id,
                    "deletable": False,
                    "app_type": "azumaril",
                    "file_path": None,
                    "file_name": None,
                    "file_type": None
                }
                db002.secrets.insert_one(secret_infos)
            print("azumaril super admin created")
    except:
        print("failed to create azumaril super admin")
        
if active_cluster_mode:
    if is_primary():
        create_super_admin_user(ecptk)
else:
    create_super_admin_user(ecptk)

if safes.find_one({"owner_uid" : "SYSTEM", "name" : "SYSTEM", "type" : "system"}) is None:
    safe_info = {
        "owner_uid": "SYSTEM",
        "safe_id": str(ObjectId()),
        "name": "SYSTEM",
        "type": "system",
        "date": datetime.now(),
    }
    safes.insert_one(safe_info)

def search_user_info(identifier, get_all_data=False):
    try:
        # Establish connection to LDAP server
        uid = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
        # print(f"identifier is {uid}={identifier}")
        # print(config)
        # print(f'{config_data["LDAP_USER_DN"]}')
        ldap = ldap_connexion()[1]
        ldap.search(
            search_base=config_data["LDAP_USER_DN"],
            # search_filter=f"(|(mail={identifier})(email={identifier})(uid={identifier}))",
            search_filter=f"(|(mail={identifier})({uid}={identifier}))",
            search_scope=SUBTREE,
            attributes=[ALL_ATTRIBUTES],
        )
        # print("LDAP SEARCH RESULT")
        # print(ldap.entries)
        # print(ldap.entries[0].entry_attributes)
        # Retrieve user info
        if ldap.entries:
            if get_all_data:
                user_info = {}
                for attribute in ldap.entries[0].entry_attributes:
                    user_info[attribute] = ldap.entries[0][attribute].value
                return user_info
            else:
                return ldap.entries[0].entry_dn
        else:
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None

def ldap_login_and_add_user_if_404(uid, password):
    try:
        founduser_dn = search_user_info(
            uid
        )  # uid should be an email in this case
        if founduser_dn is None:  # still can't found the user in ldap so break
            print("bad uid or email ldap_login_and_add_user_if_404")
            return {"message" : "bad uid or email"}, 401
        else:  # found the user so insert it in azumaril database
            result = Connection(
                server, user=founduser_dn, password=password
            )
            if (
                result.bind()
            ):
                firstname = config_data["LDAP_USER_ATTRIBUTES"]["firstname"]
                lastname = config_data["LDAP_USER_ATTRIBUTES"]["lastname"]
                tel = config_data["LDAP_USER_ATTRIBUTES"]["tel"]
                mail = config_data["LDAP_USER_ATTRIBUTES"]["email"]
                ref = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
                ldap_user_info = search_user_info(uid, True)
                ldap_user_info["password"] = password
                ldap_user_info["firstname"] = ldap_user_info.get(firstname, "")
                ldap_user_info["lastname"] = ldap_user_info.get(lastname, "")
                ldap_user_info["tel"] = ldap_user_info.get(tel, "")
                ldap_user_info["email"] = ldap_user_info.get(mail, "")
                ldap_user_info["uid"] = ldap_user_info.get(ref, "")
                ldap_user_info["user_type"] = "user"
                fuser = db002.users.find_one({"uid" : {"$regex": f"^{uid}$", "$options": "i"}})
                if fuser is None:
                    addNewUser(
                        ldap_user_info, from_ldap=True
                    )  # if connexion success add it to mongo
                
                fuser = db002.users.find_one({"uid" : {"$regex": f"^{uid}$", "$options": "i"}}, {"_id" : 0})
                homeDirectory = (
                    "/home/" + fuser["firstname"][0] + fuser["lastname"]
                )
                fa2 = FA2info.find_one({"uid":uid})
                fa22 = "no" if fa2 is None else fa2["2fa"]
                
                response = {
                    "status": "success",
                    "message": "Successfully authenticated",
                    "2FA": fa22,
                }
                if fa22 == "yes":
                    response["uid"] = uid
                    return response, 200 
                groups = getUserGroup(founduser_dn, ldap_user_info["uid"])
                user_info = search_user_info(uid, True)
                user_info = {
                    firstname : user_info.get(firstname, None),
                    lastname : user_info.get(lastname, None),
                    tel : user_info.get(tel, None),
                    mail : user_info.get(mail, None),
                    ref : user_info.get(ref, None)
                }
                default_user_info = {
                    "businessCategory": "",
                    "cn": user_info[firstname],
                    "displayName": f"{user_info[firstname]} {user_info[lastname]}",
                    "gidNumber": 10002,
                    "homeDirectory": homeDirectory,
                    "loginShell": "/bin/bash",
                    "mail": user_info[mail],
                    "manager": "",
                    "sn": user_info[lastname],
                    "telephoneNumber": user_info[tel],
                    "uid": user_info[ref],
                    "uidNumber": 10002,
                }
                fuser.update(default_user_info)
                print(user_info)
                response["token"] = encode_auth_token(ldap_user_info["uid"])[
                    "token"
                ]
                if len(groups) == 0:
                    groups = ["readonly"]
                response["user_groups"] = groups
                response["user_info"] = fuser
                return response, 200
            else:
                return {"message" : "failed bad uid or password"}, 401
    except:
        print(traceback.format_exc())
        return {"message" : "something went wrong"}, 500

def azumaril_login(uid, password):
    try:
        fuser = users.find_one({"uid" : {"$regex": f"^{uid}$", "$options": "i"}}, {"_id": 0})
        if fuser is None:
            fuser = users.find_one({"email" : uid}, {"_id": 0})
            if fuser is None:
                return {"message" : "failed bad uid or bad password"}, 401

            if "marked_for_deletion" in fuser:
                if fuser["marked_for_deletion"] == True:
                    return jsonify({"status": "failed", "message": "Your account is marked for deletion. Please contact admin for more informations."}), 400
        
        if passwdKey(password) == fuser["password"]:
            if not fuser["is_activated"]:
                objet = "Azumaril account activation"
                ftoken = db002["tokens"].find_one(
                    {"type": "activation", "user_uid": fuser["uid"]}
                )
                if ftoken is None:
                    return {
                                "status": "failed",
                                "message": "Account not activated yet, please activate account and retry",
                            }, 403
                else:
                    message = f"Voici votre code d'activation : {ftoken['activation_code']} ,\n voici votre identifiant : {fuser['uid']}"
                    try:
                        print(message)
                    except OSError:
                        pass    
                    activation_code_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('activation_code', None)
                    if os.path.exists(activation_code_html_path):
                        with open(activation_code_html_path, "r", encoding='utf-8') as f:
                            message = f.read().replace("activation_code", f"{str({ftoken['activation_code']})}")
                            message = f.read().replace("identifiant", f"{str({fuser['uid']})}")
                            f.close()
                    Thread(
                        target=mail_sender,
                        args=(
                            fuser["email"],
                            objet,
                            message,
                        ),
                    ).start()
                return {
                            "status": "failed",
                            "message": "Account not activated yet, please activate account by verifiying your email and retry",
                        }, 403
            fa2 = FA2info.find_one({"uid": uid})
            if fa2 is None:
                fa2 = FA2info.find_one({"mail": uid})
                if fa2 is None:
                    fa22 = "no"
                else:
                    fa22 = fa2["2fa"]
            else:
                fa22 = fa2["2fa"]
            response = {
                "status": "success",
                "message": "Successfully authenticated",
                "2FA": fa22,
            }
            if fa22 == "no":
                response["token"] = encode_auth_token(fuser["uid"])["token"]
                response["user_groups"] = fuser["groups"]
                homeDirectory = (
                    "/home/" + fuser["firstname"][0] + fuser["lastname"]
                )
                default_user_info = {
                    "businessCategory": "",
                    "cn": fuser["firstname"],
                    "displayName": f"{fuser['firstname']} {fuser['lastname']}",
                    "gidNumber": 10002,
                    "homeDirectory": homeDirectory,
                    "loginShell": "/bin/bash",
                    "mail": fuser["email"],
                    "manager": "",
                    "sn": fuser["lastname"],
                    "telephoneNumber": fuser["tel"],
                    "uid": fuser["uid"],
                    "uidNumber": 10002,
                }
                fuser.update(default_user_info)
                response["user_info"] = fuser
            else:
                response["uid"] = uid
            return response, 200   
        else:
            return {"message" : "failed bad uid or bad password"}, 401
    except:
        print(traceback.format_exc())
        return {"message" : "something went wrong"}, 500

def google_connexion(fuser):
    fa2 = FA2info.find_one({"uid": fuser["uid"]})
    if fa2 is None:
        fa2 = FA2info.find_one({"mail": fuser["uid"]})
        if fa2 is None:
            fa22 = "no"
        else:
            fa22 = fa2["2fa"]
    else:
        fa22 = fa2["2fa"]
    response = {
        "status": "success",
        "message": "Successfully authenticated",
        "2FA": fa22,
    }
    if fa22 == "no":
        response["token"] = encode_auth_token(fuser["uid"])["token"]
        response["user_groups"] = fuser.get("groups", ["readonly"])
        homeDirectory = (
            "/home/" + fuser["firstname"][0] + fuser["lastname"]
        )
        default_user_info = {
            "businessCategory": "",
            "cn": fuser["firstname"],
            "displayName": f"{fuser['firstname']} {fuser['lastname']}",
            "gidNumber": 10002,
            "homeDirectory": homeDirectory,
            "loginShell": "/bin/bash",
            "mail": fuser["email"],
            "manager": "",
            "sn": fuser["lastname"],
            "telephoneNumber": fuser.get("tel", None),
            "uid": fuser["uid"],
            "uidNumber": 10002,
        }
        fuser.update(default_user_info)
        response["user_info"] = fuser
    else:
        response["uid"] = fuser["uid"]
    return jsonify(response), 200

def check_deletion_field(uid):
    user = users.find_one({"uid": uid})
    if user:
        if "marked_for_deletion" not in user:
            pass
        else:
           deletion = users.find_one({"uid": uid, "marked_for_deletion": True})
           if deletion:
               return jsonify({"status": "failed", "message": "bad uid or email"}), 400
           else:
               pass
    else:
        return jsonify({"message":"User not found", "status": "failed"}), 404
    
def connectUser(req_data):
    if req_data is None:
        return jsonify({"message": "Missing params", "status": "failed"}), 400
    if not isErrorKey(req_data, "uid"):
        return jsonify({"status": "failed", "message": "uid is required"}), 400
    uid = req_data["uid"]
    
    check_deletion_field(uid)

    if "auth_type" in req_data:
        if req_data["auth_type"] == "ldap":
            result = ldap_login_and_add_user_if_404(uid, req_data["password"])
            return jsonify(result[0]), result[1]
        
        if req_data["auth_type"] == "azumaril":
            result = azumaril_login(uid, req_data["password"])
            return jsonify(result[0]), result[1]
        
    scope = {"uid": uid}
            
    if "app" in req_data:
        scope["app"] = req_data["app"]
    foundUser = users.find_one(scope, {"_id": 0})
    try:
        print(foundUser) 
    except OSError:
        pass        
    if config_data["LDAP"]:
        if foundUser is None:
            scope = {"email": uid}
            foundUser = users.find_one(scope, {"_id": 0})
            if foundUser is None:
                print("bad uid or email *******")
                return jsonify({"status": "failed", "message": "bad uid or email"}), 400
            uid = foundUser["uid"]
        result = ldap_login_and_add_user_if_404(uid, req_data["password"])
        return jsonify(result[0]), result[1]

    if foundUser is None:
        scope = {"email": uid}
        if "app" in req_data:
            scope["app"] = req_data["app"]
        foundUser = users.find_one(scope, {"_id": 0})
        if foundUser is None:
            if config_data[
                "LDAP"
            ]:  # can't found user so trying to find it in LDAP if used
                result = ldap_login_and_add_user_if_404(uid, req_data["password"])
                return jsonify(result[0]), result[1]
            else:  # LDAP is not used break
                print("bad uid or email ======")
                return jsonify({"status": "failed", "message": "bad uid or email"}), 400
    
    if not foundUser["is_activated"]:
        objet = "Azumaril account activation"
        ftoken = db002["tokens"].find_one(
            {"type": "activation", "user_uid": foundUser["uid"]}
        )
        if ftoken is None:
            return (
                jsonify(
                    {
                        "status": "failed",
                        "message": "Account not activated yet, please activate account and retry",
                    }
                ),
                400,
            )
        else:
            message = f"Voici votre code d'activation : {ftoken['activation_code']} ,\n voici votre identifiant : {foundUser['uid']}"
            print(message)
            activation_code_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('activation_code', None)
            if os.path.exists(activation_code_html_path):
                with open(activation_code_html_path, "r", encoding='utf-8') as f:
                    message = f.read().replace("activation_code", f"{str({ftoken['activation_code']})}")
                    message = f.read().replace("identifiant", f"{str({foundUser['uid']})}")
                    f.close()
            Thread(
                target=mail_sender,
                args=(
                    foundUser["email"],
                    objet,
                    message,
                ),
            ).start()
        return (
            jsonify(
                {
                    "status": "failed",
                    "message": "Account not activated yet, please activate account by verifiying your email and retry",
                }
            ),
            400,
        )
    # if not config_data["LDAP"]:
    if passwdKey(req_data["password"]) == foundUser["password"]:
        fa2 = FA2info.find_one({"uid": uid})
        print(fa2)
        print(uid)
        if fa2 is None:
            fa2 = FA2info.find_one({"mail": uid})
            if fa2 is None:
                fa22 = "no"
            else:
                fa22 = fa2["2fa"]
        else:
            fa22 = fa2["2fa"]
        response = {
            "status": "success",
            "message": "Successfully authenticated",
            "2FA": fa22,
        }
        if fa22 == "no":
            response["token"] = encode_auth_token(foundUser["uid"])["token"]
            response["user_groups"] = foundUser["groups"]
            homeDirectory = (
                "/home/" + foundUser["firstname"][0] + foundUser["lastname"]
            )
            default_user_info = {
                "businessCategory": "",
                "cn": foundUser["firstname"],
                "displayName": f"{foundUser['firstname']} {foundUser['lastname']}",
                "gidNumber": 10002,
                "homeDirectory": homeDirectory,
                "loginShell": "/bin/bash",
                "mail": foundUser["email"],
                "manager": "",
                "sn": foundUser["lastname"],
                "telephoneNumber": foundUser["tel"],
                "uid": foundUser["uid"],
                "uidNumber": 10002,
            }
            foundUser.update(default_user_info)
            response["user_info"] = foundUser
        else:
            response["uid"] = uid
        return jsonify(response), 200
    else:
        return (
            jsonify({"message": "Authentication failed", "status": "failed"}),
            401,
        )

    # search_dn1 = config["LDAP_USER_DN"] + "," + config["LDAP_BASE_DN"]

    # uid = foundUser["uid"]
    # user_dn = "uid=" + uid + "," + search_dn1

    # result = Connection(server, user=user_dn, password=req_data["password"])
    # if result.bind():
    #     try:
    #         fa2 = FA2info.find_one({"uid": uid})
    #         if fa2 is None:
    #             fa22 = "no"
    #         else:
    #             fa22 = fa2["2fa"]
    #     except:
    #         return (
    #             jsonify(
    #                 {
    #                     "message": "Authentication failed, this user has no email",
    #                     "status": "failed",
    #                 }
    #             ),
    #             400,
    #         )
    #     response = {
    #         "status": "success",
    #         "message": "Successfully authenticated",
    #         "2FA": fa22,
    #     }
    #     if fa22 == "no":
    #         groups = getUserGroup(user_dn, uid)
    #         user_info = {}
    #         for k, v in get_userInfo(user_dn, uid).items():
    #             try:
    #                 user_info[k] = v[0]
    #             except:
    #                 user_info[k] = ""
    #         response["token"] = encode_auth_token(uid)["token"]
    #         response["user_groups"] = groups
    #         response["user_info"] = user_info
    #     else:
    #         response["uid"] = uid

    #     return jsonify(response), 200
    # else:
    #     return jsonify({"message": "Authentication failed", "status": "failed"}), 400

authorization_endpoint = "https://192.168.1.174:5000/authorize"
oidc_apps = db002["oidc_apps"]
oidc_authorization_links = db002["oidc_authorization_links"]
oidc_authorization_tokens = db002["oidc_authorization_tokens"]
oidc_authorization_codes = db002["oidc_authorization_codes"]

oidc_authorization_links_index_info = oidc_authorization_links.index_information()
oidc_index_name = "oidc_ttl_index"
if index_name not in oidc_authorization_links_index_info:
    try:
        if active_cluster_mode:
            if is_primary():
                oidc_authorization_links.create_index(
                    [("expired_at", 1)],
                    expireAfterSeconds=600,
                    name=oidc_index_name,
                )
        else:
            oidc_authorization_links.create_index(
                    [("expired_at", 1)],
                    expireAfterSeconds=600,
                    name=oidc_index_name,
                )
    except:
        pass

oidc_authorization_tokens_index_info = oidc_authorization_tokens.index_information()
if index_name not in oidc_authorization_tokens_index_info:
    try:
        if active_cluster_mode:
            if is_primary():
                oidc_authorization_tokens.create_index(
                    [("expired_at", 1)],
                    expireAfterSeconds=3600,
                    name=oidc_index_name,
                )
        else:
            oidc_authorization_tokens.create_index(
                    [("expired_at", 1)],
                    expireAfterSeconds=3600,
                    name=oidc_index_name,
                )
    except:
        pass

oidc_authorization_codes_index_info = oidc_authorization_codes.index_information()
if index_name not in oidc_authorization_codes_index_info:
    try:
        if active_cluster_mode:
            if is_primary():
                oidc_authorization_codes.create_index(
                    [("expired_at", 1)],
                    expireAfterSeconds=30,
                    name=oidc_index_name,
                )
        else:
            oidc_authorization_codes.create_index(
                    [("expired_at", 1)],
                    expireAfterSeconds=30,
                    name=oidc_index_name,
                )
    except:
        pass

import json


def check_required_keys(required_keys, request_values):
    missing_keys = [key for key in required_keys if key not in request_values]
    if not missing_keys:
        return True, ""
    else:
        message = f"Keys {', '.join(missing_keys)} is not provided"
        return False, message


def verify_dict_keys(dic, keys, value_type):
    for key in dic.keys():
        if key not in keys:
            return False
        if not isinstance(dic[key], value_type):
            return False
    return True


def retries(mail, incr=False, reset=False):
    has_uid, has_mail = users.find_one({"uid": mail}), users.find_one({"email": mail})
    instance = has_uid if has_mail is None else has_mail
    if instance is None:
        return 0
    tries = 0

    if not "try" in instance:
        if not incr:
            users.update_one({"_id": instance["_id"]}, {"$set": {"try": 0}})
            return 0
        else:
            users.update_one({"_id": instance["_id"]}, {"$set": {"try": 1}})
            return 1

    if reset:
        users.update_one({"_id": instance["_id"]}, {"$set": {"try": tries}})
    elif incr:
        tries = instance["try"]
        tries += 1
        users.update_one({"_id": instance["_id"]}, {"$set": {"try": tries}})

    return tries


def check_date_format(date_str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False

def isDeleted(uid):
    user = users.find_one({"uid": uid})
    if user:
        if "marked_for_deletion" not in user:
            deletion_delay_days = 1  # Délai par défaut de 30 jours
            deletion_date = datetime.utcnow() + timedelta(days=deletion_delay_days)
            users.update_one({"uid": uid}, {"$set": {"marked_for_deletion": True, "deletion_date": deletion_date}})
            return True
        else:
            users.update_one({"uid": uid}, {"$set": {"marked_for_deletion": True}})
            return True
    
collections = db002.list_collection_names()

# Fonction pour vérifier les champs dans une collection
def check_and_delete_fields(collection, mail=None, uid=None):
    sample_doc = db002[collection].find_one()
    if sample_doc:
        has_uid = 'uid' in sample_doc
        has_owner_uid = 'owner_uid' in sample_doc
        has_mail = 'mail' in sample_doc
        has_email = 'email' in sample_doc
        
        if has_mail:
            db002[collection].delete_many({'mail': mail})
        elif has_email:
            db002[collection].delete_many({'email': mail})
        elif has_uid:
            db002[collection].delete_many({'uid': uid})
        elif has_owner_uid:
            db002[collection].delete_many({'owner_uid': uid})


def define_user_for_deletion(owner_uid):
    user = users.find_one({"uid": owner_uid})
    if user:
        for collection in collections:
            check_and_delete_fields(collection, mail=user["email"], uid=user["uid"])
    else:
        return jsonify({"message":"User not found", "status": "failed"}), 404

def delete_expired_users(nothing):
    while True:
        today = datetime.utcnow()
        expired_users = users.find({
            "marked_for_deletion": True,
            "deletion_date": {"$lt": today}
        })
        for user in expired_users:
            if user:
                print(user)
                for collection in collections:
                    # Suppression de l'utilisateur et de toutes les données associées
                    check_and_delete_fields(collection, mail=user["email"], uid=user["uid"])
        
        time.sleep(60)

expiration_account_thread = CustomThread(target=delete_expired_users, args=("",))
expiration_account_thread.start()

