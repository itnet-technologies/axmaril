import sys
import logging
import ssl
import multiprocessing
import subprocess
import gunicorn.app.base
from flask_cors import CORS
from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint
import atexit, time
import threading
import random
import os
import psutil
from datetime import timedelta
from gunicorn.app.base import BaseApplication
from gunicorn.glogging import Logger
from loguru import logger
from OpenSSL import crypto

# ---- Modules internes / Blueprints -------------------------------------------------
from modules.ldapauth import LDAP_REQUEST
from modules.applications import APP_REQU
from modules.secret import SHARE_REQUEST
from modules.password import PASSWORD_REQUEST
from modules.policies import POLICIES_REQU
from modules.oidc_app import OIDC
from modules.google_auth import GOOGLE_AUTH
from modules.tickets.routes import TICKET_REQUEST
from modules.raft_state import RAFTSTATE_REQUEST
from modules.kmip_route import KMIP_REQUEST
from modules.required_packages import (
    db_pid, config_data, DEBUG, API_PORT, ALLOWED_CORS, LOCAL_DATABASE, initapp_port, cache
)

from api.v2.modules.application.application_routes import application_bp
from api.v2.modules.coffre.safe_routes import safe_bp
from api.v2.modules.kmip.kmip_routes import kmip_bp
from api.v2.modules.CA.ca_routes import ca_bp
from api.v2.modules.secret.secret_routes import secret_bp
from api.v2.modules.group.group_routes import group_bp
from api.v2.modules.shared.shared_routes import shared_bp
from api.v2.modules.shared_safe.shared_safe_routes import shared_safe_bp
from api.v2.modules.third_party.third_party_routes import third_party_bp
from api.v2.modules.ssh.ssh_routes import ssh_bp
from api.v2.modules.third_party_account.third_party_account_routes import third_party_account_bp
from api.v2.modules.update.update_routes import bulk_bp
from api.v2.modules.guacamole.guacamole_routes import guacamole_bp

# OPTIONNEL (expose les routes d’admin des groupes Guac si besoin seulement)
# from modules.guacamole_group import guacamole_group_bp

# ---- App / cache -------------------------------------------------------------------
if "RAFT" in config_data and config_data["RAFT"].get("active"):
    app = Flask(__name__)
else:
    app = Flask(__name__)
cache.init_app(app)

# ---- CORS (unifié) -----------------------------------------------------------------
if ALLOWED_CORS == "*":
    CORS(app, resources={r"/api/*": {"origins": "*"}})
elif isinstance(ALLOWED_CORS, list):
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_CORS, "methods": "*"}})
else:
    print("invalid cors in config.json file")
    print("cors must be * or a list of allowed links eg : ['https://example.com', 'https://example2.com']")
    sys.exit(1)

# ---- Swagger -----------------------------------------------------------------------
SWAGGER_URL = '/swagger/'
API_URL2 = "/api/v1/"
API_URL_V2 = "/api/v2/"
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL, API_URL, config={'app_name': "Seans-Python-Flask-REST-Boilerplate"}
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

# ---- Blueprints V1 -----------------------------------------------------------------
app.register_blueprint(LDAP_REQUEST, url_prefix=API_URL2 + "auth")
app.register_blueprint(GOOGLE_AUTH, url_prefix=API_URL2 + "auth")
app.register_blueprint(APP_REQU, url_prefix=API_URL2 + "application")
app.register_blueprint(SHARE_REQUEST, url_prefix=API_URL2 + "secret")
app.register_blueprint(PASSWORD_REQUEST, url_prefix=API_URL2 + "password")
app.register_blueprint(POLICIES_REQU, url_prefix=API_URL2 + "policies")
app.register_blueprint(OIDC, url_prefix=API_URL2 + "oidc")
app.register_blueprint(TICKET_REQUEST, url_prefix=API_URL2 + "ticket")
app.register_blueprint(RAFTSTATE_REQUEST, url_prefix=API_URL2 + "raft")
app.register_blueprint(ssh_bp, url_prefix=f"{API_URL2}")
app.register_blueprint(group_bp, url_prefix=f"{API_URL2}")
app.register_blueprint(shared_bp, url_prefix=f"{API_URL2}")
app.register_blueprint(shared_safe_bp, url_prefix=f"{API_URL2}")

# ---- Blueprints V2 -----------------------------------------------------------------
app.register_blueprint(application_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(safe_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(secret_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(kmip_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(ca_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(bulk_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(third_party_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(third_party_account_bp, url_prefix=f"{API_URL_V2}")
app.register_blueprint(guacamole_bp, url_prefix=f"{API_URL_V2}")

# OPTIONNEL: exposer l’admin des groupes Guac (protège-le par JWT/admin !)
# app.register_blueprint(guacamole_group_bp, url_prefix=f"{API_URL_V2}guacamole")

# ---- Session / secrets -------------------------------------------------------------
app.secret_key = ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!#') for _ in range(20))
app.permanent_session_lifetime = timedelta(minutes=1)

# ---- Logging fichier ---------------------------------------------------------------
log_file_path = os.path.dirname(__file__) + "/azumaril_log.txt"
if "LOG_PATH" in config_data:
    log_file_path = config_data["LOG_PATH"]
if not os.path.exists(log_file_path):
    with open(log_file_path, "x"):
        pass

# ---- Kill helpers (gardés, mais accrochés en debug seulement) ----------------------
def kill_process(pid):
    subprocess.run(["sudo", "kill", "-9", pid], capture_output=True, text=True)
    return True

def find_pid_by_port(port):
    try:
        result = subprocess.check_output(['lsof', '-i', f':{port}'], text=True)
        for line in result.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 1:
                return int(parts[1])
    except subprocess.CalledProcessError:
        print(f"No process is using port {port}.")
    except ValueError:
        print("Error parsing PID.")
    return None

def kill_process_and_threads(pid):
    try:
        subprocess.run(['kill', '-9', str(pid)], check=True)
        print(f"Process {pid} and all its threads have been killed.")
    except subprocess.CalledProcessError:
        print(f"Failed to kill process with pid {pid}.")
    except ValueError:
        print("Error with PID.")

def kill_process_by_port(port):
    pid = find_pid_by_port(port)
    if pid is not None:
        kill_process_and_threads(pid)
    else:
        print(f"No process is using port {port}.")

def exit_handler():
    kill_process_by_port(initapp_port)
    if LOCAL_DATABASE:
        kill_process(str(db_pid))
        print('-- end database server --')
    # Nettoyage de ports front éventuels
    for process in psutil.process_iter():
        try:
            info = process.as_dict(attrs=['pid', 'name', 'connections'])
            if info['connections']:
                for conn in info['connections']:
                    if conn.laddr.port in (54321, int(config_data.get("FRONTEND_PORT", 0))):
                        process.kill()
                        print(f"Process with PID {info['pid']} killed.")
        except psutil.NoSuchProcess:
            pass

# ---- Gunicorn integration ----------------------------------------------------------
def number_of_workers():
    return (multiprocessing.cpu_count() * 2) + 1

class StandaloneApplication(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()
    def load_config(self):
        config = {k: v for k, v in self.options.items() if k in self.cfg.settings and v is not None}
        for k, v in config.items():
            self.cfg.set(k.lower(), v)
    def load(self):
        return self.application

LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO"))
JSON_LOGS = True if os.environ.get("JSON_LOGS", "0") == "1" else False

class InterceptHandler(logging.Handler):
    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())

class StubbedGunicornLogger(Logger):
    def setup(self, cfg):
        handler = logging.NullHandler()
        self.error_logger = logging.getLogger("gunicorn.error")
        self.error_logger.addHandler(handler)
        self.access_logger = logging.getLogger("gunicorn.access")
        self.access_logger.addHandler(handler)
        self.error_log.setLevel(LOG_LEVEL)
        self.access_log.setLevel(LOG_LEVEL)

# ---- SSL utils ---------------------------------------------------------------------
def generate_ssl_certificates(cert_file, key_file, key_size=2048):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    with open(cert_file, "wb") as cert_file_out:
        cert_file_out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as key_file_out:
        key_file_out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    print("SSL certificates generated successfully!")

# ---- Healthchecks ------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200

@app.route("/health/guacamole", methods=["GET"])
def health_guacamole():
    try:
        from api.v2.modules.guacamole.guacamole_service import GuacamoleService
        s = GuacamoleService()
        s.get_admin_token()
        return {"guacamole": "ok"}, 200
    except Exception as e:
        return {"guacamole": "down", "error": str(e)}, 503

# ---- Main --------------------------------------------------------------------------
if __name__ == '__main__':
    class OutputRedirector:
        def __init__(self, filename):
            self.filename = filename
            self.original_stdout = sys.stdout
        def write(self, text):
            with open(self.filename, 'a') as f:
                f.write(text)
            self.original_stdout.write(text)
        def flush(self):
            self.original_stdout.flush()

    redirector = OutputRedirector(os.path.dirname(__file__) + "/azumaril_log.txt")
    sys.stdout = redirector

    cert_file = os.path.dirname(__file__) + '/static/certificate.crt'
    key_file = os.path.dirname(__file__) + '/static/private.key'
    if getattr(sys, 'frozen', False):
        cert_file = f"{sys._MEIPASS}/static/certificate.crt"
        key_file = f"{sys._MEIPASS}/static/private.key"

    AZUMARIL_CRT_PATH = config_data.get("AZUMARIL_CRT_PATH", None)
    AZUMARIL_KEY_PATH = config_data.get("AZUMARIL_KEY_PATH", None)
    key_file = key_file if AZUMARIL_KEY_PATH is None else AZUMARIL_KEY_PATH
    cert_file = cert_file if AZUMARIL_CRT_PATH is None else AZUMARIL_CRT_PATH

    print("CERT FILE PATH")
    print(cert_file)
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print("not found a valid certificate")
        print("generating a new certificate..")
        generate_ssl_certificates(cert_file, key_file)

    # atexit: seulement en debug pour éviter de tuer des process en prod
    if DEBUG:
        atexit.register(exit_handler)

    intercept_handler = InterceptHandler()
    logging.root.setLevel(LOG_LEVEL)
    seen = set()
    for name in [
        *logging.root.manager.loggerDict.keys(),
        "gunicorn", "gunicorn.access", "gunicorn.error",
        "uvicorn", "uvicorn.access", "uvicorn.error",
    ]:
        if name not in seen:
            seen.add(name.split(".")[0])
            logging.getLogger(name).handlers = [intercept_handler]

    logger.configure(handlers=[{"sink": sys.stdout, "serialize": JSON_LOGS}])

    options = {
        'bind': '%s:%s' % ('0.0.0.0', API_PORT),
        'workers': 1,  # ou number_of_workers()
        'timeout': 120,
        'certfile': cert_file,
        'keyfile': key_file,
        "accesslog": "-",
        "errorlog": "-",
        "logger_class": StubbedGunicornLogger,
    }
    print(f"https://localhost:{API_PORT}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(options['certfile'], options['keyfile'])
    StandaloneApplication(app, options).run()

    # restore stdout
    sys.stdout = redirector.original_stdout
