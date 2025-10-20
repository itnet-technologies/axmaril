# axmaril
AXMARIL is a secure secret management and access control platform developed by ITNET TECHNOLOGIES. Designed for enterprises and DevSecOps teams, it enables secure storage, sharing, and auditing of API keys, certificates, passwords, and other sensitive data.

🚀 Key Features:
✅ Centralized secret management
✅ Integration with OpenID Connect (OIDC)
✅ Access logging and audit trails
✅ Advanced encryption for maximum security
✅ CLI interface for automation

🔗 Check out the project on GitHub: AXMARIL on GitHub


## 🚀 Installation

### 1️⃣ Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **Ubuntu/Debian** or any system using `apt`

### 2️⃣ Clone the repository

```bash
git clone https://github.com/itnet-technologies/axmaril.git
cd axmaril/AXMARIL


3️⃣ Create and activate a virtual environment

python3 -m venv env
source env/bin/activate
pip install -r requirements.txt


⚙️ Running AXMARIL

🖥️ Terminal 1 — Start the main service

python app.py


⚙️ Terminal 2 — Initialize and configure

###Execute the following commands in order:


python app.py --init
python app.py --add-config -file static/config.json
python app.py --unseal

🔐 Environment Variables

#Set the AXMARIL key:

echo 'export AZUMARIL_KEYS="replace_with_your_key"' >> ~/.bashrc
source ~/.bashrc


###Set the internal database path:

export AZUMARIL_INITIATOR_DBPATH="/home/ubuntu/.azumaril_database"


###Reload your environment if necessary:


source ~/.bashrc




🧰 Common Commands


| Command | Description |
|----------|-------------|
| `python app.py` | Start the main service |
| `python app.py --init` | Initialize Axmaril |
| `python app.py --add-config -file static/config.json` | Add configuration file |
| `python app.py --unseal` | Unseal the module |
| `echo 'export AZUMARIL_KEYS="key"' >> ~/.bashrc` | Set access key |
| `export AZUMARIL_INITIATOR_DBPATH="..."` | Set local database path |
----------------------------------------------------------------------------------


📜 License

This project is licensed under the MIT License (or Apache 2.0, depending on your chosen license file).

👥 Authors

ITNET Technologies
📧 contact@axmaril.com

🌐 https://itnet-technologies.com

🤝 Contributing

Contributions are welcome!
Please open an issue or submit a pull request to suggest improvements or report bugs.
