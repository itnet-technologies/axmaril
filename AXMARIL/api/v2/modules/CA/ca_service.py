from ...utils.helpers import success_response, error_response, config_data, reveal_secret
from ...database.db_manager import DBManager
from datetime import datetime, timedelta
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, InsufficientRight, AttemptsExceeded, CustomException, SomethingWentWrong, KeyMissing, AttemptsExceeded, InvalidDataException, TokenInvalidError
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from .ca_model import CAModel
import base64
import uuid

ca_model = CAModel()

class CaService:
    
    def generate_private_key(sefl, data):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size= data or 2048
        )
        #print (key)
        return key
    
    def subject(self, data):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, data.get("country_name") or "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data.get("state") or "Ile-de-France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, data.get("locality") or "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, data.get("organization") or "MonAC"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, data.get("organizational_unit") or "IT"),
            x509.NameAttribute(NameOID.COMMON_NAME, data.get("common_name") or "Mon Autorité de Certification")
        ])
        return subject
    
    def generate_csr(self, private_key, data):
        """Génère un CSR (Certificate Signing Request)"""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.subject(data))
            .sign(private_key, hashes.SHA256())
        )
        return csr
    
    def create_certificate(self, data, signing_cert=None, signing_key=None): 
        if data["certificate_type"] == "root_ca":
            key_size = 4096 
            private_key = self.generate_private_key(key_size)
            subject = self.subject(data)  
            issuer = subject  
        else:
        #  Vérifier si un CSR est fourni par l'utilisateur
            if "csr" in data and data["csr"]:
                try:
                    csr_pem = data["csr"].encode()
                    csr = x509.load_pem_x509_csr(csr_pem)
                    private_key = None  # La clé privée n'est pas connue dans ce cas
                except Exception as e:
                    raise ValueError(f"Le CSR fourni est invalide : {e}")
            else:
                # 🔹 Cas 3: Générer une nouvelle clé privée et un CSR si aucun n'est fourni
                key_size = 4096 if data["certificate_type"] == "intermediate_ca" else 2048
                private_key = self.generate_private_key(key_size)
                csr = self.generate_csr(private_key, data)

            subject = csr.subject  # Récupération du subject depuis le CSR

            # Déterminer l'émetteur du certificat
            if isinstance(signing_cert, bytes):
                signing_cert = x509.load_pem_x509_certificate(signing_cert)
            issuer = signing_cert.subject
        
        
        signing_cert = x509.load_pem_x509_certificate(signing_cert)
        serial_number = signing_cert.serial_number
        issuer_signing_key = signing_cert.issuer
        root_ca_cn = issuer_signing_key.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        unique_id = str(uuid.uuid4())[:8]
        crl_url = f"localhost/{root_ca_cn}_{unique_id}_crl.pem"
        
        print("########3")
        public_key = csr.public_key() if private_key is None else private_key.public_key()
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=int(data.get("validity_days", 3650) )))
            .add_extension(
                x509.BasicConstraints(ca=(data["certificate_type"] in ["root_ca", "intermediate_ca"]), path_length=None),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH if data["certificate_type"] == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.AccessDescription(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ]),
                critical=False
            )
        )
        print("########4")
        if data["certificate_type"] == "root_ca":
            cert = cert_builder.sign(private_key, hashes.SHA256())  # Auto-signé
        elif data["certificate_type"] == "intermediate_ca":
            signing_key = serialization.load_pem_private_key(signing_key, password=None)
            #print(signing_key)
            cert = cert_builder.sign(signing_key, hashes.SHA256())  # Signé par la Root CA
        else:  # Certificat Leaf
            signing_key = serialization.load_pem_private_key(signing_key, password=None)
            cert = cert_builder.sign(signing_key, hashes.SHA256())  # Signé par la CA Intermédiaire
        print("#######5")
        cert_byte = cert.public_bytes(serialization.Encoding.PEM).decode()
        private_key_byte = None
        if private_key:
            private_key_byte = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        return private_key_byte, cert_byte
    
    def sign_certificate(self, cert_builder, ca_key):
        return cert_builder.sign(ca_key, hashes.SHA256())
    
    def modify_certificate(self, new_data):
        
        response_key = reveal_secret(new_data['key_secret_id'])
        response_cert = reveal_secret(new_data['cert_secret_id'])
        response_ca_key = reveal_secret(new_data['ca_key_id'])
        response_ca_cert = reveal_secret(new_data['ca_cert_id'])
        
        cert_pem = base64.b64decode(response_cert['cert'])
        private_key_pem = base64.b64decode(response_key['key'])
        ca_key = base64.b64decode(response_ca_key['key'])
        ca_cert = base64.b64decode(response_ca_cert['cert'])

        print("&&&&&&&&&11111111")
        ca_key = serialization.load_pem_private_key(ca_key, password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert)
        
        cert = x509.load_pem_x509_certificate(cert_pem)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        issuer_signing_key = ca_cert.issuer
        root_ca_cn = issuer_signing_key.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        unique_id = str(uuid.uuid4())[:8]
        crl_url = f"localhost/{root_ca_cn}_{unique_id}_crl.pem"
        
        if new_data.get("certificate_type") == "root_ca":
            raise ValueError(" Impossible de modifier un certificat Root CA car il est auto-signé.")
        print("ééééééééééééééé")
        csr = self.generate_csr(private_key, new_data)
        is_ca = new_data.get("certificate_type") == "intermediate_ca"
        modified_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)  # Utilisation du subject du CSR
            .issuer_name(ca_cert.subject)  # Signé par l'autorité parent (CA)
            .public_key(csr.public_key())  # Utilisation de la clé publique du CSR
            .serial_number(cert.serial_number)  # Conservation du numéro de série
            .not_valid_before(cert.not_valid_before)  # Garde la date de début
            .not_valid_after(datetime.utcnow() + timedelta(days=int(new_data.get("validity_days", 3650))))  # Mise à jour de la validité
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH if new_data.get("certificate_type") == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.AccessDescription(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ]),
                critical=False
            )
        )
        print("!!!!!!!!!!!!!!!")
        # Signature avec la clé privée de l'autorité de certification
        signed_cert = modified_cert.sign(ca_key, hashes.SHA256())
        new_cert = signed_cert.public_bytes(serialization.Encoding.PEM)
        print("ààààààààààààà")
        return new_cert
    
    def all_key(self, data):
        list_ca = []
        certificate_type = data.get('certificate_type')
        #print(f"{certificate_type}#####################")

        all_secrets = ca_model.find_secret_by_uid(data['owner_uid'])
        if certificate_type == "intermediate_ca":  # Correction ici
            list_ca = [{k: v for k, v in ca.items() if k != "secret"} 
                   for ca in all_secrets if ca.get('certificate_type') == "root_ca" and ca.get('identity') == "key"]

        elif certificate_type == "leaf_cert":
            list_ca = [{k: v for k, v in inter.items() if k != "secret"} 
                   for inter in all_secrets if inter.get('certificate_type') == "intermediate_ca" and inter.get('identity') == "key"]
        else:
            raise ValueError(f"certificate_type {data['certificate_type']} not found")
        return list_ca
    
    def all_cert(self, data):
        list_cert = []
        certificate_type = data.get('certificate_type')
        
        all_secrets = ca_model.find_secret_by_uid(data['owner_uid'])
        
        if certificate_type == "intermediate_ca":
            list_cert = [{k: v for k, v in ca.items() if k != "secret"} 
                     for ca in all_secrets if ca.get('certificate_type') == "root_ca" and ca.get('identity') == "cert"]

        elif certificate_type == "leaf_cert":
            list_cert = [{k: v for k, v in inter.items() if k != "secret"} 
                     for inter in all_secrets if inter.get('certificate_type') == "intermediate_ca" and inter.get('identity') == "cert"]
        
        else:
            raise ValueError(f"certificate_type {certificate_type} not found")
        
        return list_cert

    
    def revoke_certificate(certificate, ca_cert, ca_key, crl_file_path="crl.pem", reason=x509.ReasonFlags.unspecified):
        
        cert = x509.load_pem_x509_certificate(certificate)
        ca_cert_pem = x509.load_pem_x509_certificate(ca_cert)
        ca_key_pem = serialization.load_pem_private_key(ca_key, password=None)
        
        if cert.issuer != ca_cert.subject:
            return {"error": "Ce certificat n'a pas été émis par la Root CA"}, 400

        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            cert.serial_number
        ).revocation_date(
            datetime.utcnow()
        ).add_extension(
            x509.CRLReason(reason), critical=False
        ).build()
        
        crl = None
        try:
            with open(crl_file_path, "rb") as crl_file:
                crl_pem = crl_file.read()
                crl = x509.load_pem_x509_crl(crl_pem)
        except FileNotFoundError:
            pass
        
        if crl:
            crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
                crl.issuer
            ).last_update(
                datetime.utcnow()
            ).next_update(
                datetime.utcnow() + timedelta(days=1)
            )
            for revoked in crl:
                crl_builder = crl_builder.add_revoked_certificate(revoked)
            
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        else:
            crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
                ca_cert_pem.subject
            ).last_update(
                datetime.utcnow()
            ).next_update(
                datetime.utcnow() + timedelta(days=1)
            ).add_revoked_certificate(revoked_cert)
        
        crl = crl_builder.sign(private_key=ca_key_pem, algorithm=hashes.SHA256())
        
        with open(crl_file_path, "wb") as crl_file:
            crl_file.write(crl.public_bytes(serialization.Encoding.PEM))
    
    def revoke_cert(self, cert_pem):
        cert = x509.load_pem_x509_certificate(cert_pem)
        print(cert)
        pass


        """        def create_ca_certificate(self,data):
        ca_key = self.generate_private_key()
        print(data)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, data.get("country_name") or "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data.get("state") or "ile de france"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, data.get("locality") or "paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, data.get("organization") or "tencen"),
            x509.NameAttribute(NameOID.COMMON_NAME, data.get("common_name") or "Mon Autorité de Certification"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, data.get("organizational_unit") or "IT")
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(subject)
        ca_cert = ca_cert.issuer_name(issuer)
        ca_cert = ca_cert.public_key(ca_key.public_key())
        ca_cert = ca_cert.serial_number(x509.random_serial_number())
        ca_cert = ca_cert.not_valid_before(datetime.utcnow())
        ca_cert = ca_cert.not_valid_after(datetime.utcnow() + timedelta(days=3650))
        ca_cert = ca_cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        if data['ca'] is not None:    
            ca_cert = ca_cert.sign(data['ca'], hashes.SHA256())
            print("cle signe avec la CA partagé ")
        else:
            ca_cert = ca_cert.sign(ca_key, hashes.SHA256())
        
        ca_key_byte = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        ca_cert_byte = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        #print(ca_cert_byte)
        return ca_key_byte, ca_cert_byte
        """