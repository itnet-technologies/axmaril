from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from kmip.pie.client import ProxyKmipClient


# user_data = {
#     "COUNTRY_NAME": "FR",
#     "STATE_OR_PROVINCE_NAME": "Ile-de-France",
#     "LOCALITY_NAME": "Paris",
#     "ORGANIZATION_NAME": "MyCompany",
#     "COMMON_NAME": "mycompany.com",
#     "keyUsage" : "critical, digitalSignature, keyEncipherment",
#     "extendedKeyUsage" : "clientAuth"
# }

# oid_mapping = {
#     "COUNTRY_NAME": NameOID.COUNTRY_NAME,
#     "STATE_OR_PROVINCE_NAME": NameOID.STATE_OR_PROVINCE_NAME,
#     "LOCALITY_NAME": NameOID.LOCALITY_NAME,
#     "ORGANIZATION_NAME": NameOID.ORGANIZATION_NAME,
#     "COMMON_NAME": NameOID.COMMON_NAME
# }

# subject = issuer = x509.Name([
#     x509.NameAttribute(oid_mapping[key], value)
#     for key, value in user_data.items() if key in oid_mapping
# ])

# with open("/home/python3.10/ca_1k.pem","rb") as k:
#     ca_key = serialization.load_pem_private_key(
#         k.read(),
#         password=None,
#         )
    
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )

# cert = (
#     x509.CertificateBuilder()
#     .subject_name(subject)
#     .issuer_name(issuer)
#     .public_key(private_key.public_key())
#     .serial_number(x509.random_serial_number())
#     .not_valid_before(datetime.utcnow())
#     .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Certificat valide 1 an
#     .add_extension(
#         x509.BasicConstraints(ca=True, path_length=None), critical=True
#     )
#     .sign(ca_key, hashes.SHA256())
# )

# with open("certificate.pem", "wb") as f:
#     f.write(cert.public_bytes(serialization.Encoding.PEM))

# with open("private_key.pem", "wb") as f:
#     f.write(private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     ))

# print("✅ Certificat et clé privée générés avec succès!")

def get_kmip_client():
    return ProxyKmipClient (
        hostname="localhost",
        port= 5690,
        cert="/home/AZUMARIL/test_k/certificate.pem",
        key="/home/AZUMARIL/test_k/private_key.pem",
        ca="/home/python3.10/ca_1.pem",
        config={'tls_cipher_suites': 'ECDHE-RSA-AES256-GCM-SHA384'}
    )
    

def status_key(key_id):
    #cle_id = data.get('key_id')
    client = get_kmip_client()
    client.open()

    status = client.get_attributes(key_id, ['State'])
    print (status)
    client.close()
    state_value = status[1][0].attribute_value.value.name
    
    print(state_value)
    

status_key(key_id="2")