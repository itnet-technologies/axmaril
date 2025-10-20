from marshmallow import Schema, fields, validate

class CaCertificateModifySchema(Schema):
    key_secret_id = fields.Str(required=True)
    cert_secret_id = fields.Str(required=True)
    secret_name = fields.Str(required=True)
    safe_id = fields.Str(required=True)
    country_name = fields.Str(required=False)
    locality = fields.Str(required=False)
    organization = fields.Str(required=False)
    common_name = fields.Str(required=False)
    organizational_unit = fields.Str(required=False)
    validity_days =fields.Str(required=False)
    
class CaRevokeSchema(Schema):
    secret_id = fields.Str(required=True)
    root_ca_key_id = fields.Str(required=True)
    root_ca_cert_id = fields.Str(required=True)
    revocation_reason = fields.Str(required=False)
    
class CaSignSchema(Schema):
    secret_id_cert = fields.Str(required=True)
    secret_id_ca = fields.Str(required=True)
    
class CaprivatekeySchema(Schema):
    safe_id = fields.Str(required=True)
    
class CaFindKeySckhema(Schema):
    certificate_type = fields.Str(required=True)
