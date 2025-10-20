from marshmallow import Schema, fields, validate

class SecretSchema(Schema):
    secret_id = fields.Str(dump_only=True)
    secret_name = fields.Str(required=True)
    secret = fields.Dict(required=True, validate=validate.Length(min=1))
    safe_id = fields.Str(required=True)
    secret_type = fields.Str(required=True)
    owner_uid = fields.Str(required=True)
    #exp_time = fields.Int(required=False)
    date = fields.Date(dump_only=True)


class SecretFileSchema(Schema):
    secret_name = fields.Str(required=True)
    secret = fields.Dict(required=True, validate=validate.Length(min=1))
    safe_id = fields.Str(required=True)
    secret_type = fields.Str(required=True)
    owner_uid = fields.Str(required=True)
    app_type = fields.Str(required=False)
    file_path = fields.Str(required=False)
    file_name = fields.Str(required=False)
    file_type = fields.Str(required=False)
    secret_file = fields.Str(required=False)
    

class SecretCredentialSchema(SecretSchema):
    #secret = fields.Dict(required=True, validate=validate.Length(min=1))
    exp_time = fields.Int(required=False)
    app_type = fields.Str(required=True)


class SecretSshSchema(SecretCredentialSchema):
    use_password = fields.Bool(required=False)
    auto_generate = fields.Bool(required=False)
    #is_blocked = fields.Bool(default=False)

class SecretKmipSchema(SecretSchema):
    user_key = fields.Str(required=False)
    user_cert = fields.Str(required=False)
    app_type = fields.Str(required=True)
    
class SecretKmipIdSchema(SecretSchema):
    secret_cert_id = fields.Str(required=True)
    secret_key_id = fields.Str(required=True)
    app_type = fields.Str(required=True)

class SecretUpdateSchema(Schema):
    secret_id = fields.Str(required=True)
    secret_name = fields.Str(required=True)
    secret = fields.Dict(required=True, validate=validate.Length(min=1))
    safe_id = fields.Str(required=True)

class SecretFileUpdateSchema(Schema):
    secret_id = fields.Str(required=True)
    secret_name = fields.Str(required=True)
    secret = fields.Dict(required=True, validate=validate.Length(min=1))
    safe_id = fields.Str(required=True)
    app_type = fields.Str(required=True)

class SecretUpdateSshPassword(Schema):
    secrets = fields.Dict(required=True, validate=validate.Length(min=1))

class SecretIdSchema(Schema):
    secret_id = fields.Str(required=True)

class SecretCertificateSchema(Schema):
    safe_id = fields.Str(required=True)
    key_name = fields.Str(required=True)
    certificate_name = fields.Str(required=True)
    operation_type = fields.Str(required=True)
    certificate_type = fields.Str(required=True)
    key_secret_id = fields.Str(required=False)
    cert_secret_id = fields.Str(required=False)
    ca_key_id = fields.Str(required=False)
    ca_cert_id = fields.Str(required=False)
    country_name = fields.Str(required=False)
    locality = fields.Str(required=False)
    organization = fields.Str(required=False)
    common_name = fields.Str(required=False)
    organizational_unit = fields.Str(required=False)
    validity_days =fields.Str(required=False)
    
class CaCertificateModifySchema(Schema):
    key_secret_id = fields.Str(required=True)
    cert_secret_id = fields.Str(required=True)
    ca_key_id = fields.Str(required=True)
    ca_cert_id = fields.Str(required=True)
    certificate_type = fields.Str(required=True)
    operation_type = fields.Str(required=True)
    country_name = fields.Str(required=False)
    locality = fields.Str(required=False)
    organization = fields.Str(required=False)
    common_name = fields.Str(required=False)
    organizational_unit = fields.Str(required=False)
    validity_days =fields.Str(required=False)
    safe_id = fields.Str(required=False)
    key_name = fields.Str(required=False)
    certificate_name = fields.Str(required=False)
    
class SecretCACsrSchema(Schema):
    safe_id = fields.Str(required=True)
    certificate_name = fields.Str(required=True)
    certificate_type = fields.Str(required=True)
    operation_type = fields.Str(required=True)
    csr = fields.Str(required=True)
    key_secret_id = fields.Str(required=True)
    cert_secret_id =  fields.Str(required=True)
    
    
