from marshmallow import Schema, fields, validate

class KmipKeySchema(Schema):
    #name = fields.Str(required=False)
    url = fields.Str(required=True)
    database = fields.Str(required=True)
    collection = fields.Str(required=True)

class KmipStatusSchema(Schema):
    key_id = fields.Str(required=True)
    
class KmipRevokeSchema(Schema):
    key_id = fields.Str(required=True)
    reason = fields.Str(required=True)
    secret_name = fields.Str(required=True)
    
class KmipDeleteSchma(Schema):
    key_id = fields.Str(required=True)

class KmipActivateSchema(Schema):
    key_id = fields.Str(required=True)
    
class KmipFileSchema(Schema):
    secret_name = fields.Str(required=True)
    secret = fields.Dict(required=True, validate=validate.Length(min=1))
    user_key = fields.Str(required=False)
    user_cert = fields.Str(required=False)
    safe_id = fields.Str(required=False)
    secret_type = fields.Str(required=False)
    app_type = fields.Str(required=False)
    #file_type = fields.Str(required=False)

    
    

# class SecretFileSchema(Schema):
#     secret_name = fields.Str(required=True)
#     secret = fields.Dict(required=True, validate=validate.Length(min=1))
#     safe_id = fields.Str(required=True)
#     secret_type = fields.Str(required=True)
#     owner_uid = fields.Str(required=True)
#     app_type = fields.Str(required=False)
#     file_path = fields.Str(required=False)
#     file_name = fields.Str(required=False)
#     file_type = fields.Str(required=False)
    

# class SecretCredentialSchema(SecretSchema):
#     #secret = fields.Dict(required=True, validate=validate.Length(min=1))
#     exp_time = fields.Int(required=False)
#     app_type = fields.Str(required=True)


# class SecretSshSchema(SecretCredentialSchema):
#     use_password = fields.Bool(required=False)
#     auto_generate = fields.Bool(required=False)
#     #is_blocked = fields.Bool(default=False)


# class SecretUpdateSchema(Schema):
#     secret_id = fields.Str(required=True)
#     secret_name = fields.Str(required=True)
#     secret = fields.Dict(required=True, validate=validate.Length(min=1))
#     safe_id = fields.Str(required=True)

# class SecretFileUpdateSchema(Schema):
#     secret_id = fields.Str(required=True)
#     secret_name = fields.Str(required=True)
#     secret = fields.Dict(required=True, validate=validate.Length(min=1))
#     safe_id = fields.Str(required=True)
#     app_type = fields.Str(required=True)

# class SecretUpdateSshPassword(Schema):
#     secrets = fields.Dict(required=True, validate=validate.Length(min=1))

# class SecretIdSchema(Schema):
#     secret_id = fields.Str(required=True)

