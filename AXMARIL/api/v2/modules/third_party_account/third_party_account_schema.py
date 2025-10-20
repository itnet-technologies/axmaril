from marshmallow import Schema, fields, validate

class ThirdPartyAccountSchema(Schema):
    third_party_id = fields.Str(required=True)
    name = fields.Str(required=False)
    fields = fields.Dict(required=True, validate=validate.Length(min=1))
    
class ThirdPartyAccountSchemaUpdate(Schema):
    name = fields.Str(required=False)
    account_id = fields.Str(required=True)
    fields = fields.Dict(required=True, validate=validate.Length(min=1))
    
class ThirdPartyAccountSearchSchema(Schema):
    name = fields.Str(required=True)
    page = fields.Int(required=False)
    per_page = fields.Int(required=False)

class CyberArkCheck(Schema):
    account_id = fields.Str(required=True)

class CyberArkSafes(Schema):
    safeName = fields.Str()
    safeUrlId = fields.Str()

class CyberArkSecrets(Schema):
    accounts = fields.List(fields.Dict())
    safeName = fields.Str()
    safeUrlId = fields.Str()

class ImportSafeFromCyberArk(Schema):
    cyberark_safe_id = fields.Str(required=True)
    safe_id = fields.Str(required=False)
    safe_name = fields.Str(required=False)
    account_id = fields.Str(required=True)

class ImportSecretFromCyberArk(Schema):
    cyberark_secret_id = fields.Str(required=True)
    safe_id = fields.Str(required=True)
    account_id = fields.Str(required=True)
    new_secret_name = fields.Str(required=False)

class Synchronization(Schema):
    safe_id = fields.Str(required=True)
    account_id = fields.Str(required=True)
    force = fields.Bool(required=False)