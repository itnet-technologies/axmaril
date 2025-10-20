from marshmallow import Schema, fields, validate

class ThirdPartySchema(Schema):
    name = fields.Str(required=True)
    fields = fields.List(fields.Str(), required=True, validate=validate.Length(min=1))
    
class ThirdPartySchemaUpdate(Schema):
    name = fields.Str(required=False)
    fields = fields.List(fields.Str(), required=False, validate=validate.Length(min=1))
    
class ThirdPartySearchSchema(Schema):
    name = fields.Str(required=True)
    page = fields.Int(required=False)
    per_page = fields.Int(required=False)