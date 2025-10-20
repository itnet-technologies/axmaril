from marshmallow import Schema, fields, validate

class CoffreSchema(Schema):
    safe_id = fields.Str(dump_only=True)
    name = fields.Str(required=True)
    creation_date = fields.Date(dump_only=True)

class CoffreUpdateSchema(Schema):
    name = fields.Str(required=True)