from marshmallow import Schema, fields, validate


class RightSchema(Schema):
    read = fields.Boolean(required=True)
    write = fields.Boolean(required=True)
    delete = fields.Boolean(required=True)
    share = fields.Boolean(required=True)

class RightUpdateSchema(Schema):
    rights = fields.Nested(RightSchema, required=True)
    police_id = fields.String(required=False, missing=None)
    

class ReceptorSchema(Schema):
    receiver = fields.String(required=True)
    rights = fields.Nested(RightSchema, required=True)
    police_id = fields.String(required=False, missing=None)
    receiver_type = fields.String(required=True)

class AddUsersSchema(Schema):
    receptors = fields.List(fields.Nested(ReceptorSchema) , required=True, validate=validate.Length(min=1))

class SharedSafeSchema(Schema):
    shared_safe_id = fields.Str(dump_only=True)
    safe_id = fields.Str(required=True)
    owner_uid = fields.Str(required=True)
    receptors = fields.List(fields.Nested(ReceptorSchema) , required=True, validate=validate.Length(min=1))
    created_at = fields.Date(dump_only=True)