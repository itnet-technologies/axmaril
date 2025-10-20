from marshmallow import Schema, fields, validate

class GroupSchema(Schema):
    group_id = fields.Str(dump_only=True)
    group_name = fields.Str(required=True)
    group_members = fields.List(fields.Str(), required=True, validate=validate.Length(min=1))
    owner_uid = fields.Str(required=True)
    created_at = fields.Date(dump_only=True)

class AddMemberSchema(Schema):
    group_members = fields.List(fields.Str(), required=True, validate=validate.Length(min=1))

class GroupSchemaUpdate(Schema):
    group_name = fields.Str(required=False, missing=None)
    # group_members = fields.List(fields.Str(), required=True, validate=validate.Length(min=1))