from marshmallow import Schema, fields, validate


class SharedSchema(Schema):
    shared_id = fields.Str(dump_only=True)
    secret_id = fields.Str(required=True)
    receiver = fields.Email(required=True)
    receivers = fields.List(fields.Str(), required=False, validate=validate.Length(min=1))
    duration = fields.Int(required=False)
    is_valid = fields.Bool(default=True)
    owner_uid = fields.Str(required=True)
    shared_token = fields.Str(required=False)
    shared_link = fields.Str(required=False)
    created_at = fields.Date(dump_only=True)
    last_used_at = fields.Date(dump_only=True)
    expire_at = fields.Date(dump_only=True)
    use_count = fields.Date(dump_only=True)
