from marshmallow import Schema, fields, post_load


class SshSchema(Schema):
    hostname = fields.Str(required=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class SshEventSessionSchema(Schema):
    event_data = fields.Str(required=True)
    event_time = fields.Date(dump_only=True)

class SshSessionSchema(Schema):
    session_id = fields.Str(dump_only=True)
    secret_id = fields.Str(required=True)
    owner_uid = fields.Str(required=True)
    is_active = fields.Bool(default=True)
    email = fields.Str(required=True)
    status = fields.Str(required=True)
    start_time = fields.Date(dump_only=True)
    end_time = fields.Date(dump_only=True)
    creation_date = fields.Date(dump_only=True)
    events = fields.List(fields.Nested(SshEventSessionSchema), default=[])
    

