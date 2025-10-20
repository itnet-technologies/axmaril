from marshmallow import Schema, fields, validate

class GuacamoleSchema(Schema):
    app_id = fields.Str(dump_only=True)
    app_name = fields.Str(required=True)
    app_type = fields.Str(required=True)
    app_icon_path = fields.Str(required=False)
    app_fields = fields.Dict(required=True, validate=validate.Length(min=1))
    creation_date = fields.Date(dump_only=True)


class GuacamoleUpdateSchema(Schema):
    app_name = fields.Str(required=False)
    app_type = fields.Str(required=False)
    app_icon_path = fields.Str(required=False)
    app_fields = fields.Dict(required=False)


class GuacamoleSearchSchema(Schema):
    app_name = fields.Str(required=True)
    page = fields.Int(required=False)