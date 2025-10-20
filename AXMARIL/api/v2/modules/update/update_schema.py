from marshmallow import Schema, fields


class BulkSchema(Schema):
    bulk_id = fields.Str(dump_only=True)
    owner_uid = fields.Str(required=True)
    reason = fields.Str(required=True)
    start_date = fields.Date(dump_only=True)
    end_date = fields.Date(dump_only=True)
    created_at = fields.Date(dump_only=True)
    