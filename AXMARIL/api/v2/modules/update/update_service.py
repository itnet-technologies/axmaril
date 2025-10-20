from .update_model import BulkModel
from .update_schema import BulkSchema
from ...utils.helpers import send_emails_in_batches, check_date_format, isAdmin
from ...database.db_manager import DBManager
from datetime import datetime
from ...utils.custom_exception import SomethingWentWrong, InsufficientRight

db_manager = DBManager()


class BulkService:
    def __init__(self):
        self.bulk_model = BulkModel()
        self.bulk_schema = BulkSchema()
    
    def create_bulk_email(self, data):
        uid = data["owner_uid"]

        if not isAdmin(uid):
            raise InsufficientRight("Unauthorized. Please contact admin.")
        
        start_date = data["start_date"]
        end_date = data["end_date"]

        if not check_date_format(start_date):
            raise SomethingWentWrong("Invalid start_date format. Use YYYY-MM-DD")

        if not check_date_format(end_date):
            raise SomethingWentWrong("Invalid start_date format. Use YYYY-MM-DD")
    
        data["reason"] = data["reason"]
        data["start_date"] = start_date
        data["end_date"] = end_date    
        data["created_at"] = datetime.now()
        
        users = db_manager.find_many("users", {}, {"email":1})
        
        emails = [user['email'] for user in users]
        
        send_emails_in_batches(emails, start_date, end_date, data["reason"])
        
        return self.bulk_model.create_bulk(data)
    
    def find_all_bulk(self, uid):
        if not isAdmin(uid):
            raise InsufficientRight("Unauthorized. Please contact admin.")
        all_bulk = self.bulk_model.find_bulk_by_uid(uid)
        return all_bulk

        

