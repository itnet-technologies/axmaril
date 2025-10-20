import traceback
from datetime import datetime, timedelta
from modules.required_packages import (success_response, error_response, db002, ObjectId)

tickets = db002["tickets"]

class Ticket:
    def create_ticket(self, title, description, type, attachment, createdBy, createdAt, assignee, resolution, status):
        self.id = str(ObjectId())
        self.title = title
        self.description = description
        self.type = type
        self.attachment = attachment
        self.createdBy = createdBy
        self.createdAt = createdAt
        self.assignee = assignee
        self.resolution = resolution
        self.status = status
    
    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "type": self.type,
            "attachment": self.attachment,
            "createdBy": self.createdBy,
            "createdAt": self.createdAt,
            "assignee": self.assignee,
            "resolution": self.resolution,
            "status": self.status
        }
    
    def marked(self, ticketId, email, resolution):
        existing = tickets.find_one({"id": ticketId, "assignee": email})

        if existing is None:
            return error_response(message="Ticket not found", code=404)

        if existing["status"] != "closed":
            return error_response(message="This ticket is not closed, so you cannot resolve it.")

        to_update = {
            "resolution": resolution,
            "status": "resolved"
        }

        tickets.update_one({"id": ticketId}, {"$set": to_update})
        return True
    
    def get_ticket_with_id(self, ticketId):
        existing = tickets.find_one({"id": ticketId}, {"_id":0})
        return existing
    
    def closed_ticket_with_id(self, ticketId, email):
        existing = tickets.find_one({"id": ticketId, "assignee": email})

        if existing is None:
            return error_response(message="Ticket not found", code=404)
        
        if not existing:
            return error_response(message="unauthorized", code=403)

        if existing["status"] != "progress":
            return error_response(message="This ticket is not assigned, so you can't close it.")
        
        tickets.update_one({"id": ticketId}, {"$set": {"status": "closed"}})
        return True


class Comment:
    def new_comment(self, content, attachment, sender, firstname, lastname, ticketId, createdAt):
        self.id = str(ObjectId)
        self.content = content
        self.attachment = attachment
        self.sender = sender
        self.firstname = firstname
        self.lastname = lastname
        self.ticketId = ticketId
        self.createdAt = createdAt
    
    def to_dict(self):
        return {
            "id": self.id,
            "content": self.content,
            "attachment": self.attachment,
            "sender": self.sender,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "ticketId": self.ticketId,
            "createdAt": self.createdAt
        }


