from .ssh_model import SshSessionModel
from .ssh_schema import SshSessionSchema, SshEventSessionSchema
import json
from ...utils.custom_exception import NotFoundException, InsufficientRight, SomethingWentWrong
from ...utils.helpers import isAdmin, Blacklisted, save_ssh_response
from datetime import datetime


class SshSessionService:
    def __init__(self):
        self.ssh_session_model = SshSessionModel()
        self.ssh_session_schema = SshSessionSchema()
        self.ssh_event_schema = SshEventSessionSchema()
    
    def create_session(self, uid, email, secret_id):
        data = {
            'secret_id': secret_id,
            'owner_uid': uid,
            'status': 'active',
            'is_active': True,
            'email': email,
            'start_time': datetime.now(),
            'end_time': datetime.now(),
            'creation_date': datetime.now(),
            'events': []   
        }
        return self.ssh_session_model.create_ssh_session(data)
    
    def update_session(self, session_id, data, event_response):
        print(data)
        event = {
            "event_time": datetime.now(),
            "event_data": data,
            "event_response": event_response
        }

        event_query = {"events": event}
        end_time = {"end_time": datetime.now()}

        self.ssh_session_model.update_ssh_session(session_id, end_time, event_query)

    def ssh_response(self, command):
        output, error = save_ssh_response(command)
        if output: 
            return output
        else: 
            return error
    
    def update_state(self, session_id, data):
        self.ssh_session_model.update_session(session_id, data)
    
    
    def find_one_session(self, session_id):
        session = self.ssh_session_model.find_by_id(session_id)
        if not session:
            raise NotFoundException('Session not found')
        return session

    def find_session_by_id(self, uid, session_id):
        session = self.ssh_session_model.find_by_id(session_id)
        existing_session = self.ssh_session_model.find_session_by_id(uid, session_id)
        
        if isAdmin(uid):
            if not session:
                raise NotFoundException('Session not found')
            return session
        else:
            if not existing_session:
                raise NotFoundException('Session not found')
            return existing_session
    
    def find_session_by_uid(self, uid):
        return self.ssh_session_model.find_ssh_session_by_uid(uid)
    
    def unlocked_user(self, uid, session_owner):
        """session_owner: pass session owner uid"""
        if isAdmin(uid):
            Blacklisted(session_owner, is_denied=False)
        else:
            raise InsufficientRight('You are not authorized')
    
    def find_all_sessions(self, uid, page, per_page):
        if isAdmin(uid):
            session = self.ssh_session_model.find_all_with_paginate(page, per_page)
            return session
        else:
            raise InsufficientRight('You are not authorized')
    
    def delete_session(self, uid, session_id):
        session = self.ssh_session_model.find_by_id(session_id)
        if not session:
            raise NotFoundException('Session not found')
        
        if isAdmin(uid):
            self.ssh_session_model.delete_ssh_session(session_id)
        else:
            raise InsufficientRight('Unauthorized')



#6669a2295e849ae0b72143c7
#eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MTg4MDIzMDQsImlhdCI6MTcxODIwNDcwNCwic3ViIjoiMDAwMDIxOSJ9.pGk39aqCi_hFymQotYrmkOlicSjBZw_mDm_FzkWryTQ