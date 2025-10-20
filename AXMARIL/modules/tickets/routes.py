import traceback
from datetime import datetime, timedelta
from modules.tickets.utils import  upload_files
from modules.tickets.features import Ticket, Comment
from modules.ldapauth import users
from threading import Thread
from flask import request, jsonify
from modules.required_packages import (
    success_response, error_response, db002, Blueprint, get_userid_by_token, mail_sender,
    check_date_format, isAdmin
)


TICKET_REQUEST = Blueprint("ticket", __name__)

tickets = db002["tickets"]
comments = db002["comments"]
support_mail = ["mbankole@axe-tag.com", "backend@axe-tag.fr", "frontend@axe-tag.fr"]

@TICKET_REQUEST.route("/create", methods=["POST"])
def create_ticket():
    try:
        title = request.form.get("title")  
        description = request.form.get("description")
        type = request.form.get("type")
        files = request.files.getlist('files')
        today = datetime.now()

        objects = upload_files(files)

        user_info = users.find_one({"uid": get_userid_by_token()})

        send_new_ticket = Ticket()

        send_new_ticket.create_ticket(title, description, type, objects, user_info["email"], today, None, None, "open")

        ticket_dict = send_new_ticket.to_dict()
        
        tickets.insert_one(ticket_dict)

        client = user_info['email']
        objet = "NOUVEAU TICKET ALTARA"
        message = f"Cher {user_info['email']},\nVous avez ajouté un nouveau ticket. Votre demande est en cours de traitement. Merci"

        Thread(target=mail_sender, args=(
                client, objet, message,True,)).start()

        for user in support_mail:
            client = user
            objet = "ALERTE NOUVEAU TICKET ALTARA"
            message = f"Cher {user},\nUn nouveau ticket a été ajouté par le client {user_info['email']}. Veuillez le consultez.\nNB: Prenez soin de l'assigner ou de le résoudre."
                    
            Thread(target=mail_sender, args=(
                    client, objet, message,True,)).start()

        return success_response(message="successfully created")
        
    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"Something went wrong. {e}")


@TICKET_REQUEST.route("/stories", methods=["GET"])
def get_all_tickets():
    try:
        start = int(request.args.get("start", 0))
        end = int(request.args.get("end", 0))

        start_date_str = request.args.get("start_date", None)
        end_date_str = request.args.get("end_date", None)

        if start_date_str and not check_date_format(start_date_str):
            return jsonify({
                "status" : "failed",
                "message" : "Invalid start_date format. Use YYYY-MM-DD"
                }),400

        if end_date_str and not check_date_format(end_date_str):
            return jsonify({
                "status" : "failed",
                "message" : "Invalid start_date format. Use YYYY-MM-DD"
            }),400

        status_choice = request.args.get("status", None)

        filter_start_date = datetime.strptime(start_date_str, "%Y-%m-%d") if start_date_str else None
        filter_end_date = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1) if end_date_str else None

        filter_criteria = {}

        if filter_start_date and filter_end_date:
            filter_criteria["createdAt"] = {
                "$gte": filter_start_date,
                "$lt": filter_end_date
            }
        
        if status_choice:
            filter_criteria["status"] = status_choice

        fuser = users.find_one({"uid": get_userid_by_token()})

        isAdmin(get_userid_by_token())
        
        if  isAdmin(get_userid_by_token()) == True:
            all = list(tickets.find(filter_criteria, {"_id":0}).skip(start).limit(end))
        else:
            filter_criteria["createdBy"] = fuser["email"]
            all = list(tickets.find(filter_criteria, {"_id":0, "attachment":0}).skip(start).limit(end))
        return success_response(data=all)
    
    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")


@TICKET_REQUEST.route("/<string:ticket_id>", methods=["GET"])
def get_one_ticket(ticket_id):
    try:
        fuser = users.find_one({"uid":get_userid_by_token()})

        start = int(request.args.get("start", 0))
        end = int(request.args.get("end", 0))
        
        if isAdmin(get_userid_by_token()) == True:
            ticket = tickets.find_one({"id": ticket_id}, {"_id":0})
        else:
            ticket = tickets.find_one({"createdBy": fuser["email"], "id": ticket_id}, {"_id":0})
        
        if ticket is not None:
            fcomments = list(comments.find({"ticketId": ticket_id}, {"_id":0}).skip(start).limit(end).sort("createdAt", -1))
            response = {
                "id": ticket["id"],
                "title": ticket["title"],
                "description": ticket["description"],
                "type": ticket["type"],
                "createdBy": ticket["createdBy"],
                "createdAt": ticket["createdAt"],
                "assignee": ticket["assignee"],
                "messages": fcomments,
                "resolution": ticket["resolution"],
                "status": ticket["status"],
                "links": ticket["attachment"]
            }
       
            return success_response(data=response)
        return error_response(message="Ticket not found", code=404)
    
    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")


@TICKET_REQUEST.route("/assign", methods=["PUT"])
def assign_ticket_to_user():
    try:
        data = request.get_json(force=True)
        
        check_user = users.find_one({"email": data["email"]})
        
        if isAdmin(get_userid_by_token()) == False:
            return error_response(message="unauthorized", code=403)
        
        if isAdmin(check_user["uid"]) == False:
            return error_response(message="This user not allowed to resolve ticket")
             
        existing = tickets.find_one({"id": data["ticket_id"]})

        if existing is None:
            return error_response(message="Ticket not found", code=404)

        if existing["status"] == "closed":
            return error_response(message="You cannot assign closed ticket")
        
        to_update = {
            "assignee": data["email"],
            "status": "progress"
        }
        
        result = tickets.update_one({"id": data["ticket_id"]}, {"$set": to_update})
        if result:
            client = data["email"]
            objet = "ASSIGNATION TICKET ALTARA"
            message = f'Type: {existing["type"]} \nFrom: {existing["createdBy"]} \nDescription: {existing["description"]}'

            Thread(target=mail_sender, args=(
                    client, objet, message,True,)).start()

            return success_response(message="successfully assigned")
        else:
            return error_response(message="assign failed")
            
    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")


@TICKET_REQUEST.route("/assign/me", methods=["GET"])
def assign_ticket_to_me():
    try:
        start = int(request.args.get("start", 0))
        end = int(request.args.get("end", 0))

        fuser = users.find_one({"uid": get_userid_by_token()})

        if isAdmin(get_userid_by_token()) == False:
            return error_response(message="unauthorized", code=403)

        all = list(tickets.find({"assignee": fuser["email"]}, {"_id":0}).skip(start).limit(end))
        return success_response(data=all)
    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")


@TICKET_REQUEST.route("/<string:ticket_id>/answer", methods=["POST"])
def answer_ticket(ticket_id):
    try:
        
        ticket = tickets.find_one({"id": ticket_id})
        creation_date = datetime.utcnow()  
        content = request.form.get("content")
        files = request.files.getlist('files')
        
        if ticket is None:
            return error_response(message="Ticket not found", code=404)
        
        if ticket["status"] == "closed":
            error_response(message="You can no longer send messages because this ticket is closed.")
        
        sender = users.find_one({"uid": get_userid_by_token()})

        if ticket["createdBy"] == sender["email"] or ticket["assignee"] == sender["email"]:

            objects = upload_files(files)

            send_new_comment = Comment()
            send_new_comment.new_comment(content, objects, sender["email"], sender["firstname"], sender["lastname"], ticket_id, datetime.now())

            comment_dict = send_new_comment.to_dict()
            comments.insert_one(comment_dict)

            if ticket["createdBy"] == sender["email"]:
                client, objet, message = ticket["assignee"], "REPONSE TICKET", "Vous avez reçu un message"
                Thread(target=mail_sender, args=(
                        client, objet, message,True,)).start()
            
            if ticket["assignee"] == sender["email"]:
                client, objet, message = ticket["createdBy"], "REPONSE TICKET", "Vous avez reçu un message"
                Thread(target=mail_sender, args=(
                        client, objet, message,True,)).start()
                
            return success_response(message="successfully sent")
        return error_response(message="unauthorized", code=403)
    
    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")


@TICKET_REQUEST.route("/mark", methods=["PUT"])
def resolve_ticket():
    try:
        data = request.get_json(force=True)

        fuser = users.find_one({"uid": get_userid_by_token()})

        if isAdmin(get_userid_by_token()) == False:
            return error_response(message="unauthorized", code=403)
        
        ticket = Ticket()
        response = ticket.marked(data["ticket_id"], fuser["email"], data["resolution"])

        existing = ticket.get_ticket_with_id(data["ticket_id"])
    
        if response == True:
            client = existing["createdBy"]
            objet = "RESOLUTION TICKET ALTARA"
            message = f"Cher {existing['createdBy']},\nVotre ticket '{existing['title']}' a été résolu. Veuillez contacter {existing['assignee']} pour plus d'informations."

            Thread(target=mail_sender, args=(
                    client, objet, message,True,)).start()

            for user in support_mail:
                client = user
                objet = "RESOLUTION TICKET ALTARA"
                message = f"Cher {user},\nLe ticket suivant: '{existing['title']}' est résolu. Voir la description: {existing['resolution']}"

                Thread(target=mail_sender, args=(
                        client, objet, message,True,)).start()
    
            return success_response(message="Successfully resolved")
        else:
            return error_response(message="Resolved failed")

    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")


@TICKET_REQUEST.route("/<string:ticket_id>/close", methods=["PUT"])
def close_ticket(ticket_id):
    try:
        fuser = users.find_one({"uid": get_userid_by_token()})

        if isAdmin(get_userid_by_token()) == False:
            return error_response(message="unauthorized", code=403)
        
        ticket = Ticket()
        response = ticket.closed_ticket_with_id(ticket_id, fuser["email"])

        existing = ticket.get_ticket_with_id(ticket_id)

        contacts = [existing["createdBy"], fuser["email"]]

        if response == True:
            for receiver in contacts:
                client = receiver
                objet = "FERMETURE TICKET ALTARA"
                message = f"Le ticket '{existing['title']}' est fermé. Contactez {existing['assignee']} pour plus d'informations."

                Thread(target=mail_sender, args=(
                        client, objet, message,True,)).start()

            return success_response(message="successfully closed")
        else:
            return error_response(message="closing failed")

    except Exception as e:
        print(traceback.format_exc())
        return error_response(message=f"something went wrong {e}")

