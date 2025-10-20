import pymongo, time
from pprint import pprint
from datetime import datetime, timedelta

client = pymongo.MongoClient(host="0.0.0.0", port=27017)
# db001 = client["db001"]
db002 = client["db002"]

# collections = db002.list_collection_names()
# pprint(collections)

# policies = list(db002["users"].find())

shared_safe = list(db002["shared_safe"].find())

receiver_safe = list(db002["receiver_safes"].find())


# print("*"*20)
# print("users collection\n")
# print("*"*20)

# for policy in policies:
#     pprint(policy, indent=2)

print("*"*20)
print("shared safe collection\n")
print("*"*20)

for safe in shared_safe:
    pprint(safe, indent=2)

# db002["shared_safe"].delete_one({"shared_safe_id": "67e41ec5fee021e2c41405c4"})
# uids = ["0000283", "0000284", "0000282", "0000281", "0000113", "0000278"]
# db002["receiver_safes"].delete_many({"uid": {"$in": uids}})
# db002["receiver_safes"].delete_one({"uid": "0000284"})

# 67c8615575eada9f019ec06a

# print("*"*20)

print("*"*20)
print("receiver safe collection\n")
print("*"*20)

rights = []
for safe in receiver_safe:
    rights.append(safe["rights"])
    pprint(safe, indent=2)



# def check_duplicate_members(share_data, groups_data):
#     from collections import defaultdict
    
#     share_group_key, group_name_key = "receiver", "group_name"
    
#     groups_dict = {group[group_name_key]: group for group in groups_data if group_name_key in group}
#     member_groups = defaultdict(set)
    
#     for receiver in share_data: #.get("receptors", []):
#         if receiver.get("share_mode") == "group":
#             group_name = receiver.get(share_group_key)
#             group_data = groups_dict.get(group_name)
            
#             if group_data:
#                 for member in group_data.get("group_members", []):
#                     member_mail = member.get("email")
#                     if member_mail:
#                         member_groups[member_mail].add(group_name)
    
#     duplicates = {mail: groups for mail, groups in member_groups.items() if len(groups) > 1}  
    
#     if duplicates:
#         raise ValueError(f"users are present in more than one group : {duplicates}")
    
#     return "no duplicates found" 


# groups = list(db002["groups"].find({"owner_uid": "0000257"}))

# shared = {
#   "safe_id": "6691257ebe9622e90a063f2f",
#   "receptors": [
#     {
#       "receiver": "group01",
#       "rights": {
#         "read": False,
#         "write":False,
#         "delete": False,
#         "share": False
#       },
#       "police_id": "67bc87c6f5a333dab3419e89",
#       "share_mode": "group"
#     },
# {
#       "receiver": "group03",
#       "rights": {
#         "read": False,
#         "write": False,
#         "delete": False,
#         "share": False
#       },
#       "police_id": None,
#       "share_mode": "group"
#     }
#   ]
# }

# try:
#     print(check_duplicate_members(shared["receptors"], groups))
# except ValueError as e:
#     print(f"Erreur: {e}")

# db002["receiver_safes"].delete_one({"uid": "0000113"})



# print("*"*20)    
#user = list(db002["users"].find())

#user = db002["users"].find_one({"email": "fibim16283@bitflirt.com"})
#pprint(user)

#pprint(user)
"""
hngoune55@gmail.com
aogoula@axe-tag.com
duponjean559@gmail.com

collections = db002.list_collection_names()
# Fonction pour vérifier les champs dans une collection
def check_and_delete_fields(collection, delay_seconds=0):
    sample_doc = db002[collection].find_one()
    if sample_doc:
        has_uid = 'uid' in sample_doc
        has_owner_uid = 'owner_uid' in sample_doc
        has_mail = 'mail' in sample_doc
        has_email = 'email' in sample_doc
        
        if delay_seconds > 0:
            time.sleep(delay_seconds)

        if has_uid and has_owner_uid:
            db002[collection].delete_many({'$or': [{'uid': {'$exists': True}}, {'owner_uid': {'$exists': True}}]})
        elif has_mail and has_email:
            db002[collection].delete_many({'$or': [{'mail': {'$exists': True}}, {'email': {'$exists': True}}]})
        elif has_mail:
            db002[collection].delete_many({'mail': {'$exists': True}})
        elif has_email:
            db002[collection].delete_many({'email': {'$exists': True}})
        elif has_uid:
            db002[collection].delete_many({'uid': {'$exists': True}})
        elif has_owner_uid:
            db002[collection].delete_many({'owner_uid': {'$exists': True}})
            
        return has_uid, has_owner_uid, has_mail, has_email
    return False, False, False, False

# Dictionnaires pour stocker les collections en fonction des champs
collections_with_uid = []
collections_with_owner_uid = []
collections_with_mail = []
collections_with_email = []
collections_with_both = []

# Parcourez chaque collection et vérifiez les champs
for collection in collections:
    has_uid, has_owner_uid, has_mail, has_email = check_and_delete_fields(collection)
    if has_uid and has_owner_uid:
        collections_with_both.append(collection)
    elif has_uid:
        collections_with_uid.append(collection)
    elif has_owner_uid:
        collections_with_owner_uid.append(collection)
    elif has_email:
        collections_with_email.append(collection)
    elif has_mail:
        collections_with_mail.append(collection)

# Affichez les résultats
print("Collections with 'uid':")
for collection in collections_with_uid:
    print(collection)

print("\nCollections with 'owner_uid':")
for collection in collections_with_owner_uid:
    print(collection)

print("\nCollections with 'mail':")
for collection in collections_with_mail:
    print(collection)

print("\nCollections with 'email':")
for collection in collections_with_email:
    print(collection)

print("\nCollections with both 'uid' and 'owner_uid':")
for collection in collections_with_both:
    print(collection)
 """   
# sessions = list(db002["sshsession"].find())
<<<<<<< HEAD
# db002["sshsession"].delete_one({"session_id": "666ad401042cfbab44a75093"})
=======
# db002["shared_safe"].delete_one({"shared_safe_id": "67adcb4e1de509420a06cd92"})
>>>>>>> b51febe7bf1fed5070ed5a429ff36eb9fa4922f4
# print(sessions)

# secrets = list(db002["secrets"].find({"auto_remove": "false"}))
# db002["secrets"].delete_one({"auto_remove": "true"})
# print(secrets)

# histories = list(db002["propagate_history"].find())
# print(histories)


#db002["secret-v2"].delete_one({"app_type": "ssh",  "secret_id": "66434a243bc19891e17b88d0"})


# shared = list(db002["shared-v2"].find({"shared_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzZWNyZXRfaWQiOiI2NjU5YjRjZjg0ZmJlZDA1YmQxYzFjNTciLCJyZWNldmVpcl9lbWFpbCI6ImFhZGppbW9uQGF4ZS10YWcuZnIifQ.SZStjV92d4fC7w2sywzBDfdl3MC8OYJox2IpZSUgemI"}))
# print(shared)

#print("Heure Locale: ", datetime.now() + timedelta(minutes=10))
#print("Heure universelle: ", datetime.utcnow())

# d = db002["subscriptions"].find({"sub_id" : "66799d8145ba597c4968c8ac"}, {"_id" : 0})
# for i in list(d):
#    print(json.dumps(i, indent = 2))


# token = db002["sshsession"].find_one({"session_id": "669138bdbaec89a16fa70c9f"})
# db002["sshsession"].update_one({"session_id": "669138bdbaec89a16fa70c9f"}, {"$set": {"status": "active"}})
# print(token)

# session = list(db002["sshsession"].find())
# print(session)

#user = db002["users"].find_one({"user_uid": "0000257"})
#users = list(db002["users"].find())
#collections = list(db002.list_collection_names())
#print(collections)
#print(users)

# tickets = list(db001.list_collection_names())
#[print(elt) for elt in tickets]

# payments = list(db001["fedapay"].find())
# [print(payment) for payment in payments] del1@gmail.com

#user = db002["users"].update_one({"uid": "0000259"}, {"$set": {"marked_for_deletion": True}})
#print(user)

<<<<<<< HEAD
db002["shared-v2"].drop()
#token = db002["tokens"].find_one({"user_uid": "0000263"})
#print(token)
=======
# db002["shared-v2"].drop()
#token = db002["tokens"].find_one({"user_uid": "0000263"})
#print(token)


"""rights = {"read": True, "create": False, "update": False}

user_mode = ["one_user", "group_user"]

safes = [
      {
        "date": "Fri, 12 Jul 2024 14:45:50 GMT",
        "name": "test",
        "owner_uid": "0000257",
        "safe_id": "6691257ebe9622e90a063f2f",
        "share_info": None,
        "total_secrets": 1
      },
      {
        "created_by": "user",
        "creation_date": "Fri, 12 Jul 2024 14:01:43 GMT",
        "from": "azumarill",
        "name": "Naudtest",
        "owner_uid": "0000257",
        "safe_id": "66913747e1fcbea1d4a70c98",
        "share_info": None,
        "total_secrets": 0
      },
      {
        "date": "Thu, 15 Aug 2024 17:06:15 GMT",
        "name": "test01",
        "owner_uid": "0000257",
        "safe_id": "66be196739244488495f7318",
        "share_info": None,
        "total_secrets": 0
      }
    ]"""

"""data = {
    "safe_id": "6691257ebe9622e90a063f2f",
    "user_mode": user_mode[1],
    "receivers": ["x@axe-tag.fr"],
    "rights": rights
}

print(len(data["receivers"]))

def add_right(data):
    if data["user_mode"] == user_mode[0] and len(data["receivers"])==1:
        data = {
            "safe_id": data["safe_id"],
            "user_mode": user_mode[0],
            "receivers":
                {
                    "identity": data["receivers"][0],
                    "rights": rights
                },
        }
    elif data["user_mode"] == user_mode[1] and len(data["receivers"])>1:
        data = {
            "safe_id": data["safe_id"],
            "user_mode": user_mode[1],
            "receivers": data["receivers"],
            "rights": rights
        }
    else:
        print("review data")
    
    return data


response = add_right(data)

print(response)"""
>>>>>>> b51febe7bf1fed5070ed5a429ff36eb9fa4922f4
