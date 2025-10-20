import pymongo
client = pymongo.MongoClient("mongodb://localhost:27017")
dbname = str(input("Enter database name"))
db001 = client[dbname]
uid = str(input("Enter altara user uid : "))
col = db001["users"]
n = 0
col.update_one(
    {"uid" : uid},
    {
        "$set" : {
            "app" : "altara",
            "is_activated" : True
        }
    }
)
print("done")