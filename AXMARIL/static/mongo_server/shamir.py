from binascii import hexlify, unhexlify
import os
import traceback
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from mongita import MongitaClientDisk
import sys
import argparse
import time
import base64
import random
import string
import pathlib

AIDBPATH = os.path.join(pathlib.Path.home(), '.mongita')
if "AZUMARIL_INITIATOR_DBPATH" in os.environ:
    AIDBPATH = os.environ["AZUMARIL_INITIATOR_DBPATH"]
    if not os.path.exists(AIDBPATH):
        os.makedirs(AIDBPATH, exist_ok=True)
    
client = MongitaClientDisk(host = AIDBPATH)
shamri_db = client["shamir"]
app_state = shamri_db["app_state"]

def toBase64(data):
    sample_string_bytes = data.encode("ascii")
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")
    return base64_string

def decodeBase64(data):
    base64_bytes = data.encode("ascii")
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")
    return sample_string

def get_random_password():
    random_source = string.ascii_letters + string.digits + string.punctuation
    password = random.choice(string.ascii_lowercase)
    password += random.choice(string.ascii_uppercase)
    password += random.choice(string.digits)
    password += random.choice(string.punctuation)
    for i in range(12):
        password += random.choice(random_source)
    password_list = list(password)
    random.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)
    return password

def getMasterKey():
    foundSci = list(app_state.find({}))
    if len(foundSci) == 0 :
        print("Please init before encryption")
        sys.exit(1)
    keys = []
    for i in range(1, int(foundSci[0]["min"]) + 1):
        key = input(f"Enter the key : ")
        key = decodeBase64(key)
        key = key.replace(",b'", ",").replace("'", "")
        tkey = key.split(",")
        tuple_key = (int(tkey[0]), unhexlify(str(tkey[1]).encode()))
        keys.append(tuple_key)
    print()
    master_key = hexlify(Shamir.combine(keys))
    return master_key

def encrypt(string_to_encrypt, encryption_key = None, initing = False, is_file = False, file_info = None):
    if encryption_key is None:
        encryption_key = getMasterKey()
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    nonce = cipher.nonce
    data = string_to_encrypt.encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(data)
    if not initing:
        if is_file:
            file_content = f"{str(hexlify(ciphertext))[2:-1]}??azumaril??{str(hexlify(tag))[2:-1]}??azumaril??{str(hexlify(nonce))[2:-1]}??azumaril??{file_info['extension']}??azumaril??{file_info['name']}"
            f2 = open(f"{file_info['pwe']}.azumaril",'w')
            f2.write(file_content)
            f2.close()
            print("Successfully encrypted")
            return file_content
        else:
            print(hexlify(ciphertext))
            print(hexlify(tag))
            print(hexlify(nonce))
    print("Successfully encrypted")
    return ciphertext, tag, nonce

def decrypt(ciphertext, tag, nonce, encryption_key = None, debug = False, is_file = False, file_info = None):
    testkey = encryption_key
    if encryption_key is None:
        testkey = getMasterKey()
    cipher = AES.new(testkey, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        if is_file:
            f2 = open(f"{file_info['pwe']}{file_info['extension']}",'wb')
            f2.write(bytes.fromhex(plaintext.decode("utf-8")))
            f2.close()
        cipher.verify(tag)
        if debug and not is_file:
            print("The message is authentic")
            print("message :" + plaintext.decode("utf-8"))
        return True, plaintext.decode("utf-8")
    except ValueError:
        print("Key incorrect or message corrupted")
        return False, None

def unseal(reset = False):
    app_state_info = list(app_state.find({}))
    if len(app_state_info) == 0:
        print("The app has not been initiated yet")
        return False
    if reset:
        app_state.update_one({"init":True},{"$set":{"seal":True}})
    if app_state.find_one({"seal":False}) is not None:
        print("app already unsealed")
        return False
    ciphertext = app_state_info[0]["ciphertext"]
    tag = app_state_info[0]["tag"]
    nonce = app_state_info[0]["nonce"]
    if decrypt(ciphertext, tag, nonce)[0]:
        app_state.update_one({"init":True},{"$set":{"seal":False}})
        print(hexlify(ciphertext))
        print("app successfully unsealed")
        return True
    else:
        print("app not unsealed")
        return False
    
def init(reset = False):
    try:
        if app_state.count_documents({}) == 0 or reset:
            # if reset: #check if app unsealed first when resting
            #     if app_state.find_one({"seal":True}) is not None:
            #         print("app must be unsealed first")
            #         return False
            maxKey = int(input("Enter the maximum number of keys : "))
            minKey = int(input("Enter the minimum number of keys for the reconstitution : "))
            masterKey = get_random_bytes(16)
            # print(hexlify(masterKey))
            shares = Shamir.split(minKey, maxKey, masterKey)
            print()
            for idx, share in shares:
                e = str(idx) + "," + str(hexlify(share))
                b64Key = toBase64(e)
                print('Index #%d: %s' % (idx, b64Key))
            # print(hexlify(Shamir.combine(shares))) # unsealed
            encryptionKey = get_random_password()
            data = encrypt(encryptionKey, encryption_key = hexlify(masterKey), initing = True)
            app_state.delete_many({})
            app_state.insert_one(
                {
                    "seal" : True,
                    "init" : True,
                    "max" : maxKey,
                    "min" : minKey,
                    "ciphertext" : data[0],
                    "tag" : data[1],
                    "nonce" : data[2]
                }
            )
            # sys.exit(1)
            return True
        else:
            print("The app has already been initiated")
            # sys.exit(1)
            return False
    except:
        print(traceback.format_exc())
        return False
    
def seal():
    app_state.update_one({"init":True},{"$set":{"seal":True}})
# seal()
def appInfo(typed = None):
    app_info = list(app_state.find({}))
    if len(app_info) == 0:
        print("The app has not been initiated yet")
    else:
        if typed is None:
            print("Application informations --")
            print(f"Init : {app_info[0]['init']} ")
            print(f"Seal : {app_info[0]['seal']} ")
            print(f"Max  : {app_info[0]['max']} ")
            print(f"Min  : {app_info[0]['min']} ")
        if typed == "min":
            print(app_info[0]['min'])
        if typed == "max":
            print(app_info[0]['min'])

def clear():
    app_state.delete_many({})
    print("App successfully cleared")
# clear()
try:   
    PARSER = argparse.ArgumentParser(
            description="Chiffrement shamir")
    PARSER.add_argument('-a','--app', help='get the application information', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-mik','--min-key', help='get min keys', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-mak','--max-key', help='get max keys', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-i','--init', help='init app shamir', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-re','--reset', help='reset app shamir', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-u','--unseal', help='get key by providing the shamir key', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-cls','--clear', help='clear all', action=argparse.BooleanOptionalAction)
    
    PARSER.add_argument('-e','--encrypt', help='encrypt a string', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-ef','--encrypt-file', help='encrypt a file', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-path','--file-path', help='the of the file to encrypt')
    PARSER.add_argument('-ecptk','--encryption-key', help='encryption key sould be provided')
    PARSER.add_argument('-data','--data', help='something')
    
    PARSER.add_argument('-d','--decrypt', help='decrypt a string', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-df','--decrypt-file', help='decrypt a file', action=argparse.BooleanOptionalAction)
    PARSER.add_argument('-ctxt','--cipher-text', help='cipher text')
    PARSER.add_argument('-tag','--tag', help='the tag')
    PARSER.add_argument('-nce','--nonce', help='the nnonce')
    
    ARGS = PARSER.parse_args()
    args = vars(PARSER.parse_args())
    # print(args)
    if args["app"] is not None and args["app"]:
        appInfo()
        sys.exit(1)
    if args["init"] is not None and args["init"]:
        init()
    if args["min_key"] is not None and args["min_key"]:
        appInfo("min")
        sys.exit(1)
    if args["max_key"] is not None and args["max_key"]:
        appInfo("max")
        sys.exit(1)
    if args["reset"] is not None and args["reset"]:
        init(reset = True)
    if args["clear"] is not None and args["clear"]:
        app_info = app_state.find_one({})
        if app_info["seal"]:
            print("App is sealed you must unseal before")
            if unseal():
                clear()
                sys.exit(1)
            else:
               sys.exit(1) 
        else:
            clear()
    if args["unseal"] is not None and args["unseal"]:
        foundSci = list(app_state.find({}))
        if len(foundSci) == 0 :
            print("Please init before unsealing")
            sys.exit(1)
        else:
            unseal()
            sys.exit(1)
    if args["encrypt_file"] is not None and args["encrypt_file"]:
        if args["file_path"] == "":
            print("You must provide the file path to encrypt")
            sys.exit(1)
        if not os.path.exists(args["file_path"]):
            print("The file provided was not found")
            sys.exit(1)
        file_name, file_extension = os.path.splitext(args["file_path"])
        path_name = file_name
        file_name_list = file_name.split("/")
        if len(file_name_list) > 1:
            file_name = file_name_list[-1]
        if args["encryption_key"] == "":
            print("You must provide the encryption key")
            sys.exit(1)
        with open(args["file_path"], mode="rb") as file_to_encrypt:
            data_to_encrypt = file_to_encrypt.read()
        encrypt(
            string_to_encrypt = data_to_encrypt.hex(),
            encryption_key = args["encryption_key"].encode(),
            is_file = True,
            file_info = {
                "extension" : file_extension,
                "name" : file_name,
                "pwe" : path_name
            }
        )
        file_to_encrypt.close()
        sys.exit(1)
        
    if args["encrypt"] is not None and args["encrypt"]:
        if args["data"] == "":
            print("You must provide the data to encrypt")
            sys.exit(1)
        if args["encryption_key"] == "":
            print("You must provide the encryption key")
            sys.exit(1)
        encrypt(string_to_encrypt = args["data"], encryption_key = args["encryption_key"].encode())
        sys.exit(1)
        
    # if args["encrypt"] is not None:
    #     if args["encrypt"] == "":
    #         print("You must provide the data to encrypt")
    #         sys.exit(1)
    #     else:
    #         encrypt_args = args["encrypt"].split(" ")
    #         encrypt(string_to_encrypt = encrypt_args[0], encryption_key = encrypt_args[1].encode())
    #         sys.exit(1)
    
    if args["decrypt"] is not None and args["decrypt"]:
        if args["encryption_key"] == "":
            print("You must provide the encryption key")
            sys.exit(1)
        if args["cipher_text"] == "":
            print("You must provide the ciphertext to decrypt")
            sys.exit(1)
        if args["tag"] == "":
            print("You must provide the tag to decrypt")
            sys.exit(1)
        if args["nonce"] == "":
            print("You must provide the nonce to decrypt")
            sys.exit(1)
        ciphertext = unhexlify(args["cipher_text"].encode())
        tag = unhexlify(args["tag"].encode())
        nonce = unhexlify(args["nonce"].encode())
        encryption_key = args["encryption_key"].encode()
        decrypt(ciphertext, tag, nonce, encryption_key, True)
        sys.exit(1)
    
    if args["decrypt_file"] is not None and args["decrypt_file"]:
        if args["file_path"] == "":
            print("You must provide the file path to decrypt")
            sys.exit(1)
        if not os.path.exists(args["file_path"]):
            print("The file provided was not found")
            sys.exit(1)
        file_name, file_extension = os.path.splitext(args["file_path"])
        if file_extension != ".azumaril":
            print("The file provided was not an azumaril file")
            sys.exit(1)
        if args["encryption_key"] == "":
            print("You must provide the encryption key")
            sys.exit(1)
        with open(args["file_path"], mode="r") as f:
            file_content = f.read()
        decrypt_info = file_content.split("??azumaril??")
        ctxt = unhexlify(decrypt_info[0].encode())
        tag = unhexlify(decrypt_info[1].encode())
        nonce = unhexlify(decrypt_info[2].encode())
        file_info = {
            "extension" : decrypt_info[3],
            "name" : decrypt_info[4],
            "pwe" : file_name
        }
        encryption_key = args["encryption_key"].encode()
        decrypt(ctxt, tag, nonce, encryption_key, True, True, file_info)
        sys.exit(1)
        
    # if args["decrypt"] is not None:
    #     if len(args["decrypt"].split(" ")) != 4:
    #         print("You must provide the ciphertext, the tag and the nonce")
    #         sys.exit(1)
    #     else:
    #         dargs = args["decrypt"].split(" ")
    #         ciphertext = unhexlify(dargs[0].encode())
    #         tag = unhexlify(dargs[1].encode())
    #         nonce = unhexlify(dargs[2].encode())
    #         encryption_key = dargs[3].encode()
    #         decrypt(ciphertext, tag, nonce, encryption_key, True)
    #         sys.exit(1)
    
    app_info = app_state.find_one({})
    if app_info is None:
        choice = input("App not initiated, dou you want to init ? (yes/no) : ")
        if choice == "yes":
            if not init():
                sys.exit(1)
            else:
                app_info = app_state.find_one({})
                if app_info["seal"]:
                    choice = input("App sealed do you want to unseal ? (yes/no) : ")
                    if choice == "yes":
                        unseal()
                        sys.exit(1) 
                    if choice == "no":
                        print("\nBye!")
                        sys.exit(1)
                    if choice != "yes" and choice != "no":
                        print("\nInvalid choice!")
                        sys.exit(1)
        if choice == "no":
            print("\nBye!")
            sys.exit(1)
        if choice != "yes" and choice != "no":
            print("\nInvalid choice!")
            sys.exit(1)
    else:
        app_state.update_one({"init":True},{"$set":{"seal":True}})
        app_info = app_state.find_one({"seal":True})
        if app_info["seal"]:
            choice = input("App sealed do you want to unseal ? (yes/no) : ")
            if choice == "yes":
                unseal()
                sys.exit(1) 
            if choice == "no":
                print("\nBye!")
                sys.exit(1)
            if choice != "yes" and choice != "no":
                print("\nInvalid choice!")
                sys.exit(1)
except:
    sys.exit(1)


