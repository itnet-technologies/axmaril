import subprocess
import sys
import time
import sys
import os
import getpass
import traceback
from dotenv import load_dotenv
from pathlib import Path

load1 = True
# def commander(arg = None, inputs = None, option = None):
#     # command = [f"/home/itnet/Azumaril/static/shamir2.py"]
#     command = [os.path.dirname(__file__) + "/../static/shamir"]
#     if arg is not None:
#         command.append(f"{arg}")
#     if getattr(sys, 'frozen', False):
#         command[0] = f"{sys._MEIPASS}/static/shamir"
#     if option is not None:
#         command.append(option)
#     if inputs is None:
#         result = subprocess.run(
#             command,
#             capture_output = True,
#             text = True
#         )
#     else:
#         result = subprocess.run(
#             command,
#             input = inputs,
#             capture_output = True,
#             text = True
#         )
#     if result.stdout is not None and result.stdout != "":
#         lines = result.stdout
#         if arg == "-i" and len(lines.split("\n")) >2 :
#             lines = lines.split('\n',1)[-1]
#             return True, lines
#         else:
#             return True, lines
#     else:
#         return False, result.stderr

def commander(arg_list = [], inputs = None):
    # command = [f"/home/itnet/Azumaril/static/shamir2.py"]
    command = [os.path.dirname(__file__) + "/../static/shamir"]
    if getattr(sys, 'frozen', False):
        command[0] = f"{sys._MEIPASS}/static/shamir"
    command += arg_list
    if inputs is None:
        result = subprocess.run(
            command,
            capture_output = True,
            text = True
        )
    else:
        result = subprocess.run(
            command,
            input = inputs,
            capture_output = True,
            text = True
        )
    if result.stdout is not None and result.stdout != "":
        lines = result.stdout
        if len(arg_list) >=2:
            if arg_list[1] == "-i" and len(lines.split("\n")) >2 :
                # lines = lines.split('\n',1)[-1]
                return True, lines
            else:
                return True, lines
        else:
            return True, lines
    else:
        return False, result.stderr
    
def remove_last_line(s):
    return s[:s.rfind('\n')]

def remove_last_lines(s, n):
    for i in range(n):
        s = s[:s.rfind('\n')]
    return s

def remove_first_line(lines):
    return lines.split('\n',1)[-1]

def not_initiated():
    checker = commander(["-a"])
    lines = checker[1]
    print(lines)
    if "The app has not been initiated yet" in lines:
        return True
    else:
        return False

def reinit():
    print("This action is irreversible all secrets will be lost forever")
    going = input("continue ? (yes/no) : ")
    if going == "yes":
        # print("You must unseal first in order to reset shamir app")
        # mink = commander(["-mik"])[1]
        # # print(mink)
        # inputs = ""
        # for i in range(int(mink)):
        #     keyy = getpass.getpass("Enter the key : ")
        #     inputs += f"{keyy}\n"
        maxKey = input("Enter the maximum number of keys : ")
        minKey = input("Enter the minimum number of keys for the reconstitution : ")
        inputs = f"{maxKey}\n{minKey}\nno\n"
        lines = commander(arg_list = ["-re"], inputs = inputs)[1]
        print("Successfully reset the shamir app\n")
        lines = remove_last_lines(lines, 3)
        lines = remove_first_line(lines)
        print(lines)
        
        choice = input("App sealed do you want to unseal ? (yes/no) : ")
        inputs = f"{choice}"
        if choice == "yes":
            for i in range(int(minKey)):
                keyy = getpass.getpass("Enter the key : ")
                inputs += f"\n{keyy}"
            inputs += "\n"
            lines = commander(inputs = inputs)[1]
            lines = remove_first_line(lines)
            byted_encryption_key = lines.split("\n")[0]
            encryption_key = byted_encryption_key[2:-1] #b'fgf'
            lines = remove_first_line(lines)
            print(lines)
            return encryption_key
        else:
            lines = commander(inputs = inputs)[1]
            lines = remove_first_line(lines)
            print(lines)
            sys.exit(1)
    else:
        print("Wise decision!")

def loader(args, in_sdd = False):
    try:
        rks = ["clear", "app", "init", "unseal", "encrypt", "decrypt", "seal"]
        for rk in rks:
            if rk not in args:
                args[rk] = None
        if args["seal"] is not None and args["seal"]:
            lines = commander(["-u"], inputs = inputs)[1]
            lines = lines.split('\n',1)[-1]
            # mkey = lines.split("\n")[0]
            lines = lines.split('\n',1)[-1]
            # mkey = lines.split("\n")[len(lines.split("\n"))-1]
            # lines = remove_last_line(lines)
            print(lines)
            # print(mkey)
            sys.exit(1)
        if args["clear"] is not None and args["clear"]:
            mink = commander(["-mik"])[1]
            args_to_input = []
            for i in range(int(mink)):
                args_to_input.append(getpass.getpass("Enter the key : "))
            inputs = ""
            for key in args_to_input:
                inputs += f"{key}\n"
            checker = commander(["-cls"], inputs = inputs)
            lines = checker[1]
            lines = lines.split('\n',1)[-1]
            print(lines)
            sys.exit(1)
        if args["app"] is not None and args["app"]:
            checker = commander(["-a"])
            print(checker[1])
            sys.exit(1)
        if args["init"] is not None and args["init"]:
            checker = commander(["-a"])
            lines = checker[1]
            if len(lines.split("\n")) >2:
                print(commander(["-i"])[1])
                sys.exit(1)
            else:
                maxKey = input("Enter the maximum number of keys : ")
                minKey = input("Enter the minimum number of keys for the reconstitution : ")
                inputs = f"{maxKey}\n{minKey}"
                print(commander(["-i"], inputs = inputs)[1])
                sys.exit(1)
        if args["unseal"] is not None and args["unseal"]:
            mink = commander(["-mik"])[1]
            checker = commander(["-a"])[1]
            if not_initiated():
                print(commander(["-u"])[1])
                sys.exit(1)
            else:
                if "Seal : False" in checker:
                    print(commander(["-u"])[1])
                    sys.exit(1)
                else:
                    args_to_input = []
                    for i in range(int(mink)):
                        args_to_input.append(getpass.getpass("Enter the key : "))
                    inputs = ""
                    for key in args_to_input:
                        inputs += f"{key}\n"
                    lines = commander(["-u"], inputs = inputs)[1]
                    lines = lines.split('\n',1)[-1]
                    # mkey = lines.split("\n")[0]
                    lines = lines.split('\n',1)[-1]
                    # mkey = lines.split("\n")[len(lines.split("\n"))-1]
                    # lines = remove_last_line(lines)
                    print(lines)
                    # print(mkey)
                    sys.exit(1)
        if args["encrypt"] is not None:
            print(commander(["-e"], "Nothing")[1])
            sys.exit(1)
        if args["decrypt"] is not None:
                print(commander(["-d"], "Nothing Nothing Nothing")[1])
                sys.exit(1)
        if in_sdd:
            KEYS = os.getenv('AZUMARIL_KEYS')
            args["keys"] = KEYS.split(",")  #if the API is running into the development server
        
        if not_initiated():      #if the app was not initiated yet 
            choice = input("App not initiated, dou you want to init ? (yes/no) : ")
            inputs = f"{choice}"
            if choice == "yes":
                maxKey = input("Enter the maximum number of keys : ")
                minKey = input("Enter the minimum number of keys for the reconstitution : ")
                inputs += f"\n{maxKey}\n{minKey}\nno"
                lines = commander(inputs = inputs)[1]
                lines = remove_last_lines(lines, 3)
                lines = remove_first_line(lines)
                print(lines)
                choice = input("App sealed do you want to unseal ? (yes/no) : ")
                inputs = f"{choice}"
                if choice == "yes":
                    for i in range(int(minKey)):
                        keyy = getpass.getpass("Enter the key : ")
                        inputs += f"\n{keyy}"
                    lines = commander(inputs = inputs)[1]
                    lines = remove_first_line(lines)
                    byted_encryption_key = lines.split("\n")[0]
                    encryption_key = byted_encryption_key[2:-1] #b'fgf'
                    lines = remove_first_line(lines)
                    print(lines)
                    return encryption_key
                else:
                    lines = commander(inputs = inputs)[1]
                    lines = remove_first_line(lines)
                    print(lines)
                    sys.exit(1)
            else:
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                print(lines)
                sys.exit(1)
        else:               #if the app had already been initiated
            mink = commander(["-mik"])[1]
            if not in_sdd :
                choice = input("App sealed do you want to unseal ? (yes/no) : ")
            else:
                choice = "yes"      #if the API is running into the development server
            inputs = f"{choice}"
            if choice == "yes":
                keys_idx = 0
                for i in range(int(mink)):
                    if not in_sdd :  
                        keyy = getpass.getpass("Enter the key : ")
                    else:
                        keyy = args["keys"][keys_idx]   #if the API is running into the development server
                    keys_idx += 1
                    inputs += f"\n{keyy}"
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                byted_encryption_key = lines.split("\n")[0]
                encryption_key = byted_encryption_key[2:-1]
                lines = remove_first_line(lines)
                # print(lines)
                if lines.split("\n")[0] == "app not unsealed":
                    sys.exit(1)
                return encryption_key
            else:
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                print(lines)
                sys.exit(1)
    except:
        print(traceback.format_exc())
        time.sleep(80)
        sys.exit(1)


def loader_v2(args, in_sdd = False, break_if_done = True, inputs = None, outputs = True):
    try:
        rks = ["clear", "app", "init", "unseal", "encrypt", "decrypt", "seal"]
        for rk in rks:
            if rk not in args:
                args[rk] = None
        # if args["seal"] is not None and args["seal"]:
        #     mink = commander(["-mik"])[1]
        #     inputs = ""
        #     for i in range(int(mink)):
        #         inputs += getpass.getpass("Enter the key : ") + "\n"
        #     lines = commander(["-u"], inputs = inputs)[1]
        #     print(lines)
        #     lines = lines.split('\n',1)[-1]
        #     # mkey = lines.split("\n")[0]
        #     lines = lines.split('\n',1)[-1]
        #     # mkey = lines.split("\n")[len(lines.split("\n"))-1]
        #     # lines = remove_last_line(lines)
        #     # print(lines)
        #     # print(mkey)
        #     if break_if_done:
        #         sys.exit(1)
        #     else:
        #         return True
        if args["clear"] is not None and args["clear"]:
            if inputs is None:
                mink = commander(["-mik"])[1]
                args_to_input = []
                for i in range(int(mink)):
                    args_to_input.append(getpass.getpass("Enter the key : "))
                inputs = ""
                for key in args_to_input:
                    inputs += f"{key}\n"
            checker = commander(["-cls"], inputs = inputs)
            lines = checker[1]
            lines = lines.split('\n',1)[-1]
            return lines
            # print(lines)
            # sys.exit(1)
        if args["app"] is not None and args["app"]:
            checker = commander(["-a"])
            if break_if_done:
                if outputs:
                    print(checker[1])
                sys.exit(1)
            else:
                return checker[1]
        if args["init"] is not None and args["init"]:
            checker = commander(["-a"])
            lines = checker[1]
            if len(lines.split("\n")) >2:
                if outputs:
                    print(commander(["-i"])[1])
                sys.exit(1)
            else:
                if inputs is None:
                    maxKey = input("Enter the maximum number of keys : ")
                    minKey = input("Enter the minimum number of keys for the reconstitution : ")
                    inputs = f"{maxKey}\n{minKey}"
                result = commander(["-i"], inputs = inputs)[1]
                if outputs:
                    print(result)
                if inputs is not None:
                    return result
                if break_if_done:
                    sys.exit(1)
                else:
                    return True
        if args["unseal"] is not None and args["unseal"]:
            mink = commander(["-mik"])[1]
            checker = commander(["-a"])[1]
            if not_initiated():
                if outputs:
                    print(commander(["-u"])[1])
                sys.exit(1)
            else:
                if "Seal : False" in checker:
                    if outputs:
                        print(commander(["-u"])[1])
                    sys.exit(1)
                else:
                    args_to_input = []
                    for i in range(int(mink)):
                        args_to_input.append(getpass.getpass("Enter the key : "))
                    inputs = ""
                    for key in args_to_input:
                        inputs += f"{key}\n"
                    lines = commander(["-u"], inputs = inputs)[1]
                    lines = lines.split('\n',1)[-1]
                    # mkey = lines.split("\n")[0]
                    lines = lines.split('\n',1)[-1]
                    # mkey = lines.split("\n")[len(lines.split("\n"))-1]
                    # lines = remove_last_line(lines)
                    if outputs:
                        print(lines)
                    # if outputs:
                    # print(mkey)
                    sys.exit(1)
        if args["encrypt"] is not None:
            if outputs:
                print(commander(["-e"], "Nothing")[1])
            sys.exit(1)
        if args["decrypt"] is not None:
                if outputs:
                    print(commander(["-d"], "Nothing Nothing Nothing")[1])
                sys.exit(1)
        if in_sdd:
            KEYS = os.getenv('AZUMARIL_KEYS')
            args["keys"] = KEYS.split(",")  #if the API is running into the development server
        
        if not_initiated():      #if the app was not initiated yet 
            choice = input("App not initiated, dou you want to init ? (yes/no) : ")
            inputs = f"{choice}"
            if choice == "yes":
                maxKey = input("Enter the maximum number of keys : ")
                minKey = input("Enter the minimum number of keys for the reconstitution : ")
                inputs += f"\n{maxKey}\n{minKey}\nno"
                lines = commander(inputs = inputs)[1]
                lines = remove_last_lines(lines, 3)
                lines = remove_first_line(lines)
                if outputs:
                    print(lines)
                choice = input("App sealed do you want to unseal ? (yes/no) : ")
                inputs = f"{choice}"
                if choice == "yes":
                    for i in range(int(minKey)):
                        keyy = getpass.getpass("Enter the key : ")
                        inputs += f"\n{keyy}"
                    lines = commander(inputs = inputs)[1]
                    lines = remove_first_line(lines)
                    byted_encryption_key = lines.split("\n")[0]
                    encryption_key = byted_encryption_key[2:-1] #b'fgf'
                    lines = remove_first_line(lines)
                    if outputs:
                        print(lines)
                    return encryption_key
                else:
                    lines = commander(inputs = inputs)[1]
                    lines = remove_first_line(lines)
                    if outputs:
                        print(lines)
                    sys.exit(1)
            else:
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                if outputs:
                    print(lines)
                sys.exit(1)
        else:               #if the app had already been initiated
            mink = commander(["-mik"])[1]
            if not in_sdd and args["seal"] is None:
                if inputs is not None:
                    lines = commander(inputs = inputs)[1]
                    if args["seal"]:
                        return lines
                    # if outputs:
                    # print(lines)
                    lines = remove_first_line(lines)
                    byted_encryption_key = lines.split("\n")[0]
                    encryption_key = byted_encryption_key[2:-1]
                    lines = remove_first_line(lines)
                    # if outputs:
                    # print(lines)
                    if lines.split("\n")[0] == "app not unsealed":
                        if not break_if_done:
                            return None
                        
                        sys.exit(1)
                    return encryption_key
                choice = input("App sealed do you want to unseal ? (yes/no) : ")
            else:
                choice = "yes"      #if the API is running into the development server
            inputs = f"{choice}"
            if choice == "yes":
                keys_idx = 0
                for i in range(int(mink)):
                    if not in_sdd :  
                        keyy = getpass.getpass("Enter the key : ")
                    else:
                        keyy = args["keys"][keys_idx]   #if the API is running into the development server
                    keys_idx += 1
                    inputs += f"\n{keyy}"
                lines = commander(inputs = inputs)[1]
                if args["seal"]:
                    return lines
                lines = remove_first_line(lines)
                byted_encryption_key = lines.split("\n")[0]
                encryption_key = byted_encryption_key[2:-1]
                lines = remove_first_line(lines)
                # if outputs:
                # print(lines)
                if lines.split("\n")[0] == "app not unsealed":
                    if not break_if_done:
                        return None
                    
                    sys.exit(1)
                return encryption_key
            else:
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                if outputs:
                    print(lines)
                sys.exit(1)
    except:
        print(traceback.format_exc())
        time.sleep(80)
        sys.exit(1)

# ecptk = loader({}, True)
# print(ecptk)

