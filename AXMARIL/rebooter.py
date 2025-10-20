import time, os
import subprocess
print("rebooting..")
time.sleep(5)
print("rebooting..")
# process = subprocess.Popen(["python3", f"{os.path.dirname(__file__)}/../app.py"])

import os

def remove_bom(source_code):
    if source_code.startswith('\ufeff'):
        return source_code[1:]
    return source_code

file_path = f"{os.path.dirname(__file__)}app.py"

import runpy

# Get the path to the script
script_path = os.path.join(os.path.dirname(__file__), 'app.py')

# Run the script using runpy
runpy.run_path(script_path)

# with open(file_path, 'r', encoding='utf-8-sig') as fo:
#     source_code = fo.read()
#     source_code = remove_bom(source_code)
#     byte_code = compile(source_code, file_path, "exec")
#     exec(byte_code)
    
# with open(f"{os.path.dirname(__file__)}/../app.py") as fo:
#     source_code = fo.read()
#     byte_code = compile(source_code, f"{os.path.dirname(__file__)}/../app.py", "exec")
#     exec(byte_code, globals, locals)