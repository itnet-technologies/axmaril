import os
import shutil
import sys

args = sys.argv
binary_dir = None
if "--path" in args:
    index = args.index("--path") + 1
    if index < len(args):
        binary_dir = args[index]
        
if binary_dir is not None:
    old_path = f"{binary_dir}/azumaril"
    os.remove(old_path)
else:    
    old_path = f"{os.path.dirname(__file__)}/../dist/azumaril"
    os.remove(old_path)

if binary_dir is not None:
    old_path = f"{binary_dir}/temp/azumaril"
else:
    old_path = f"{os.path.dirname(__file__)}/../dist/temp/azumaril"
if binary_dir is not None:
    shutil.move(old_path, f"{binary_dir}/azumaril")
    shutil.rmtree(f"{binary_dir}/temp")
else:
    shutil.move(old_path, f"{os.path.dirname(__file__)}/../dist/azumaril")
    shutil.rmtree(f"{os.path.dirname(__file__)}/../dist/temp")
print("updating")
sys.exit(1)