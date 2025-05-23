import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding='utf-8')

GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[31m'
RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    menu()

banner = """
                                    _
|+============================+    /|\   +===============================+|
|     _____      _____   ______   / | \   ___       ___   ______   _____  |
|    / (^) \    / ___/  / __  /  /  |  \  \  \     /  /  / ____/  /  _  \ |
|   / __  _/   / /__   / /_/ /  /   |   \  \  \   /  /  / /___   /    __/ |
|  / (__)  \  / /___  / __  /  /    |    \  \  \_/  /  / /___   /  /\ \   |
| /________/ /_____/ /_/ /_/  /_____|_____\  \_____/  /_____/  /__/  \_\  |
|                        BeaverSploit--Framework                          |
|+=======================================================================+|
"""

modules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
ruby_commands = {}
module_options = {} 
selected_module = None  


if os.path.exists(modules_dir) and os.path.isdir(modules_dir):
    for root, _, files in os.walk(modules_dir):
        for file in files:
            if file.endswith(".rb"):
                command_name = file[:-3]  
                file_path = os.path.join(root, file)
                print(GREEN + f"[DEBUG] Loaded Ruby module: {command_name} from {file_path}" + RESET)

                def run_ruby_module(fp):
                    def wrapper(*args):
                        try:
                            result = subprocess.run(["ruby", fp] + list(args), capture_output=True, text=True)
                            print(result.stdout)
                        except Exception as e:
                            print(RED + f"[!] Error executing Ruby module {fp}: {e}" + RESET)

                    return wrapper

                ruby_commands[command_name] = run_ruby_module(file_path)
else:
    print(RED + f"[DEBUG] Folder '{modules_dir}' not found!" + RESET)

def generate_help():
    help_text = """ 
Available Commands:
- clear                   : Clear screen
- help                    : Show available commands
- exit                    : Exit Beaversploit
- use <module>            : Select a module
- set <option> <value>    : Set parameters for the selected module
- run                     : Execute the selected module
Options:
- IP or ip                : set IP adress
- DOMAIN or domain        : set domain 
- PORT or port            : set port
"""

    categories = {
        "payloads": [],
        "post": [],
        "exploits": [],
        "evasion": [],
        "encoders": [],
        "auxiliary": [],
        "remote_control": []  
    }


    script_dir = os.path.dirname(os.path.abspath(__file__))
    modules_path = os.path.join(script_dir, "modules/")

   
    for category in categories.keys():
        category_path = os.path.join(modules_path, category)
        if os.path.isdir(category_path):
            modules = [f.replace(".rb", "") for f in os.listdir(category_path) if f.endswith(".rb")]
            categories[category] = modules 

  
    for category, modules in categories.items():
        if modules:
            help_text += f"\n{category.capitalize()}:\n  " + ", ".join(modules)

    return help_text


def use_module(module_name):
    global selected_module, module_options
    if module_name in ruby_commands:
        selected_module = module_name
        module_options = {}
        print(f"{GREEN}[*] Module {module_name} selected.{RESET}")
    else:
        print(f"{RED}[!] Module '{module_name}' not found.{RESET}")

required_options = {
    "geoip_lookup": ["DOMAIN"],
    "reverse_dns": ["DOMAIN"],
    "subdomain_scan": ["DOMAIN"]
}

def set_option(option, value=None):

    global module_options
    if selected_module:
        required = required_options.get(selected_module, [])
        if option in required and not value:
            print(f"{RED}[!] Usage: set {option} <value> (required for {selected_module}){RESET}")
            return
        module_options[option] = value if value else None
        print(f"{GREEN}[*] {option} set to {value if value else '(no value)'}{RESET}")
    else:
        print(f"{RED}[!] No module selected. Use 'use <module>' first.{RESET}")

def run_module():

    if selected_module:
        print(f"{GREEN}[*] Running {selected_module} with options: {module_options}{RESET}")
        ruby_commands[selected_module](*(module_options.values()))
    else:
        print(f"{RED}[!] No module selected. Use 'use <module>' first.{RESET}")

commands = {
    "clear": lambda: clear_screen(),
    "help": lambda: print(generate_help()),
    "exit": lambda: exit(),
    "use": lambda mod: use_module(mod),
    "set": lambda opt, val: set_option(opt, val),
    "run": lambda: run_module()
}

def terminal():
    while True:
        user_input = input(f"{YELLOW}bsf>> {RESET}").strip()
        if not user_input:
            continue
        args = user_input.split()
        cmd = args[0]
        params = args[1:]
        if cmd in commands:
            try:
                commands[cmd](*params)
            except TypeError:
                print(f"{YELLOW}Error: Incorrect usage of '{cmd}', check 'help'{RESET}")
        else:
            print(f"{YELLOW}Error: Command not found{RESET}")

def menu():
    print(GREEN + banner + RESET)
    print("Beaversploit is a framework for security testing (educational purposes only)")
    print("Use this tool responsibly and only on systems you have permission to test")
    terminal()

menu()