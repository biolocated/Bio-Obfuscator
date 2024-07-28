import ast
import base64
import marshal
import random
import string
import os
import sys
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from colorama import init, Fore, Style

init()

def generate_random_name(length=12):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_key():
    return os.urandom(32)

def compress_data(data):
    return zlib.compress(data)

def decompress_data(data):
    return zlib.decompress(data)

def encrypt_code(code, key):
    cipher = AES.new(key, AES.MODE_GCM)
    code_bytes = marshal.dumps(code)
    compressed_code = compress_data(code_bytes)
    padded_code = pad(compressed_code, AES.block_size)
    ct_bytes, tag = cipher.encrypt_and_digest(padded_code)
    encrypted_code = base64.b64encode(cipher.nonce + tag + ct_bytes).decode()
    final_encoded_code = base64.b64encode(encrypted_code.encode()).decode()
    return final_encoded_code

def decrypt_code(encoded_code, key):
    decoded_encoded_code = base64.b64decode(encoded_code).decode()
    decoded = base64.b64decode(decoded_encoded_code)
    nonce, tag, ct = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_padded = cipher.decrypt_and_verify(ct, tag)
    decrypted_code = unpad(decrypted_padded, AES.block_size)
    decompressed_code = decompress_data(decrypted_code)
    return marshal.loads(decompressed_code)

class AdvancedObfuscator(ast.NodeTransformer):
    def __init__(self):
        self.var_names = {}
        self.func_names = {}
        self.class_names = {}
        self.imports = []

    def visit_Import(self, node):
        self.imports.append(node)
        return node

    def visit_ImportFrom(self, node):
        self.imports.append(node)
        return node

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store) and node.id not in self.var_names:
            self.var_names[node.id] = generate_random_name()
        if node.id in self.var_names:
            node.id = self.var_names[node.id]
        return node

    def visit_FunctionDef(self, node):
        if node.name not in self.func_names:
            self.func_names[node.name] = generate_random_name()
        node.name = self.func_names[node.name]
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node):
        if node.name not in self.class_names:
            self.class_names[node.name] = generate_random_name()
        node.name = self.class_names[node.name]
        self.generic_visit(node)
        return node

    def obfuscate(self, code):
        tree = ast.parse(code)
        obfuscated_tree = self.visit(tree)
        obfuscated_code = compile(obfuscated_tree, filename="<ast>", mode="exec")
        return obfuscated_code

def generate_decryption_function(encrypted_code, key):
    decrypt_func_name = generate_random_name()
    key_var_name = generate_random_name()
    encoded_key = base64.b64encode(key).decode()
    encoded_code = base64.b64encode(encrypted_code.encode()).decode()
    decryption_function = f"""
def {decrypt_func_name}():
    global {key_var_name}
    {key_var_name} = base64.b64decode(b'{encoded_key}')
    encrypted_code = base64.b64decode(b'{encoded_code}')
    decrypted_code = decrypt_code(encrypted_code, {key_var_name})
    exec(decrypted_code)
"""
    return decryption_function, decrypt_func_name

def anti_debug_check():
    import ctypes
    if ctypes.windll.kernel32.IsDebuggerPresent():
        print(Fore.RED + "Debugger detected!" + Style.RESET_ALL)
        sys.exit()

def sandbox_check():
    try:
        import platform
        if 'virtual' in platform.platform().lower():
            print(Fore.YELLOW + "Running in a virtual environment!" + Style.RESET_ALL)
            sys.exit()
    except ImportError:
        pass

def print_ascii_art():
    ascii_art = """
    {0}____  _             ____  __    ____                      __
   / __ )(_)___        / __ \/ /_  / __/_  ________________ _/ /_____  _____
  / __  / / __ \______/ / / / __ \/ /_/ / / / ___/ ___/ __ `/ __/ __ \/ ___/
 / /_/ / / /_/ /_____/ /_/ / /_/ / __/ /_/ (__  ) /__/ /_/ / /_/ /_/ / /
/_____/_/\____/      \____/_.___/_/  \__,_/____/\___/\__,_/\__/\____/_/""".format(Fore.CYAN)
    print(ascii_art)
    print(Fore.GREEN + "--made by biolocated" + Style.RESET_ALL)

def get_valid_file_path(prompt):
    while True:
        path = input(prompt)
        if os.path.isdir(path):
            print(Fore.RED + "Error: The path provided is a directory. Please provide a full file path including the file name." + Style.RESET_ALL)
        elif os.path.exists(path):
            return path
        else:
            print(Fore.RED + "Error: The file does not exist. Please provide a valid file path." + Style.RESET_ALL)

def main():
    print_ascii_art()
    anti_debug_check()
    sandbox_check()

    input_file = get_valid_file_path('Enter the path to the Python file you want to obfuscate: ')
    output_file = f"{os.path.splitext(input_file)[0]}-obf.py"

    if os.path.exists(output_file):
        overwrite = input(f"File '{output_file}' already exists. Overwrite? (y/n): ")
        if overwrite.lower() != 'y':
            print(Fore.YELLOW + "Aborting." + Style.RESET_ALL)
            sys.exit(1)

    settings = {
        'key': generate_key(),
        'input_file': input_file,
        'output_file': output_file
    }

    try:
        with open(settings['input_file'], 'r') as f:
            code = f.read()
    except Exception as e:
        print(Fore.RED + f"Error reading input file: {e}" + Style.RESET_ALL)
        sys.exit(1)

    obfuscator = AdvancedObfuscator()
    obfuscated_code = obfuscator.obfuscate(code)
    encrypted_code = encrypt_code(obfuscated_code, settings['key'])

    decryption_function_code, decrypt_func_name = generate_decryption_function(encrypted_code, settings['key'])

    obfuscated_script = f"""
import base64
import marshal
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import sys

def decrypt_code(encoded_code, key):
    decoded_encoded_code = base64.b64decode(encoded_code).decode()
    decoded = base64.b64decode(decoded_encoded_code)
    nonce, tag, ct = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_padded = cipher.decrypt_and_verify(ct, tag)
    decrypted_code = unpad(decrypted_padded, AES.block_size)
    decompressed_code = zlib.decompress(decrypted_code)
    return marshal.loads(decompressed_code)

{decryption_function_code}
{decrypt_func_name}()
"""

    try:
        with open(settings['output_file'], 'w') as f:
            f.write(obfuscated_script)
    except Exception as e:
        print(Fore.RED + f"Error writing output file: {e}" + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.GREEN + f'Obfuscation complete. Obfuscated file saved as: {settings["output_file"]}' + Style.RESET_ALL)

if __name__ == '__main__':
    main()
