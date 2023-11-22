import ctypes
import sys
import os
import random
import string
from getpass import getpass
import hashing_passwords as hp

lib = ctypes.CDLL("./client_info.so")

# 创建一个ClientInfo结构体实例
class ClientInfo(ctypes.Structure):
    _fields_ = [("username", ctypes.c_char * 256),
                ("password", ctypes.c_char * 256)]

# 定义C函数的参数和返回类型
lib.insert_to_database.argtypes = [ctypes.POINTER(ClientInfo)]

client_info = ClientInfo()

def generate_random_string(length = 13):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def encrypt(pw):
    return(hp.make_hash(pw))

def struct_generate():
    file_name = "username"
    district = ['001','002','003']
    try:
        if os.path.isfile(file_name):
            with open(file_name, 'r') as file:
                content = file.read()
                if content:
                    username = content 
                else:
                    username = district[0]+generate_random_string()
                    with open(file_name, 'w') as file:
                        file.write(username)
        else:
            username = district[0]+generate_random_string()
            with open(file_name, 'w') as file:
                file.write(username)
    except IOError as e:
        print(f"Failed to Read/Write: {e}")
        return -1

    pw = getpass("Enter password: ")
    pw2 = getpass("Re-enter password: ")
    if pw != pw2:
        sys.exit("Passwords don't match!")
    password = encrypt(pw)

    return {
        "username": username,
        "password": password
    }

struct1 = struct_generate()
client_info.username = struct1["username"].encode()
client_info.password = struct1["password"].encode()

lib.insert_to_database(ctypes.byref(client_info))
