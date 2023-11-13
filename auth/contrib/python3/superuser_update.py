import ctypes
import sys
import os
import random
import string
from getpass import getpass
import hashing_passwords as hp

lib = ctypes.CDLL("./client_info.so")
lib2 = ctypes.CDLL("./compare.so")

# 创建一个ClientInfo结构体实例
class ClientInfo(ctypes.Structure):
    _fields_ = [("username", ctypes.c_char * 256),
                ("password", ctypes.c_char * 256)]

# 定义C函数的参数和返回类型
lib.search_database.argtypes = [ctypes.c_char_p]
lib.search_database.restype = ctypes.POINTER(ClientInfo)
lib.update_superuser.argtypes = [ctypes.POINTER(ClientInfo),ctypes.c_bool]
lib2.pbkdf2_check.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib2.pbkdf2_check.restype = ctypes.c_int

client_info = ClientInfo()

# def generate_random_string(length = 16):
#     characters = string.ascii_letters + string.digits
#     random_string = ''.join(random.choice(characters) for _ in range(length))
#     return random_string

# def encrypt(pw):
#     return(hp.make_hash(pw))

def struct_generate():
    file_name = "username"
    try:
        if os.path.isfile(file_name):
            with open(file_name, 'r') as file:
                content = file.read()
                if content:
                    username = content 
                else:
                    print("username not found!")
    except IOError as e:
        print(f"Failed to Read/Write: {e}")
        return -1

    pw = getpass("Enter password: ")

    struct1 = lib.search_database(username.encode())
    temp = struct1.contents
    passwd = temp.password
    if struct1 is not None :
        if lib2.pbkdf2_check(pw.encode(),passwd) == 0:
            sys.exit("Passwords don't match!")
        else:
            flag = getpass("is it a superuser? Enter true or false")
            flag = flag.lower()
            if flag == "true":
                lib.update_superuser(struct1,1)
            elif flag == "false":   
                    lib.update_superuser(struct1,0)

struct_generate()

# struct1 = struct_generate()
# client_info.username = struct1["username"].encode()
# client_info.password = struct1["password"].encode()

# lib.insert_to_database(ctypes.byref(client_info))
