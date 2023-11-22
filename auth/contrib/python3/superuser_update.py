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
                ("password", ctypes.c_char * 256),
                ("superuser",ctypes.c_bool)]

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
            # print(temp.username)
            # print(temp.superuser)
            if temp.superuser == True:
                new_username = getpass("Please enter the username for which you want to modify superuser permissions: ")
                # if new_username == username:
                #     permission = getpass("tring to change your own user's ")
                struct2 = lib.search_database(new_username.encode())
                print(struct2.contents.username)
                if struct2 is not None:
                    # lib.update_superuser(struct1,1)
                    flag = getpass("superuser or not? Enter true or false")
                    flag = flag.lower()
                    if flag == "true":
                        lib.update_superuser(struct2,1)
                    elif flag == "false" and username == new_username:
                        flag2 = getpass("you will never be superuser!are you sure to be?yes or no")
                        if flag2 == 'yes':   
                            lib.update_superuser(struct1,0)
                        else:
                            print("operator is interrupted")
                    else:
                        print("cannot do this to other user")
                else:
                    print("the user you entered is not existed!")
            elif temp.superuser == False:
                print("only superuser can!")

struct_generate()

# struct1 = struct_generate()
# client_info.username = struct1["username"].encode()
# client_info.password = struct1["password"].encode()

# lib.insert_to_database(ctypes.byref(client_info))
