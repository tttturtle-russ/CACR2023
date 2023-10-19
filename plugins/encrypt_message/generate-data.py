import cmd
import random
import subprocess
import uuid
import pymongo
from tqdm import tqdm
from multiprocessing import Process,Pool


def generate_data():
    _pass = random.randint(0, 65536)
    content = subprocess.run(f"gmssl sm2keygen -pass {_pass}", shell=True, capture_output=True).stdout.decode("utf-8")
    _id = uuid.uuid4()
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["mqtt"]
    collection = db["pems"]
    sm4_key = random.randbytes(16).hex()
    sm4_iv = random.randbytes(16).hex()
    sm3_hmac_key = random.randbytes(16).hex()

    data = {
        "uuid": _id.hex,
        "pass": _pass,
        "private_key": content[:content.index("PUBLIC") - 11],
        "sm4_key": sm4_key,
        "sm4_iv": sm4_iv,
        "sm3_hmac_key": sm3_hmac_key
    }

    collection.insert_one(data)


num = 100000

p = Pool(10)
for i in tqdm(range(num)):
    p.apply_async(generate_data)

p.close()
p.join()

