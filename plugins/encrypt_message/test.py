import os
import random
import time
import unittest
import subprocess
import pymongo
import string
import paho.mqtt.client as mqtt

mqtt_broker = "localhost"
mqtt_port = 1883


def generate_random_string(l):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(l))


def rand_state():
    return "public" if random.randint(0, 65535) % 2 == 0 else "p2p"


class MyTestCase(unittest.TestCase):
    def test_something(self):
        global result
        db = pymongo.MongoClient("mongodb://localhost:27017/")["mqtt"]
        cli = mqtt.Client()
        cli.connect(mqtt_broker, mqtt_port)
        for i in range(100000):
            message = generate_random_string(i + 1)
            print(message)
            state = rand_state()
            coll = db[state + "_message"]
            topic = ""
            cipher = ""
            sender = ""
            receiver = ""
            print(state)
            if state == 'p2p':
                pipeline = [{"$sample": {"size": 2}}]
                result = list(db["pems"].aggregate(pipeline))
                sender = result[0].get("uuid")
                receiver = result[1].get("uuid")
                topic = "/" + state + "/" + receiver
                print(f"sender:{sender}\nreceiver:{receiver}")
                cipher = subprocess.run(f"./test_data p2p {message} {sender} {receiver}", shell=True).stdout.decode(
                    "utf-8")
            elif state == "public":
                topic = "/" + state
                pipeline = [{"$sample": {"size": 2}}]
                result = list(db["pems"].aggregate(pipeline))
                sender = result[0].get("uuid")
                print(f"sender:{sender}")
                cipher = subprocess.run(f"./test_data public {message} {sender}", shell=True)
            print(cipher)
            cli.publish(topic, payload=cipher)
            time.sleep(1)
            if state == "p2p":
                result = coll.find_one({"uuid": sender}, None)
            elif state == "public":
                result = coll.find_one({"sender": sender, "receiver": receiver}, None)
            self.assertEqual(i + 1, coll.count_documents({}))
            self.assertEqual(message, result.get("message"))


if __name__ == '__main__':
    unittest.main()
