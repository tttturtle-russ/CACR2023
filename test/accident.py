import time
import threading
import paho.mqtt.client as mqtt

# MQTT 代理（broker）信息
broker_address = "localhost"
port = 1883

A = mqtt.Client("A")
B = mqtt.Client("B")
C = mqtt.Client("C")

def on_A_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to MQTT Broker with client ID: {client._client_id}")
        client.subscribe("/accident")
        client.subscribe("/checkpoint")

        client.publish("/checkpoint","paylaod")
        client.publish("/checkpoint","payload")
        time.sleep(3)
        client.publish("/accident","payload")
    else:
        print(f"Connection failed for client ID {client._client_id} with code {rc}")


def on_B_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to MQTT Broker with client ID: {client._client_id}")
        client.publish("/checkpoint","payload")
        client.publish("/checkpoint","payload")
    else:
        print(f"Connection failed for client ID {client._client_id} with code {rc}")

def on_C_connect(client,userdata,flags,rc):
    if rc == 0:
        print(f"Connected to MQTT Broker with client ID: {client._client_id}")
        client.subscribe("/accident")
    else:
        print(f"Connection failed for client ID {client._client_id} with code {rc}")

def on_message(client, userdata, message):
    print(f"Received message '{message.payload.decode()}' on topic '{message.topic}' for client ID {client._client_id}")

A.on_connect = on_A_connect
B.on_connect = on_B_connect
C.on_connect = on_C_connect

A.connect(broker_address, port, keepalive=0)
B.connect(broker_address, port, keepalive=0)
C.connect(broker_address, port, keepalive=0)

def run_client(client):
    client.loop_start()
    while True:
        pass

thread1 = threading.Thread(target=run_client, args=(A,))
thread2 = threading.Thread(target=run_client, args=(B,))
thread3 = threading.Thread(target=run_client, args=(C,))

# 启动线程
thread1.start()
thread2.start()
thread3.start()

# 等待所有线程完成
thread1.join()
thread2.join()
thread3.join()
