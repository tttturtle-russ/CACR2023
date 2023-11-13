import paho.mqtt.client as mqtt
import threading

# MQTT 代理（broker）信息
broker_address = "localhost"
port = 1883


# 定义回调函数来处理连接事件
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to MQTT Broker with client ID: {client._client_id}")
        client.subscribe("test/topic")
    else:
        print(f"Connection failed for client ID {client._client_id} with code {rc}")


# 定义回调函数来处理接收消息
def on_message(client, userdata, message):
    print(f"Received message '{message.payload.decode()}' on topic '{message.topic}' for client ID {client._client_id}")


# 创建多个 MQTT 客户端
num_clients = 10000
clients = []

for i in range(num_clients):
    client = mqtt.Client(f"MyClient_{i}")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker_address, port, keepalive=60)
    clients.append(client)


# 启动多个线程，每个线程处理一个 MQTT 客户端
def run_client(client):
    client.loop_start()
    while True:
        pass


threads = [threading.Thread(target=run_client, args=(client,)) for client in clients]

for thread in threads:
    thread.start()

# 等待所有线程完成
for thread in threads:
    thread.join()
