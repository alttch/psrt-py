from psrt import Client
import time


def x(client, userdata, message):
    print(message.topic)
    print(message.payload)


client = Client()
path = client.connect_cluster(paths='localhost,localhost:3873')
print(path)
client.subscribe('test')
client.subscribe_bulk(['test2', '#'])
client.unsubscribe('test')
client.unsubscribe_bulk(['test2', '#'])
client.subscribe('#')
# time.sleep(1)
client.publish('unit/tests/test1', 'hello')
client.on_message = x
while True:
    client.subscribe('test')
    client.unsubscribe('test')
    time.sleep(1)
client.bye()
