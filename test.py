from psrt import Client
import time


def x(client, userdata, message):
    print(message.topic)
    print(message.payload)


client = Client(path='localhost:2883')
# client.tls = True
# client.tls_ca = '/opt/workstuff/psrt/certs/ca.crt'
# client.need_data_socket = False
# client.connect()
# client.disconnect()
client.connect()
try:
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
finally:
    client.bye()
