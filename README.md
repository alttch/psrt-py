# PSRT Python connector

Python connector for [PSRT](https://github.com/alttch/psrt)

SDK Documentation: https://psrt-py.readthedocs.io/

Client usage example:

```python
from psrt import Client
import time

def process_message(client, userdata, message):
    print(message.topic)
    print(message.payload)


client = Client(path='localhost:2873')
# client.tls = True
# client.tls_ca = '/opt/workstuff/psrt/certs/ca.crt'
# client.need_data_socket = False
client.connect()
try:
    client.subscribe('test')
    client.subscribe_bulk(['test2', '#'])
    client.unsubscribe('test')
    client.unsubscribe_bulk(['test2', '#'])
    client.subscribe('#')
    client.publish('unit/tests/test1', 'hello')
    client.on_message = process_message
    while True:
        client.publish('unit/tests/test1', 'hello')
        time.sleep(1)
finally:
    client.bye()
```
