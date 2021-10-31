#!/usr/bin/env python3

import time
import sys
import random
import threading
from psrt import Client
from argparse import ArgumentParser

ap = ArgumentParser()

ap.add_argument('PAYLOAD_SIZE')
ap.add_argument('-w', help='workers', type=int, default=4)
ap.add_argument('-i', help='iters per worker', type=int, default=10_000)
ap.add_argument('-s', help='socket buffer size', type=int, default=1_000)

a = ap.parse_args()
print(a)

c = 0


def on_message(client, userdata, message):
    global c
    global payload
    assert message.payload == payload
    c += 1


n = int(a.i)
workers = int(a.w)
payload_size = int(a.PAYLOAD_SIZE)

topic = f'benchmark/test-{random.randint(1, 1000)}'
payload = b''
ok = False
print('generating payload')
payload = b'\x01' * payload_size
# while not ok:
    # for x in range(0, 255):
        # payload += x.to_bytes(1, 'little')
        # if len(payload) == payload_size:
            # ok = True
            # break
print('testing')


def pub(cl, i):
    t = f'{topic}-{i}'
    try:
        for i in range(0, n):
            cl.publish(t, payload)
    except Exception as e:
        import traceback
        traceback.print_exc()


try:
    clients = []
    for i in range(0, workers):
        client = Client(path='localhost:2883', buf_size=a.s)
        # client.tls = True
        # client.tls_ca = '/opt/workstuff/psrt/certs/ca.crt'
        client.connect()
        clients.append(client)
    th = []
    t_start = time.perf_counter()
    for i in range(0, workers):
        t = threading.Thread(target=pub, args=(clients[i], i))
        t.start()
        th.append(t)
    for t in th:
        t.join()
        th.clear()
    elapsed = time.perf_counter() - t_start
    print(f'Publish {payload_size} bytes: {n*workers} messages in '
          f'{elapsed} seconds, {n*workers/elapsed} messages/sec')
    for i in range(0, workers):
        clients[i].subscribe(f'{topic}-{i}')
        clients[i].on_message = on_message
    c = 0
    t_start = time.perf_counter()
    for i in range(0, workers):
        t = threading.Thread(target=pub, args=(clients[i], i))
        t.start()
    while c < n * workers:
        time.sleep(0.1)
    elapsed = time.perf_counter() - t_start
    print(f'Pub/sub {payload_size} bytes: {c} messages in '
          f'{elapsed} seconds, {c/elapsed} messages/sec')
finally:
    for i in range(0, workers):
        clients[i].bye()
