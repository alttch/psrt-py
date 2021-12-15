from psrt import pub_udp, AUTH_KEY_AES_128_GCM, AUTH_KEY_AES_256_GCM

pub_udp('localhost:2873',
        'abcxxx',
        'hello',
        user='user1',
        password='123',
        need_ack=True)

pub_udp(
    'localhost:2873',
    'mytopic',
    'hello',
    user='user1',
    password='26fd38045707792a9bc50f3761a58987c4a9362cf60389f341c28e37b1125d93',
    auth=AUTH_KEY_AES_256_GCM,
    need_ack=True)
