from psrt import pub_udp

pub_udp('localhost:2873',
        'abcxxx',
        'hello',
        user='user1',
        password='123',
        need_ack=True)
