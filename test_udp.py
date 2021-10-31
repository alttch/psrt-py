from psrt import pub_udp

pub_udp('localhost:2883', 'xxx', 'hello'.encode(), need_ack=True)
