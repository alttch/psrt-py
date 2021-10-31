from psrt import pub_udp

pub_udp('localhost:2883', 'xxx', 'hello', need_ack=True)
