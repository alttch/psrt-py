from psrt import pub_udp

pub_udp('localhost:2873', 'xxx', 'hello', need_ack=True)
