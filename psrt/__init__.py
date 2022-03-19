__version__ = '0.0.18'

import threading
import socket
import logging
import time
import logging

from types import SimpleNamespace

# logger for background processes (pinger and data stream)
logger = logging.getLogger('psrt')

DEFAULT_PORT = 2873

DEFAULT_TIMEOUT = 5
BUF_SIZE = 1024

PROTO_VERSION = 1
SLEEP_STEP = 0.1

OP_NOP = b'\x00'
OP_BYE = b'\xFF'

OP_PUBLISH = b'\x01\x7F'  # priority hard-coded until supported
OP_PUBLISH_NO_ACK = b'\x21\x7F'  # priority hard-coded until supported
OP_SUBSCRIBE = b'\x02'
OP_UNSUBSCRIBE = b'\x03'

RESPONSE_OK = 0x01
RESPONSE_ACCESS_DENIED = 0xFE

CONTROL_HEADER = b'\xEE\xAA'
DATA_HEADER = b'\xEE\xAB'

AUTH_LOGIN_PASS = b'\x00'
AUTH_KEY_AES_128_GCM = b'\x02'
AUTH_KEY_AES_256_GCM = b'\x03'


def pub_udp(target,
            topic,
            message,
            need_ack=True,
            check_ack_src=True,
            auth=AUTH_LOGIN_PASS,
            **kwargs):
    """
    Publish message with UDP frame

    Args:
        target: host:port or (host, port) tuple
        topic: topic to publish
        message: message (string, bytes or anyting which can be str())

    Optional:
        * need_ack: require server acknowledge (default: True)
        * check_ack_src: check acknowledge source (host/port, default: True)
        * user: user name
        * password: password
        * timeout: socket timeout
        * auth: auth mode (password is used as AES key, str or bytes)
    """
    if isinstance(target, str):
        host, port = target.rsplit(':', maxsplit=1)
        if check_ack_src:
            host = socket.gethostbyname(host)
        target = (host, int(port))
    elif check_ack_src:
        target = (socket.gethostbyname(target[0]), target[1])
    user = kwargs.get('user', '')
    password = kwargs.get('password', '')
    timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
    topic = topic
    if isinstance(message, bytes):
        pass
    elif isinstance(message, str):
        message = message.encode()
    else:
        message = str(message).encode()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if auth == AUTH_LOGIN_PASS:
        client_socket.sendto(
            CONTROL_HEADER + PROTO_VERSION.to_bytes(2, 'little') +
            AUTH_LOGIN_PASS + user.encode() + b'\x00' + password.encode() +
            b'\x00' + (OP_PUBLISH if need_ack else OP_PUBLISH_NO_ACK) +
            topic.encode() + b'\x00' + message, target)
    else:
        from Cryptodome import Random
        from Cryptodome.Cipher import AES
        nonce = Random.new().read(12)
        if isinstance(password, str):
            import binascii
            password = binascii.unhexlify(password)
        cipher = AES.new(password, AES.MODE_GCM, nonce)
        frame, digest = cipher.encrypt_and_digest(
            (OP_PUBLISH if need_ack else OP_PUBLISH_NO_ACK) + topic.encode() +
            b'\x00' + message)
        client_socket.sendto(
            CONTROL_HEADER + PROTO_VERSION.to_bytes(2, 'little') + auth +
            user.encode() + b'\x00' + nonce + frame + digest, target)
    if need_ack:
        client_socket.settimeout(timeout)
        (data, server) = client_socket.recvfrom(5)
        if check_ack_src and server != target:
            raise RuntimeError(f'Invalid ack source: {server}')
        if data[0:2] != CONTROL_HEADER:
            raise RuntimeError(f'Invalid control header in ack')
        if int.from_bytes(data[2:4], 'little') != PROTO_VERSION:
            raise RuntimeError(f'Invalid server protocol in ack')
        code = data[4]
        if code == RESPONSE_ACCESS_DENIED:
            raise AccessError
        elif code != RESPONSE_OK:
            raise RuntimeError(f'Server error: {data[0]}')


class Message:
    qos = 2
    retain = False


class AccessError(Exception):
    pass


def reduce_timeout(timeout, m):
    t = timeout - (time.perf_counter() - m)
    if t <= 0:
        raise TimeoutError
    return t


class Client:
    """
    PSRT client
    """

    # paho mqtt compat
    def tls_set(self, ca_certs, *args, **kwargs):
        self.tls = True
        self.tls_ca = ca_certs

    def username_pw_set(self, username, password=''):
        self.user = username if username is not None else ''
        self.password = password if password is not None else ''

    def loop_start(self):
        pass

    def loop_stop(self):
        pass

    # end compat

    def enable_logger(self):
        # TODO debug log
        pass

    def __init__(self, **kwargs):
        """
        Initialize PSRT client

        Additioanal properties which can be set directly to client object:

        * on_message = on_message(client, userdata, message) # message handler
        * on_connect(self, client, userdata, flags, rc) # connect handler

        (as the connection is performed in the current thread, on_connect is
        used for paho-mqtt compat. only)

        Optional:
            * path: host:port or (host, port) tuple
            * user: user name
            * password: password
            * timeout: client timeout
            * buf_size: socket and message buffer (set 100K+ for large frames)
            * userdata: anything useful
            * tls: use TLS (default: False)
            * tls_ca: path to an alternative CA file
        """
        self.path = kwargs.get('path', f'localhost:{DEFAULT_PORT}')
        self.user = kwargs.get('user', '')
        self.password = kwargs.get('password', '')
        self.timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
        self.buf_size = kwargs.get('buf_size', BUF_SIZE)
        self.userdata = kwargs.get('userdata')
        self.tls = kwargs.get('tls', False)
        self.tls_ca = kwargs.get('tls_ca')
        self.connected = False
        self._state = 0
        self.connect_event = threading.Event()
        self.control_lock = threading.Lock()
        self.shutdown_lock = threading.RLock()
        self._h_pinger = None
        self.on_message = None
        self.on_connect = None
        self.need_data_socket = True
        self.control_socket = None
        self.data_socket = None
        self.disconnect = self.bye

    def _shutdown(self, from_pinger):
        self.connected = False
        self._state = 0
        try:
            self.control_socket.close()
        except:
            pass
        try:
            self.data_socket.close()
        except:
            pass
        if not from_pinger and self._h_pinger is not None and \
                self._h_pinger.is_alive():
            self._h_pinger.join()

    def _handle_control_response(self, from_pinger):
        response = int.from_bytes(self.control_socket.recv(1), 'little')
        if response != RESPONSE_OK:
            if response == RESPONSE_ACCESS_DENIED:
                raise AccessError
            else:
                self._shutdown(from_pinger)
                raise RuntimeError(f'server error {self.path}: {hex(response)}')

    def _exec_control_command(self, payload, from_pinger=False):
        op_start = time.perf_counter()
        try:
            if not self.control_lock.acquire(timeout=self.timeout):
                raise TimeoutError(
                    f'client error {self.path} control lock timeout')
            try:
                self.control_socket.settimeout(
                    reduce_timeout(self.timeout, op_start))
                self.control_socket.sendall(payload)
                self.control_socket.settimeout(
                    reduce_timeout(self.timeout, op_start))
                self._handle_control_response(from_pinger)
            finally:
                self.control_lock.release()
        except:
            self._shutdown(from_pinger)
            raise

    def _pinger(self):
        while self.connected:
            try:
                self._exec_control_command(OP_NOP, True)
            except Exception as e:
                if not self.connected:
                    break
                logger.error(f'server {self.path} ping error: {e}')
                raise
            sleep_to = time.perf_counter() + self.timeout / 2
            while time.perf_counter() < sleep_to and self.connected:
                time.sleep(SLEEP_STEP)

    def connect_cluster(self, paths, randomize=True):
        """
        Connect the client to PSRT cluster

        If randomize parameter is set to False, the nodes are chosen in the
        listed order

        Args:
            paths: list of node paths (host:port or tuples) or comma separated
            string

        Optional:
            * randomize: choose random node (default: True)

        Returns:
            Successful node path if connected

        Raises:
            RuntimeError: if no nodes available
        """
        if isinstance(paths, str):
            paths = [x for x in [x.strip() for x in paths.split(',')] if x]
        if randomize:
            import random
            paths = paths.copy()
            random.shuffle(paths)
        for p in paths:
            logger.info(f'trying PSRT node {p}')
            self.path = p
            try:
                self.connect()
                logger.info(f'PSRT node connected: {p}')
                return p
            except Exception as e:
                logger.warning(f'Failed to connect to {p}: {e}')
        raise RuntimeError('no nodes available')

    def connect(self, host=None, port=DEFAULT_PORT, keepalive=None):
        """
        Connect the client

        Optional:
            * host: ovverride server host
            * port: override server port
            * keepalive: not used, for paho-mqtt compat-only
        """
        self.connect_event.clear()
        self.connected = False
        if host is None:
            if ':' in self.path:
                host, port = self.path.rsplit(':', maxsplit=1)
            else:
                host = self.path
                port = DEFAULT_PORT
        else:
            self.path = f'{host}:{port}'
        port = int(port)
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                  self.buf_size)
        control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                  self.buf_size)
        control_socket.settimeout(self.timeout)
        op_start = time.perf_counter()
        control_socket.connect((host, port))
        control_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        control_socket.settimeout(reduce_timeout(self.timeout, op_start))
        control_socket.sendall(CONTROL_HEADER +
                               (b'\x01' if self.tls else b'\x00'))
        control_socket.settimeout(reduce_timeout(self.timeout, op_start))
        if self.tls:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.verify_mode = ssl.CERT_REQUIRED
            if self.tls_ca:
                context.load_verify_locations(self.tls_ca)
            control_socket = context.wrap_socket(control_socket)
        header = control_socket.recv(2)
        if len(header) < 2:
            raise RuntimeError('Server connection error')
        if header != CONTROL_HEADER:
            raise RuntimeError('Invalid control header')
        control_socket.settimeout(reduce_timeout(self.timeout, op_start))
        proto = int.from_bytes(control_socket.recv(2), 'little')
        if proto != PROTO_VERSION:
            raise RuntimeError('Unsupported protocol')
        data = self.user.encode() + b'\x00' + self.password.encode()
        control_socket.settimeout(reduce_timeout(self.timeout, op_start))
        control_socket.sendall(len(data).to_bytes(4, 'little') + data)
        try:
            control_socket.settimeout(reduce_timeout(self.timeout, op_start))
            token = control_socket.recv(32)
            if not token:
                raise AccessError
            while len(token) < 32:
                control_socket.settimeout(reduce_timeout(
                    self.timeout, op_start))
                token += control_socket.recv(1)
        except:
            raise AccessError
        self.control_socket = control_socket
        # connect data socket
        if self.need_data_socket:
            try:
                data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                       self.buf_size)
                data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                       self.buf_size)
                data_socket.settimeout(reduce_timeout(self.timeout, op_start))
                data_socket.connect((host, port))
                data_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                                       1)
                data_socket.settimeout(reduce_timeout(self.timeout, op_start))
                data_socket.sendall(DATA_HEADER +
                                    (b'\x01' if self.tls else b'\x00'))
                if self.tls:
                    data_socket = context.wrap_socket(data_socket)
                data_socket.settimeout(reduce_timeout(self.timeout, op_start))
                header = data_socket.recv(2)
                if header != DATA_HEADER:
                    raise RuntimeError('Invalid data header')
                data_socket.settimeout(reduce_timeout(self.timeout, op_start))
                proto = int.from_bytes(data_socket.recv(2), 'little')
                if proto != PROTO_VERSION:
                    raise RuntimeError('Unsupported protocol')
                data_socket.settimeout(reduce_timeout(self.timeout, op_start))
                data_socket.sendall(token +
                                    int(self.timeout).to_bytes(1, 'little'))
                data_socket.settimeout(reduce_timeout(self.timeout, op_start))
                response = int.from_bytes(data_socket.recv(1), 'little')
                if response != RESPONSE_OK:
                    self._shutdown(False)
                    raise RuntimeError(
                        f'server error (data socket) {self.path}: '
                        f'{hex(response)}')
                data_socket.settimeout(self.timeout)
                self.data_socket = data_socket
                threading.Thread(target=self._t_data_stream,
                                 daemon=True).start()
            except:
                try:
                    self.control_socket.close()
                except:
                    pass
                try:
                    data_socket.close()
                except:
                    pass
                raise
        # run control pinger
        self.connected = True
        self._state = 1
        self.connect_event.set()
        self._h_pinger = threading.Thread(target=self._pinger, daemon=True)
        self._h_pinger.start()
        if self.on_connect:
            self.on_connect(self, self.userdata, None, None)

    def _t_data_stream(self):
        try:
            while True:
                op_start = time.perf_counter()
                self.data_socket.settimeout(self.timeout)
                header = self.data_socket.recv(1)
                if not header:
                    raise RuntimeError(
                        f'server {self.path} data socket disconnected')
                if header[0] == RESPONSE_OK:
                    self.data_socket.settimeout(
                        reduce_timeout(self.timeout, op_start))
                    priority = self.data_socket.recv(1)
                    self.data_socket.settimeout(
                        reduce_timeout(self.timeout, op_start))
                    data_len_buf = self.data_socket.recv(4)
                    while len(data_len_buf) < 4:
                        self.data_socket.settimeout(
                            reduce_timeout(self.timeout, op_start))
                        data_len_buf += self.data_socket.recv(1)
                    data_len = int.from_bytes(data_len_buf, 'little')
                    data = b''
                    while len(data) < data_len:
                        self.data_socket.settimeout(
                            reduce_timeout(self.timeout, op_start))
                        buf_size = data_len - len(data)
                        data += self.data_socket.recv(
                            buf_size if buf_size < self.buf_size else self.
                            buf_size)
                    message = Message()
                    topic, message.payload = data.split(b'\x00', maxsplit=1)
                    message.topic = topic.decode()
                    if self.on_message:
                        self.on_message(self, self.userdata, message)
                elif header[0] != 0:
                    raise RuntimeError(f'server {self.path} invalid data '
                                       f'in data stream: {hex(header[0])}')
        except Exception as e:
            with self.shutdown_lock:
                if self.connected:
                    logger.error(str(e))
                    self.bye()

    def is_connected(self):
        """
        Check is the client connected
        """
        return self.connected

    def subscribe(self, topic, qos=None):
        """
        Subscribe to a topic

        Args:
            topic: topic name

        Optional:
            * qos: not used, for paho-mqtt compat-only
        """
        data = topic.encode()
        try:
            self._exec_control_command(OP_SUBSCRIBE +
                                       len(data).to_bytes(4, 'little') + data)
        except AccessError:
            raise AccessError(f'{self.path} topic {topic} sub access denied')

    def subscribe_bulk(self, topics):
        """
        Subscribe to topics

        Args:
            topics: topic names (list or tuple)

        Optional:
            * qos: not used, for paho-mqtt compat-only
        """
        data = b'\x00'.join(t.encode() for t in topics)
        self._exec_control_command(OP_SUBSCRIBE +
                                   len(data).to_bytes(4, 'little') + data)

    def unsubscribe(self, topic):
        """
        Unsubscribe from a topic

        Args:
            topic: topic name

        Optional:
            * qos: not used, for paho-mqtt compat-only
        """
        data = topic.encode()
        self._exec_control_command(OP_UNSUBSCRIBE +
                                   len(data).to_bytes(4, 'little') + data)

    def unsubscribe_bulk(self, topics):
        """
        Unsubscribe from topics

        Args:
            topics: topic names (list or tuple)

        Optional:
            * qos: not used, for paho-mqtt compat-only
        """
        data = b'\x00'.join(t.encode() for t in topics)
        self._exec_control_command(OP_UNSUBSCRIBE +
                                   len(data).to_bytes(4, 'little') + data)

    def publish(self, topic, message, qos=None, retain=None):
        """
        Publish a message

        Args:
            topic: topic name
            message: message (string, bytes or anyting which can be str())
        Optional:
            * qos: not used, for paho-mqtt compat-only
            * retain: not used, for paho-mqtt compat-only
        """
        topic = topic.encode()
        if isinstance(message, bytes):
            pass
        elif isinstance(message, str):
            message = message.encode()
        else:
            message = str(message).encode()
        # copy code to avoid message copying
        op_start = time.perf_counter()
        if not self.control_lock.acquire(timeout=self.timeout):
            raise TimeoutError(f'client error {self.path} control lock timeout')
        try:
            self.control_socket.settimeout(
                reduce_timeout(self.timeout, op_start))
            self.control_socket.sendall(OP_PUBLISH +
                                        (len(topic) + len(message) +
                                         1).to_bytes(4, 'little') + topic +
                                        b'\x00')
            self.control_socket.settimeout(
                reduce_timeout(self.timeout, op_start))
            self.control_socket.sendall(message)
            try:
                self._handle_control_response(False)
            except AccessError:
                raise AccessError(
                    f'{self.path} topic {topic} pub access denied')
        finally:
            self.control_lock.release()

    def bye(self):
        """
        End communcation
        """
        with self.shutdown_lock:
            if self.connected:
                self._exec_control_command(OP_BYE)
                self._shutdown(False)
