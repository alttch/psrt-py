
.. py:module:: psrt


.. py:exception:: AccessError
   :module: psrt


.. py:class:: Client(**kwargs)
   :module: psrt

   PSRT client
   
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
   
   
   .. py:method:: Client.bye()
      :module: psrt
   
      End communcation
      
   
   .. py:method:: Client.connect(host=None, port=2873, keepalive=None)
      :module: psrt
   
      Connect the client
      
      Optional:
          * host: ovverride server host
          * port: override server port
          * keepalive: not used, for paho-mqtt compat-only
      
   
   .. py:method:: Client.connect_cluster(paths, randomize=True)
      :module: psrt
   
      Connect the client to PSRT cluster
      
      If randomize parameter is set to False, the nodes are chosen in the
      listed order
      
      :param paths: list of node paths (host:port or tuples)
      
      Optional:
          * randomize: choose random node (default: True)
      
      :returns: Successful node path if connected
      
      :raises RuntimeError: if no nodes available
      
   
   .. py:method:: Client.is_connected()
      :module: psrt
   
      Check is the client connected
      
   
   .. py:method:: Client.publish(topic, message, qos=None, retain=None)
      :module: psrt
   
      Publish a message
      
      :param topic: topic name
      :param message: message (string, bytes or anyting which can be str())
      
      Optional:
          * qos: not used, for paho-mqtt compat-only
          * retain: not used, for paho-mqtt compat-only
      
   
   .. py:method:: Client.subscribe(topic, qos=None)
      :module: psrt
   
      Subscribe to a topic
      
      :param topic: topic name
      
      Optional:
          * qos: not used, for paho-mqtt compat-only
      
   
   .. py:method:: Client.subscribe_bulk(topics)
      :module: psrt
   
      Subscribe to topics
      
      :param topics: topic names (list or tuple)
      
      Optional:
          * qos: not used, for paho-mqtt compat-only
      
   
   .. py:method:: Client.unsubscribe(topic)
      :module: psrt
   
      Unsubscribe from a topic
      
      :param topic: topic name
      
      Optional:
          * qos: not used, for paho-mqtt compat-only
      
   
   .. py:method:: Client.unsubscribe_bulk(topics)
      :module: psrt
   
      Unsubscribe from topics
      
      :param topics: topic names (list or tuple)
      
      Optional:
          * qos: not used, for paho-mqtt compat-only
      

.. py:function:: pub_udp(target, topic, message, need_ack=True, check_ack_src=True, **kwargs)
   :module: psrt

   Publish message with UDP frame
   
   :param target: host:port or (host, port) tuple
   :param topic: topic to publish
   :param message: message (string, bytes or anyting which can be str())
   
   Optional:
       * need_ack: require server acknowledge (default: True)
       * check_ack_src: check acknowledge source (host/port, default: True)
       * user: user name
       * password: password
       * timeout: socket timeout
   
