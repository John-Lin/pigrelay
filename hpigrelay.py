import os
import sys
import time
import socket
import logging
from Queue import Queue
from threading import Thread

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SOCKFILE = "/tmp/snort_alert"
BUFSIZE = 65863

# Must to set your controller IP here
CONTROLLER_IP = '127.0.0.1'

# Controller port is 51234 by default.
# If you want to change the port number
# you need to set the same port number in the controller application.
CONTROLLER_PORT = 51234


class SnortListener():
    def __init__(self):
        self.unsock = None

    def start_recv(self, out_q):
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.unsock.bind(SOCKFILE)
        logger.info("Unix Domain Socket listening...")
        self.recv_loop_producer(out_q)

    def recv_loop_producer(self, out_q):
        while True:
            data = self.unsock.recv(BUFSIZE)
            time.sleep(0.01)
            if data:
                logger.debug("Send {0} bytes of data.".format
                             (sys.getsizeof(data)))
                # data == 65900 byte
                out_q.put(data)


class SnortRelay():
    def __init__(self):
        self.nwsock = None

    def start_send(self, in_q):
        self.nwsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.nwsock.connect((CONTROLLER_IP, CONTROLLER_PORT))
        except Exception, e:
            logger.info("Network socket connection error: %s" % e)
            sys.exit()
        self.send_loop_consumer(in_q)

    def send_loop_consumer(self, in_q):
        while True:
            data = in_q.get()
            self.nwsock.sendall(data)
            logger.info("Send the alert messages to Ryu.")


if __name__ == '__main__':
    # Create the shared queue and launch both threads
    q = Queue()
    listener = SnortListener()
    relay = SnortRelay()

    t1 = Thread(target=listener.start_recv, args=(q,))
    t1.daemon = True
    t2 = Thread(target=relay.start_send, args=(q,))
    t2.daemon = True

    t1.start()
    t2.start()
