import os
import sys
import time
import socket
import logging
from Queue import Queue
from threading import Thread

from daemon import Daemon
from settings import CONTROLLER_IP, CONTROLLER_PORT, SOCKFILE, BUFSIZE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
            time.sleep(0.01)
            data = self.unsock.recv(BUFSIZE)
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
        logger.info("Network socket sending...")
        self.send_loop_consumer(in_q)

    def send_loop_consumer(self, in_q):
        while True:
            data = in_q.get()
            self.nwsock.sendall(data)
            time.sleep(0.01)
            logger.info("Send the alert messages to Ryu.")


class PigrelayDaemon(Daemon):
    def run(self):
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

        while True:
            time.sleep(1)


if __name__ == '__main__':
    daemon = PigrelayDaemon('/tmp/daemon.pid')
    # daemon.run()
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
            sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
