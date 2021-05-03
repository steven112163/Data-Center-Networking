# Send UDP broadcast packets
import time
from socket import *

MY_PORT = 50000
s = socket(AF_INET, SOCK_DGRAM)
s.bind(('', 0))
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
while 1:
    data = repr(0)
    s.sendto(data, ('10.255.255.255', MY_PORT))
    time.sleep(2)
