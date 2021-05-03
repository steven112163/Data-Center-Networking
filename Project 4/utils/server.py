# Receive UDP packets transmitted by a
# broadcasting service
import sys
from socket import *

MY_PORT = 50000
s = socket(AF_INET, SOCK_DGRAM)
s.bind(('', MY_PORT))
while 1:
    data, where_from = s.recvfrom(1500, 0)
    sys.stderr.write(repr(where_from) + '\n')
    sys.stdout.write(data)
