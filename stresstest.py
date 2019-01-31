import requests
import threading
import socket
import socks

# Set up a proxy
socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', 11223)
socket.socket = socks.socksocket

def do_request():
    while 1:
        resp = requests.get('http://tonarchiv.ch')
        print(resp.status_code)
for i in range(0,4):
    try:
       t=threading.Thread(target=do_request)
       t.start()
    except:
       print ("Error: unable to start thread")
while 1:
   pass

