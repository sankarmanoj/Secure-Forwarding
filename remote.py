import socket
import rsa
from threading import Thread
from socketclient import remoteSocketClient
runServer = True
def loadPubKey(pubPath):
    with open(pubPath,"r") as pubFile:
        pubString = pubFile.read()
        publicKey = rsa.PublicKey.load_pkcs1(pubString)
        return publicKey
def loadPrivKey(privPath):
    with open(privPath,"r") as privFile:
        privString = privFile.read()
        privateKey = rsa.PrivateKey.load_pkcs1(privString)
        return privateKey
privateKey = loadPrivKey("door-remote.priv")
paths=("door-local.pub",)
pubkeys=[]
for path in paths:
    pubkeys.append(loadPubKey(path))
def Server():
    server=socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("",8347))
    server.listen(5)
    print "Server started..."
    while runServer:
        client, addr = server.accept()
        print addr
        newClient = remoteSocketClient(client,pubkeys,privateKey)
        newClient.start()
Server()
