import rsa
import socket
from socketclient import localSocketClient
def loadKeys(pubPath,privPath):
    with open(privPath,"r") as privFile:
        privString = privFile.read()
        privateKey = rsa.PrivateKey.load_pkcs1(privString)
    with open(pubPath,"r") as pubFile:
        pubString = pubFile.read()
        publicKey = rsa.PublicKey.load_pkcs1(pubString)
        return publicKey,privateKey


(remotepublicKey,privateKey) = loadKeys("door-remote.pub","door-local.priv")
client = socket.socket()
client.connect(("localhost",8347))
cH = localSocketClient(client,remotepublicKey,privateKey)
cH.start()
cH.sendMessage("rpi-server")
