from threading import Thread
import os
import sys
import time
import rsa
def printSig(sign):
    x = ""
    print "\n--\n--\n--\n"
    for a in sign:
        x+=str(ord(a))
    print len(x)
    print x,"\n\n"
class remoteSocketClient(Thread):
    localSocket=None
    localPublicKey=None
    def __init__(self,Socket,pub,priv):
        self.socket=Socket
        self.privateKey = priv
        self.allPublicKeys = pub
        self.clientPublicKey = None
        self.running = True
        self.myPublicKey = rsa.PublicKey(priv.n,priv.e)
        self.random=""
        for x in os.urandom(20):
            self.random+=str(ord(x))
        self.socket.send("random=+=+"+self.random)
        Thread.__init__(self)
        self.buffer = []
        print remoteSocketClient.localSocket
    def run(self):
        inputBufferString = ""
        while self.running:
            sys.stdout.flush()
            inputBufferString=inputBufferString+self.socket.recv(500000)
            if inputBufferString=="":
                print "closing socket"
                break
            executeString = inputBufferString.split("ending")[0]
            if "key" in  executeString:
                randomString = executeString.split(":::")[0]
                print randomString
                if self.random not in randomString:
                    print "Invalid Random String"
                    print "Bye Bye"
                    self.socket.close()
                    break
                    self.running = False
                keyString = executeString.split(":::")[1]
                signString = executeString.split(":::")[-1].split('=+=+')[-1]
                checkMessage = randomString+":::"+keyString
                print checkMessage
                printSig(signString)
                print signString
                self.clientPublicKey=rsa.PublicKey.load_pkcs1(keyString.split("=+=+")[-1])
                try:
                    rsa.verify(checkMessage,signString,self.clientPublicKey)
                    print "Success!"
                except rsa.VerificationError:
                    self.sendMessage("Signature Mismatch. Closing. Bye Bye")
                    print self.socket.recv(10000)
                    self.socket.close()
                    self.running=False
                    print "Signature Mismatch. Closing. Bye Bye"
                if self.clientPublicKey not in self.allPublicKeys:
                    self.sendMessage("Public Key not Found. Closing. Bye Bye")
                    self.socket.close()
                    self.running=False
                    print "Public Key not Found. Closing. Bye Bye"
            else:
                self.execute(executeString)
            inputBufferString=inputBufferString.split("ending")[-1]
    def execute(self, executeString):
        try:
            print "message length = ",len(executeString)
            message = rsa.decrypt(executeString,self.privateKey)
            print message
            if "rpi-server" in message:
                remoteSocketClient.localSocket=self.socket
                remoteSocketClient.localPublicKey=self.clientPublicKey
                print "RPI Server Set"
            elif remoteSocketClient.localSocket is not None:
                toSend = rsa.encrypt(message,remoteSocketClient.localPublicKey)+"ending"
                remoteSocketClient.localSocket.send(toSend)
        except rsa.DecryptionError:
            self.running=False
            print "DecryptionError Socket Closed"
            self.socket.close()
    def sendMessage(self,message):
        try:
            toSend = rsa.encrypt(message,self.clientPublicKey)+"ending"
            self.socket.send(message)
        except rsa.DecryptionError, err:
            print " Error"
            print err #Remove during run time
class localSocketClient(Thread):
        def __init__(self,Socket,rpub,priv):
            self.socket=Socket
            self.privateKey = priv
            self.remotePublicKey = rpub
            self.running = True
            self.myPublicKey = rsa.PublicKey(priv.n,priv.e)
#            self.servo = Servo
            firstMessage = self.socket.recv(200000)
            self.random = firstMessage.split("=+=+")[-1]
            print (self.random)
            Thread.__init__(self)
            self.buffer = []
            self.sendPublicKey()

        def run(self):
            inputBufferString = ""
            zeroCount = 0
            while self.running:
                sys.stdout.flush()
                inputBufferString=inputBufferString+self.socket.recv(500000)
                if inputBufferString=="":
                    print "closing socket"
                    break
                self.execute(inputBufferString.split("ending")[0])
                inputBufferString=inputBufferString.split("ending")[-1]
        def execute(self, executeString):
            try:
                message = rsa.decrypt(executeString,self.privateKey)
                print message
                if "open" in message:
#                    self.servo.open()
                    print "open"
                elif "close" in message:
#                    self.servo.close()
                    print "close"
            except rsa.DecryptionError:
                print "socket clsoing"
                self.socket.close()
                print "Decryption Error"
        def sendMessage(self,message):
            encryptedMessage = rsa.encrypt(message,self.remotePublicKey)
            self.socket.send(encryptedMessage+"ending")
            print "Sending encrypted Message"
        def sendPublicKey(self):
            toSend = "random=+=+"+self.random
            toSend=toSend.encode("ascii")
            toSend+=":::key=+=+"+self.myPublicKey.save_pkcs1()
            toSend = toSend.encode("ascii")
            print toSend
            signature = rsa.sign(toSend,self.privateKey,"SHA-1")
            printSig(signature)
            bob = toSend+":::"+"sign=+=+"+signature+"ending"
            self.socket.send(bob)
