import logging
import select
import socket
import struct
import hashlib
import string
import random
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

from Crypto.Cipher import AES

import MyCryptor

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5

license = b"1357753124688642"

def aesKeyGenerator(length):
    if length != 32:
        return None
    x = string.ascii_letters+string.digits
    return ''.join([random.choice(x) for i in range(length)])

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        state = 0
        publicKey = None
        aesKey = None
        if state==0:
            stringBuffer = b""
            while True:
                newData = self.connection.recv(1024)
                if len(newData) > 0:
                    stringBuffer = stringBuffer + newData
                    logging.info("rsa stringbuffer : " + str(stringBuffer))
                    if len(stringBuffer) >= 303:
                        digest = hashlib.sha256(stringBuffer[:271]+license).digest()
                        digest_ = stringBuffer[271:]
                        if not digest == digest_:
                            raise ValueError("Digest not match")
                        publicKey = RSA.importKey(stringBuffer[:271])
                        state = 1
                        break
                else:
                    break
            logging.info("public_rsa_key : " + str(publicKey))

        if state==1:
            aesKey = aesKeyGenerator(32)
            logging.info("aesKey: " + str(aesKey))
            aesCryptor = MyCryptor.MyCryptor(aesKey, AES.MODE_CFB, license)
            rsaCryptor = Cipher_pkcs1_v1_5.new(publicKey)
            cipherText = rsaCryptor.encrypt(aesKey.encode(encoding="utf-8"))
            self.connection.sendall(cipherText)

        # request
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length)

        port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logging.info(address)
                remote.connect((address, port))
                logging.info("heiheihei")
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            #reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                                #addr, port)
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1,
                                addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        assert len(reply) <= 255
        length = len(reply)
        while len(reply) < 255:
            reply += b'0'
        reply = length.to_bytes(1, "little") + reply
        logging.info("len(reply) : " + str(len(reply)))
        assert len(reply) == 256
        reply = aesCryptor.encrypt(reply)
        self.connection.sendall(reply)

        # establish data exchange
        # if reply[1] == 0 and cmd == 1:
        logging.info("exchange_loop now")
        self.exchange_loop(self.connection, remote, aesKey)

        self.server.close_request(self.request)

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote, aesKey):

        aesCryptor = MyCryptor.MyCryptor(aesKey, AES.MODE_CFB, license)

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                newData = client.recv(256)
                logging.info("len newData " + str(len(newData)))
                while len(newData) < 256:
                    logging.info("len newData " + str(len(newData)))
                    newData += client.recv(256 - len(newData))
                assert len(newData) == 256
                data = aesCryptor.decrypt(newData)
                length = int(data[0])
                data = data[1:length+1]
                if remote.send(data) < 0:
                    break

            if remote in r:
                newData = remote.recv(255)
                length = len(newData)
                while len(newData) < 255:
                    newData += b'0'
                toEncrypt = length.to_bytes(1,"little") + newData
                data = aesCryptor.encrypt(toEncrypt)
                assert len(data) == 256
                if client.send(data) < 0:
                    break


if __name__ == '__main__':
    with ThreadingTCPServer(('127.0.0.1', 1234), SocksProxy) as server:
        server.serve_forever()
