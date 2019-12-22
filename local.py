import logging
import select
import socket
import struct
import hashlib
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

from Crypto.Cipher import AES

import MyCryptor

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5

license = b"1357753124688642"


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        # read and unpack 2 bytes from a client
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        # socks 5
        assert version == SOCKS_VERSION
        assert nmethods > 0

        # get available methods
        methods = self.get_available_methods(nmethods)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            self.server.close_request(self.request)
            return

        # send welcome message
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        if not self.verify_credentials():
            return

        # request
        stringBuffer = self.connection.recv(4)
        if len(stringBuffer) < 4:
            self.connection.close()
            return
        version, cmd, _, address_type = struct.unpack("!BBBB", stringBuffer)
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            ipv4_addr = self.connection.recv(4)
            stringBuffer += ipv4_addr
            address = socket.inet_ntoa(ipv4_addr)
        elif address_type == 3:  # Domain name
            recv_domain_len = self.connection.recv(1)[0]
            stringBuffer += recv_domain_len
            domain_length = ord(recv_domain_len)
            recv_domain_addr = self.connection.recv(domain_length)
            stringBuffer += recv_domain_addr
            address = recv_domain_addr

        recv_port = self.connection.recv(2)
        stringBuffer += recv_port
        port = struct.unpack('!H', recv_port)[0]

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(("127.0.0.1", 1234))
            # 分发RSA公钥
            # 生成一对RSA公钥和私钥
            random_generator = Random.new().read
            rsa = RSA.generate(1024, random_generator)
            private_key = rsa.exportKey()
            public_key = rsa.publickey().exportKey()
            logging.info("public_rsa_key : " + str(public_key))
            # 将公钥发送给远程服务器端
            message = public_key + hashlib.sha256(public_key+license).digest()
            length = len(message)
            logging.info("message : " + str(message))
            x = remote.send(message)
            if x != length:
                logging.error("send rsa public key failed : " + str(x))
            # 获取服务器分发的AES密钥
            rsaCryptor = Cipher_pkcs1_v1_5.new(RSA.importKey(private_key))
            cipherText = b""
            aesKey = None
            while True:
                newData = remote.recv(1024)
                cipherText = cipherText + newData
                if len(newData) > 0:
                    try:
                        aesKey = rsaCryptor.decrypt(cipherText, None).decode("utf-8")
                        break
                    except Exception as e:
                        logging.error("recving aes key -- " + type(e).__name__ + ": " + e)
                        pass
                else:
                    logging.error("recv aes key failed : closing socket....")
                    remote.close()
                    exit(0)
            logging.info("aesKey: " + str(aesKey))
            remote.sendall(stringBuffer)
        except Exception as err:
            logging.error("this error!")
            logging.error(err)
            self.connection.close()
            return
        
        self.exchange_loop(self.connection, remote, aesKey)
        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote, aesKey):

        aesCryptor = MyCryptor.MyCryptor(aesKey, AES.MODE_CFB, license)

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                newData = client.recv(255)
                length = len(newData)
                while len(newData) < 255:
                    newData += b'0'
                toEncrypt = length.to_bytes(1, "little") + newData
                assert len(toEncrypt) == 256
                data = aesCryptor.encrypt(toEncrypt)
                logging.info("from client , data : " + str(len(data)))
                if remote.send(data) <= 0:
                    break

            if remote in r:
                newData = remote.recv(256)
                logging.info("len newData " + str(len(newData)))
                while len(newData) < 256:
                    # logging.info("len newData " + str(len(newData)))
                    newData += remote.recv(256 - len(newData))
                assert len(newData) == 256
                data = aesCryptor.decrypt(newData)
                length = int(data[0])
                data = data[1:length + 1]
                logging.info("response from proxy : " + str(len(data)))
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    with ThreadingTCPServer(('127.0.0.1', 8080), SocksProxy) as server:
        server.serve_forever()
