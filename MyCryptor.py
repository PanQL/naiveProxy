from Crypto.Cipher import AES

class MyCryptor:
    def __init__(self, key, mode, iv):
        self._key = key
        self._mode = mode
        self._iv = iv
        
    def encrypt(self, plainText):
        aesCryptor = AES.new(self._key, self._mode, self._iv)
        return aesCryptor.encrypt(plainText)
        
    def decrypt(self, cipherText):
        aesCryptor = AES.new(self._key, self._mode, self._iv)
        return aesCryptor.decrypt(cipherText)
        
