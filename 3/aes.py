from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from constants import KEY_SIZES,BLOCK_SIZE,IV_SIZE,IV_BYTE_ORDER,SEGMENT_SIZE,AES_MODES


def xorBytes(b1, b2): 
    result = [bytes([b1 ^ b2]) for b1, b2 in zip(b1, b2)]
    return b''.join(result)


def SplitData(data, chunk_size):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]


def spreadIv(iv):
    spreadedIv = int.from_bytes(iv, byteorder=IV_BYTE_ORDER) + 1
    return spreadedIv.to_bytes(IV_SIZE,  byteorder=IV_BYTE_ORDER)

def checkInput(mode, data):
    return mode != 'ctr' and len(data) % BLOCK_SIZE != 0


class AesOperator:
    """
    Sets mode, cipher, IV for operator
    """
    def __init__(self, key, mode, iv=None):
        mode = mode.lower()
        if mode not in AES_MODES:
            return None

        self.cipherMode = mode
        self.cipher = AES.new(key, AES.MODE_ECB)
        
        if mode != 'ecb':
            if iv is None:
                return None
            if len(iv) != BLOCK_SIZE:
                return None
        self.iv = iv
        
    
    """
    Encrypts single block
    """
    def _AesBlockEncrypt(self, block):
        return self.cipher.encrypt(block)

    """
    Decrypts single block
    """
    def _AesBlockDecrypt(self, block):
        return self.cipher.decrypt(block)

    """
    Splits message into blocks and encrypts it
    """
    def encrypt(self, data):
        if checkInput(self.cipherMode, data):
            data = pad(data, BLOCK_SIZE)
        
        self.method = self._AesBlockEncrypt
        if self.cipherMode == 'ecb':
            return self._AesEcb(data)
        if self.cipherMode == 'ctr':
            return self._AesCtr(data)    
        if self.cipherMode == 'cbc':
            return self._AesCbcEncrypt(data)
        if self.cipherMode == 'cfb':
            return self._AesCfbEncrypt(data)
        if self.cipherMode == 'ofb':
            return self._AesOfbEncrypt(data)

    """
    Decrypts message after splitting into blocks
    """
    def decrypt(self, data):
        if checkInput(self.cipherMode, data):
            raise Exception('Block size must be a multiple of 16')
        
        self.method = self._AesBlockDecrypt
        if self.cipherMode == 'ecb':
            chiperText = self._AesEcb(data)
        else:
            self.iv = data[:IV_SIZE]
            data = data[IV_SIZE:]

            if self.cipherMode == 'ctr':
                chiperText = self._AesCtr(data, True)
            if self.cipherMode == 'cbc':
                chiperText = self._AesCbcDecrypt(data)
            if self.cipherMode == 'cfb':
                chiperText = self._AesCfbDecrypt(data)
            if self.cipherMode == 'ofb':
                chiperText = self._AesOfbDecrypt(data)
        try:
            return unpad(chiperText, BLOCK_SIZE)
        except ValueError:
            return chiperText

    def _AesEcb(self, data):
        blocks = SplitData(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            result += self.method(block)
        return result

    def _AesCbcEncrypt(self, data):
        blocks = SplitData(data, BLOCK_SIZE)

        result = self.iv
        for block in blocks:
            input = xorBytes(block, self.iv)
            cipherBlock = self._AesBlockEncrypt(input)
            result += cipherBlock
            self.iv = cipherBlock
        return result

    def _AesOfbEncrypt(self, data):
        blocks = SplitData(data, BLOCK_SIZE)

        result = self.iv
        for block in blocks:
            cipherBlock = self._AesBlockEncrypt(self.iv)
            self.iv = cipherBlock
            result += xorBytes(block, cipherBlock)
        return result

    def _AesCfbEncrypt(self, data):
        blocks = SplitData(data, BLOCK_SIZE)
        
        result = self.iv
        for block in blocks:
            cipherBlock = self._AesBlockEncrypt(self.iv)
            xorBlock = xorBytes(block, cipherBlock)
            self.iv = xorBlock
            result += xorBlock
        return result

    def _AesCtr(self, data, decrypt=False):
        blocks = SplitData(data, BLOCK_SIZE)
        
        result = b'' if decrypt else self.iv
        for block in blocks:
            cipherBlock = self._AesBlockEncrypt(self.iv)
            xorBlock = xorBytes(block, cipherBlock)
            self.iv = spreadIv(self.iv)
            result += xorBlock
        return result

    def _AesCbcDecrypt(self, data):
        blocks = SplitData(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            cipherOutput = self._AesBlockDecrypt(block)
            result += xorBytes(self.iv, cipherOutput)
            self.iv = block
        return result

    def _AesCfbDecrypt(self,data):
        blocks = SplitData(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            cipherOutput = self._AesBlockEncrypt(self.iv)
            result += xorBytes(block, cipherOutput)
            self.iv = block
        return result

    def _AesOfbDecrypt(self, data):
        blocks = SplitData(data, BLOCK_SIZE)
        result = b''
        for block in blocks:
            cipherOutput = self._AesBlockEncrypt(self.iv)
            self.iv = cipherOutput
            result += xorBytes(block, cipherOutput)
        return result

    