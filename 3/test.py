from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad

from aes import AesOperator
from constants import BLOCK_SIZE, SEGMENT_SIZE, IV_SIZE,AES_MODES


TEST_KEYS=['140b41b22a29beb4061bda66b6747e14','36f18357be4dbd77f050515c73fcf9f2']


"""
Performs AesOperator output validation and prints it in formatted way
"""
def checkCipherOutput(correctEncrypt, key, value, mode, iv):
    cipher =  AesOperator(key, mode, iv)
    operatorEncrypt = cipher.encrypt(value)
    cipher =  AesOperator(key, mode, iv)
    operatorDecrypt = cipher.decrypt(operatorEncrypt)
    print('{} mode: encryption correctness: {} -- decryption correctness: {}'.format(
        mode, correctEncrypt == operatorEncrypt, value == operatorDecrypt
        )
    )

def decryptAesText(key, cipherText, mode):
    cipher =  AesOperator(key, mode)
    plaintext = cipher.decrypt(cipherText)
    print(plaintext)

def aesOperatorFunctionalityTestSuccess():
    print('\nAES FUNCTIONALITY CHECK\n')
    key = bytes.fromhex(TEST_KEYS[1])
    value = bytes.fromhex('0000000100020003000400050006000700080009000a000b000c000d000e000f0001000200030004')
    iv = bytes.fromhex('69dda8455c7dd4254bf353b773304eed')
     
    # ECB mode check
    cipher = AES.new(key, AES.MODE_ECB)
    e = cipher.encrypt(pad(value, BLOCK_SIZE))
    checkCipherOutput(e, key, value, 'ecb', iv)
     
    # CTR mode check
    counter=Counter.new(SEGMENT_SIZE, initial_value=int(iv.hex(), IV_SIZE))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    e = iv + cipher.encrypt(value)
    checkCipherOutput(e, key, value, 'ctr', iv)

    # CBC mode check
    cipher = AES.new(key, AES.MODE_CBC, iv)
    e = iv + cipher.encrypt(pad(value, BLOCK_SIZE))
    checkCipherOutput(e, key, value, 'cbc', iv)
     
    # CFB mode check
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=SEGMENT_SIZE)
    e = iv + cipher.encrypt(pad(value, BLOCK_SIZE))
    checkCipherOutput(e, key, value, 'cfb', iv)
     
    # OFB mode check
    cipher = AES.new(key, AES.MODE_OFB, iv)
    e = iv + cipher.encrypt(pad(value, BLOCK_SIZE))
    checkCipherOutput(e, key, value, 'ofb', iv)


def attacksCheck():
    print(' \nDO NOT FORGET ABOUT THESE RULES \n')

    # Padding rule
    key = bytes.fromhex(TEST_KEYS[0])
    cipherText = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
    decryptAesText(key,cipherText,'cbc')

    # Randomisation rule
    key = bytes.fromhex(TEST_KEYS[0])
    cipherText = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
    decryptAesText(key,cipherText,'cbc')
    
    # CTR stream
    key = bytes.fromhex(TEST_KEYS[1])
    cipherText = bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
    decryptAesText(key,cipherText,'ctr')

    # Avoid two-time pad
    key = bytes.fromhex(TEST_KEYS[1])
    cipherText = bytes.fromhex('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
    decryptAesText(key,cipherText,'ctr')


aesOperatorFunctionalityTestSuccess()
attacksCheck()