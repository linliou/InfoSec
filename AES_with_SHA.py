from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512

def aesEncrypt(message, key, iv):
    cipher_Encrypt = AES.new(key,AES.MODE_OFB,iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext


def aesDecrypt(encrypted, key, iv):
    cipher_Decrypted = AES.new(key,AES.MODE_OFB,iv)
    plaintext = cipher_Decrypted.decrypt(encrypted)
    return plaintext


def aesEncryptWithSHA512(message, key, iv):
    hash_Func = SHA512.new()
    hash_Func.update((message))
    hashOfMsg=hash_Func.digest()
    print("SHA512Message: ",hashOfMsg.hex())
    return aesEncrypt(hashOfMsg + message, key, iv)

def aesDecryptWithSHA512(encryptedWithSHA512, key, iv):
    decryptedTemp = aesDecrypt(encryptedWithSHA512, key, iv)
    decryptedSHA512 = decryptedTemp[:SHA512.digest_size]
    decryptedMsg = decryptedTemp[SHA512.digest_size:]
    return decryptedSHA512, decryptedMsg


def verifySHA512(decryptedWithSHA512, decryptedMsg):
    hash_Func = SHA512.new()
    hash_Func.update(decryptedMsg)
    if hash_Func.hexdigest() == decryptedWithSHA512.hex():
        return True
    else:
        return False


def main():
    BLOCK_SIZE=16
    KEY_SIZE = 32
    message = b'Information security and Programming, Test Message!!! Name : Jeon Sin-Young'

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)

    print("AES key: ", key)
    print("IV: ", iv)

    encryptedWithSHA512 = aesEncryptWithSHA512(message,key,iv)
    print("Encrypted E(H(M)+M): ", encryptedWithSHA512.hex())

    decryptedWithSHA512, decryptedMsg = aesDecryptWithSHA512(encryptedWithSHA512,key,iv)
    print("Decrypted SHA512: ", decryptedWithSHA512.hex())
    print("Decrypted Message: ", decryptedMsg.decode())

    if verifySHA512(decryptedWithSHA512,decryptedMsg):
        print("Integrity OK, Correct Hash!!")
    else:
        print("Incorrect Hash!!")

if __name__ == "__main__":
    main()