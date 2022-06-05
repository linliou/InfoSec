from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)
    priKey = privateKey.exportKey('PEM')
    print("%s private key: %s" % (userName, priKey))
    pubKey = privateKey.publickey()
    print("%s public key: %s" % (userName, pubKey.exportKey('PEM')))
    return priKey, pubKey


def aesEncrypt(message, key, iv):
    cipher_Encrypt = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher_Encrypt.encrypt(message)
    return ciphertext


def aesDecrypt(encrypted, key, iv):
    cipher_Decrypted = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher_Decrypted.decrypt(encrypted)
    return plaintext


def rsaDigSignGen(message, priKey):
    hashMsgObj = SHA512.new(message)
    privateKey = RSA.importKey(priKey)
    signGenFuncObj = PKCS1_v1_5.new(privateKey)
    signMsg = signGenFuncObj.sign(hashMsgObj)
    return signMsg


def rsaDigSignVerify(signMsg, message, pubKey):
    hashMsgObj = SHA512.new(message)  # pubKey 는 임포트 안해도 됨
    signVerifyObj = PKCS1_v1_5.new(pubKey)
    if signVerifyObj.verify(hashMsgObj, signMsg):
        return True
    else:
        return False


def main():
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    message = b'Information security and Programming, Test Message!!!Jeon Sin-Young'

    key = Random.new().read(KEY_SIZE)
    iv = Random.new().read(BLOCK_SIZE)
    print("AES key: ", key)
    print("IV: ", iv)

    # alice & bob RSA key pairs Generation
    alice_priKey, alice_pubKey = gen_RSA_Key('alice')

    ####
    #### Alice : Digital Signature Generation & AES Encryption
    signature = rsaDigSignGen(message, alice_priKey)
    print("Length of Signature: ", len(signature))
    encrypted = aesEncrypt(signature + message, key, iv)
    print("AES Encrypted E(Sign(H(M))+M): ", encrypted.hex())
    print("Length of Encrypted E(Sign(H(M))+M): ", len(encrypted))
    print("Sending: ", encrypted.hex())
    print("**** Alice : Sending Encrypted Message...\n\n")

    ####
    #### bob : AES Decryption & Digital Signature verification
    print("**** Bob : Receiving Encrypted Message...")
    print("Received: ", encrypted.hex())
    decryptedTemp = aesDecrypt(encrypted, key, iv)
    print("AES Decryption E(E(Sign(H(M))+M)): ", decryptedTemp.hex())

    decryptedSign = decryptedTemp[:256]
    print("Decrypted Sign: ", decryptedSign.hex())
    decryptedMsg = decryptedTemp[256:]
    print("Decrypted Message: ", decryptedMsg.decode())

    if rsaDigSignVerify(decryptedSign, decryptedMsg, alice_pubKey):
        print("Digital Signature Verification OK!!! ")
    else:
        print("Digital Signature Verification FAIL!!! ")


if __name__ == "__main__":
    main()
