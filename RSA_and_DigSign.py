from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#오픈형태 인크립트 프로토콜

def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)
    priKey = privateKey.exportKey('PEM')
    print("%s private key: %s" % (userName, priKey))
    pubKey = privateKey.publickey()
    print("%s public key: %s" % (userName, pubKey.exportKey('PEM')))
    return priKey, pubKey


def rsaEncrypt(message, pubKey):
    rsa_Cipher = PKCS1_OAEP.new(pubKey)
    ciphertext = rsa_Cipher.encrypt(message)
    return ciphertext


def rsaDecrypt(encrypted, priKey):
    privateKey = RSA.importKey(priKey)
    rsaCipher = PKCS1_OAEP.new(privateKey)
    plaintext = rsaCipher.decrypt(encrypted)
    return plaintext

def main():
    message = b'Information security and Programming, Test Message!!! jeonsinyoung'
    print("Message: ", message.decode())

    # alice & bob RSA key pairs Generation
    alice_priKey, alice_pubKey = gen_RSA_Key('alice')
    bob_priKey, bob_pubKey = gen_RSA_Key('bob')

    #alice --> bob : message encrypt ---> Sending...
    # alice : using 'bob' publickey message encrypt

    encrypted = rsaEncrypt(message, bob_pubKey)
    print("RSA_Encrypt(message, bob_pubKey)", encrypted.hex())

    # Network : from alice (e)ncrypted --> sending ) to bob
    #bob : decrypt ... using bob's privateKey...
    decrypted = rsaDecrypt(encrypted,bob_priKey)
    print("RSA_Decrypt(ciphertext, bob_pubKey)", decrypted.decode())

if __name__ == "__main__":
    main()


