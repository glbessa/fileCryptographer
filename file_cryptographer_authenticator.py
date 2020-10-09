import argparse
import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def arguments():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='the file that will be encrypt or decrypt', nargs='+')
    ap.add_argument('-o', '--operation', required=True, help='what I will do for you?', choices=['decrypt', 'encrypt'])
    ap.add_argument('-k', '--key', help='the key that the program will use to encrypt or decrypt the file')
    ap.add_argument('-n', '--nouce', help='I dont know what it is but its IMPORTANT!!! use with the same key you encrypted some data!')
    ap.add_argument('-gk', '--generate-key', help='we generate a key if you want', choices=['true', 'false'])
    ap.add_argument('-ks', '--key-size', choices=['128', '192', '256'], help='the size of the key that you want')
    return vars(ap.parse_args())

def str_2_hex(string_:str):
    return bytes.fromhex(string_)

def hexdigest(hex_:bytes):
    return hex_.hex()

if __name__ == '__main__':
    args = arguments()
    print(args)
    if args['generate_key'] and args['key_size']:   
        key = AESCCM.generate_key(bit_length=int(args['key_size']))
        aesccm = AESCCM(key)
        aad = b'authentic'
        nouce = os.urandom(13)
        for file_ in args['file']:
            ct = None
            with open(file_, 'rb') as data:
                if args['operation'] == 'encrypt':
                    ct = aesccm.encrypt(nouce, data.read(), aad)
            with open(file_, 'wb') as writer:
                writer.write(ct)
        print(hexdigest(key))
        print(hexdigest(nouce))
    else:
        aesccm = AESCCM(str_2_hex(args['key']))
        aad = b'authentic'
        nouce = os.urandom(13)
        for file_ in args['file']:
            ct = None
            with open(file_, 'rb') as data:
                if args['operation'] == 'encrypt':
                    ct = aesccm.encrypt(nouce, data.read(), aad)
                else:
                    nouce = str_2_hex(args['nouce'])
                    ct = aesccm.decrypt(nouce, data.read(), aad)
            with open(file_, 'wb') as writer:
                writer.write(ct)

