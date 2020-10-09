import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def arguments():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='the file that will be encrypt or decrypt', nargs='+')
    ap.add_argument('-o', '--operation', required=True, help='what I will do for you?', choices=['decrypt', 'encrypt'])
    ap.add_argument('-k', '--key', help='the key that the program will use to encrypt or decrypt the file')
    ap.add_argument('-iv', '--initializator-vector', help='the initializator vector of the cipher block')
    ap.add_argument('-ks', '--key-size', default='256', choices=['128', '192', '256'], help='the size of the key that you want')
    return vars(ap.parse_args())

def str_2_hex(string_:str):
    return bytes.fromhex(string_)

def hexdigest(hex_:bytes):
    return hex_.hex()

def data_corrector(data:bytes, block_size:int):
    data = data.decode()
    data += '\x00' * (block_size - (len(data) % block_size))
    return data.encode()

def main(args):
    cipher, key, iv = create_cipher(args['key'], args['initializator_vector'], int(args['key_size']))
    if args['operation'] == 'encrypt':
        for file_ in args['file']:
            encrypt_file(file_, cipher)
    else:
        for file_ in args['file']:
            decrypt_file(file_, cipher)
    print(hexdigest(key))
    print(hexdigest(iv))


def create_cipher(key, iv, key_size=256, mode=modes.CBC):
    if key == None:
        key = os.urandom(int(key_size/8))
    else:
        key = str_2_hex(key)
    if iv != None:
        iv = str_2_hex(iv)
        if len(iv) != 16:
            raise Exception
    else:
        iv = os.urandom(16)
    return Cipher(algorithms.AES(key), mode(iv)), key, iv

def decrypt_file(file_, cipher_):
    data = None
    with open(file_, 'rb') as reader:
        data = reader.read()

    decryptor_ = cipher_.decryptor()
    data = decryptor_.update(data) + decryptor_.finalize()
    with open(file_, 'wb') as writer:
        writer.write(data)

def encrypt_file(file_, cipher_):
    data = None
    with open(file_, 'rb') as reader:
        data = reader.read()

    data = data_corrector(data, 16)
    encryptor_ = cipher_.encryptor()
    data = encryptor_.update(data) + encryptor_.finalize()
    with open(file_, 'wb') as writer:
        writer.write(data)


if __name__ == '__main__':
    args = arguments()
    main(args)
