import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def arguments():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True, help='the file that will be encrypt or decrypt', nargs='+')
    ap.add_argument('-o', '--operation', required=True, help='what I will do for you?', choices=['decrypt', 'encrypt'])
    ap.add_argument('-k', '--key', help='the key that the program will use to encrypt or decrypt the file')
    ap.add_argument('-ks', '--key-size', choices=['128', '192', '256'], help='the size of the key that you want')
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
    cipher, key = create_cipher(args['key'], args['key_size'])
    if args['operation'] == 'encrypt':
        map(encrypt_file, (args['file'], cipher))
    else:
        map(decrypt_file, (args['file'], cipher))
    print(hexdigest(key))


def create_cipher(key, key_size=256, mode=modes.CBC, iv=os.urandom(16)):
    if key == False:
        key = os.urandom((key_size/8))
    else:
        key = str_2_hex(key)
    return Cipher(algorithms.AES(key), mode(iv)), key

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

    encryptor_ = cipher_.encrypter()
    data = encryptor_.update(data) + encryptor_.finalize()
    with open(file_, 'wb') as writer:
        writer.write(data)


if __name__ == '__main__':
    args = arguments()
    main(args)
