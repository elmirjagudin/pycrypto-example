#!/usr/bin/env python
import sys
from os import path
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


KEY_SIZE = 16  # encryption key size, in bytes


def parse_args():
    parser = argparse.ArgumentParser(description="encrypt a file")
    parser.add_argument("-k", "--key-file", default="key_file", help="encryption key file")
    parser.add_argument("src_file", metavar="file", help="source file to encrypt")
    parser.add_argument("dest_file", metavar="encrypted_file", help="write encrypted data to this file")

    return parser.parse_args()


def err_exit(error_message):
    print(error_message)
    sys.exit(1)


def get_key(key_file):
    if path.isfile(key_file):
        # load the key from specified key file
        with open(key_file, "rb") as f:
            return f.read()

    # no key file found, create new key
    return generate_key(key_file)


def check_files(src_file, dest_file):
    # check that source file exists
    if not path.isfile(src_file):
        err_exit(f"{src_file}: no such file")

    if path.isfile(dest_file):
        err_exit(f"{dest_file}: already exists")


def generate_key(key_file):
    # generate a new random encryption key
    # and write it to the specified key file
    key = get_random_bytes(KEY_SIZE)
    with open(key_file, "wb") as f:
        f.write(key)

    print(f"wrote new encryption key to {key_file}")
    return key


def encrypt(key, src_file, dest_file):
    # use 16-byte nonce, as recommended for the EAX mode
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce)

    with open(dest_file, "wb") as dest:
        # write down used nonce
        dest.write(nonce)

        with open(src_file, "rb") as src:
            # encrypt the source data
            plaintext = src.read()
            ciphertext = cipher.encrypt(plaintext)

            # write down encrypted data
            dest.write(ciphertext)

            # write down the MAC/tag
            dest.write(cipher.digest())


def main():
    args = parse_args()
    check_files(args.src_file, args.dest_file)
    key = get_key(args.key_file)
    encrypt(key, args.src_file, args.dest_file)


main()
