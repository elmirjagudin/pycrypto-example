#!/usr/bin/env python
import sys
from os import path
import argparse
from Cryptodome.Cipher import AES


KEY_SIZE = 16  # encryption key size, in bytes


def err_exit(error_message):
    print(error_message)
    sys.exit(1)


def get_key(key_file):
    with open(key_file, "rb") as f:
        return f.read()


def check_files(key_file, src_file, dest_file):
    for file in [key_file, src_file]:
        if not path.isfile(file):
            err_exit(f"{file}: no such file")

    if path.isfile(dest_file):
        err_exit(f"{dest_file}: already exists")


def parse_args():
    parser = argparse.ArgumentParser(description="decrypt a file")
    parser.add_argument("-k", "--key-file", default="key_file", help="encryption key file")
    parser.add_argument("src_file", metavar="file", help="encrypted file")
    parser.add_argument("dest_file", metavar="encrypted_file", help="write decrypted data to this file")

    args = parser.parse_args()
    check_files(args.key_file, args.src_file, args.dest_file)

    return args


def decrypt(key, src_file, dest_file):
    src_size = path.getsize(src_file)

    with open(src_file, "rb") as src:
        nonce = src.read(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        ciphertext = src.read(src_size - 32)

        # decrypt
        plaintext = cipher.decrypt(ciphertext)

        # load MAC tag and verify integrity of the file
        mac_tag = src.read()
        try:
            cipher.verify(mac_tag)
        except ValueError as e:
            # MAC check failed, source file corrupted
            err_exit(e.args[0])

        with open(dest_file, "wb") as dest:
            dest.write(plaintext)


def main():
    args = parse_args()
    key = get_key(args.key_file)
    decrypt(key, args.src_file, args.dest_file)


main()
