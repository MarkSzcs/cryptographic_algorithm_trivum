import sys
import argparse
import binascii
import secrets
from collections import deque #double ended queue
from itertools import repeat

class Trivium:
    def __init__(self, key, iv):

        self.state = None
        self.iv = iv 
        self.key = key 

        init_list = list(map(int, list(self.key)))
        init_list += list(repeat(0, 13))
        init_list += list(map(int, list(self.iv)))
        init_list += list(repeat(0, 4))
        init_list += list(repeat(0, 108))
        init_list += list([1, 1, 1])
        self.state = deque(init_list) #deque : double ended queue

        for i in range(4 * 288):
            self._gen_keystream()

    def keystream_1(self, number):
        keystream = []
        for i in range(number):
            keystream.append(self._gen_keystream())
        return bits_to_hex(keystream)

    def _gen_keystream(self):

        t_1 = self.state[65] ^ self.state[92]
        t_2 = self.state[161] ^ self.state[176]
        t_3 = self.state[242] ^ self.state[287]

        z = t_1 ^ t_2 ^ t_3

        t_1 = t_1 ^ self.state[90] & self.state[91] ^ self.state[170]
        t_2 = t_2 ^ self.state[174] & self.state[175] ^ self.state[263]
        t_3 = t_3 ^ self.state[285] & self.state[286] ^ self.state[68]

        self.state.rotate() #1 positive rotation

        self.state[0] = t_3
        self.state[93] = t_1
        self.state[177] = t_2

        return z

    def encrypt(self, message, keystream):
        keystream = _hex_to_bytes(keystream)
        buffer = bytearray()
        for i in range(len(keystream)):
            buffer.append(message[i] ^ keystream[i] & 0xff)
        return bytes(buffer)

    def decrypt(self, cipher, keystream):
        keystream = _hex_to_bytes(keystream)
        buffer = bytearray()
        for i in range(len(keystream)):
            buffer.append(cipher[i] ^ keystream[i] & 0xff)
        print(type(buffer))
        return bytes(buffer)

_allbytes = dict([("%02X" % i, i) for i in range(256)])

def _hex_to_bytes(s):
    return [_allbytes[s[i:i+2].upper()] for i in range(0, len(s), 2)]

def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s) for i in range(8)]

def get_random_bits(length):
    randbits = secrets.randbits(length)
    randstring = '{0:080b}'.format(randbits)
    return bytearray(map(int ,randstring))

def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])

def get_bytes_from_file(filename):
    return open(filename, "rb").read()

def encrypt(input, outputKeys, outputCipher):
    key = get_random_bits(80)
    iv = get_random_bits(80)
    plain = get_bytes_from_file(input)
    print("Plain: ", plain)
    trivium = Trivium(key, iv)
    keystream = trivium.keystream_1(len(plain) * 8)
    print("IV in hex:  {}".format(bits_to_hex(iv)))
    print("Key in hex: {}".format(bits_to_hex(key)))
    print("Keystream in hex: {}".format(keystream))
    cipher = trivium.encrypt(plain, keystream)
    print("Cipher: {}".format(cipher.hex()))
    print(cipher)
    with open(outputKeys, "wb") as output_keys:
        output_keys.write(key)
        output_keys.write(iv)
    with open(outputCipher, "wb") as output_cipher:
        output_cipher.write(cipher)

def decrypt(inputCiper, inputKeys, output):
    with open(inputCiper, "rb") as input_cipher:
        cipher = bytes(input_cipher.read())
    with open(inputKeys, "rb") as input_keys:
        key = bytearray(input_keys.read(80))
        iv = bytearray(input_keys.read(80))

    print("Cipher in bytes: ", cipher)
    trivium = Trivium(key, iv)

    keystream = trivium.keystream_1(len(cipher) * 8)
    print("IV in hex:  {}".format(bits_to_hex(iv)))
    print("Key in hex: {}".format(bits_to_hex(key)))
    print("Keystream in hex: {}".format(keystream))
    plain = trivium.decrypt(cipher, keystream)
    print("Plain: {}".format(plain))
    if (output):
        with open(output, "wb") as output_file:
            output_file.write(plain)

    
def main():
    parser = argparse.ArgumentParser(description='Decryption or encryption using Trivium stream cipher.')
    parser.add_argument('-m', '--mode', type=str, choices=['e', 'd'], help='Choose mode: e for encryption or d for decryption')
    parser.add_argument('-iK', '--keys', action='store', dest='keys', type=str, help='An 80 bit key and an 80 bit iv')
    parser.add_argument('-iC', '--cipher', action='store', dest='cipher', type=str, help='Trivium encriptted file')
    parser.add_argument('M', help='Ciphertext file or plaintext file')
    parser.add_argument('-oK', action='store', dest='outK', type=str, help='Output key')
    parser.add_argument('-oC', action='store', dest='outC', type=str, help='Output cypher')
    parser.add_argument('-o', action='store', dest='out', type=str, help='Output plain')

    argv = parser.parse_args()
    mode = argv.mode
    if (mode == "e"): 
        input = argv.M
        outputKey = argv.outK
        outputCipher = argv.outC
        encrypt(input, outputKey, outputCipher)
    elif (mode == "d"):
        keys = argv.keys
        output = argv.out
        input = argv.M
        decrypt(input, keys, output)

if __name__ == "__main__":
    main()