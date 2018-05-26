import hashlib
import binascii
from os import urandom
from enum import Enum
import bitstring


class WinternizAlgorithm(Enum):
    WOTS_SHA256_N32_W1 = object()
    WOTS_SHA256_N32_W2 = object()
    WOTS_SHA256_N32_W4 = object()
    WOTS_SHA256_N32_W8 = object()

    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.name)


class Winterniz:

    BITS_PER_BYTE = 256

    def __init__(self, alg_type=WinternizAlgorithm.WOTS_SHA256_N32_W8):

        # n the number of bytes of the output of the hash function
        # w the width (in bits) of the Winternitz coefficients [ 1, 2, 4, or 8 ]
        # p the number of n-byte string elements that make up the keys and signature (p=256/w)

        if alg_type is WinternizAlgorithm.WOTS_SHA256_N32_W1:
            self._hash_alg = 'sha256'
            self._wtos_n = 32
            self._wtos_w = 1
            self._wtos_p = 256
        elif alg_type is WinternizAlgorithm.WOTS_SHA256_N32_W2:
            self._hash_alg = 'sha256'
            self._wtos_n = 32
            self._wtos_w = 2
            self._wtos_p = 128
        elif alg_type is WinternizAlgorithm.WOTS_SHA256_N32_W4:
            self._hash_alg = 'sha256'
            self._wtos_n = 32
            self._wtos_w = 4
            self._wtos_p = 64
        elif alg_type is WinternizAlgorithm.WOTS_SHA256_N32_W8:
            self._hash_alg = 'sha256'
            self._wtos_n = 32
            self._wtos_w = 8
            self._wtos_p = 32
        else:
            raise ValueError("unknown Winternitz alg_type")

    def hash(self, data):
        h = hashlib.new(self._hash_alg)
        h.update(data)
        hash_value = h.digest()
        return hash_value

    def generate_key_pair(self):

        # 1. Generate an array which is an array of size wtos_p with each item in the array
        #    containing wtos_n bytes of random data.
        pvt_key = []
        for _ in range(self._wtos_p):
            pvt_key.append(urandom(self._wtos_n))

        # 2. Hash each private key item 2^wtos_w times using the hash function to produce the
        #    wtos_p array sized public key.  Each array item contains wtos_n of data since the output
        #    of hash function is defined as being wtos_n bytes.
        pub_key = []
        for i in range(self._wtos_p):
            pub_item = self.hash(pvt_key[i])
            for _ in range(2**self._wtos_w-1):
                pub_item = self.hash(pub_item)
            pub_key.append(pub_item)

        # return the public and private WTOS keys
        return pub_key, pvt_key

    def sign(self, pvt_key, data):
        # hash the data to sign
        data_hash = self.hash(data)
        # break the hash value into a bit stream so we can read w bits at a time into a uint value
        bit_string = bitstring.ConstBitStream(data_hash)
        data_unit = "uint:{}".format(self._wtos_w)
        # produce the signature
        sig = []
        for i in range(self._wtos_p):
            sig_item = pvt_key[i]
            # read w bits of the hash into a uint
            uint_val = bit_string.read(data_unit)
            # calculate the number of hash iterations by taking the w - uint_val
            hash_iters = 2**self._wtos_w - uint_val
            # do the hash operations: note that if hash_iters == 0 then sig_item becomes that element of the pvt key
            for _ in range(hash_iters):
                sig_item = self.hash(sig_item)
            sig.append(sig_item)
        return sig

    def verify(self, signature, data, pub_key):
        # hash the data
        data_hash = self.hash(data)
        # break the hash value into a bit stream so we can read w bits at a time into a uint value
        bit_string = bitstring.ConstBitStream(data_hash)
        data_unit = "uint:{}".format(self._wtos_w)
        verify = []
        # now we complete the hash operations so that in the end we end up with the same public key expected
        for i in range(self._wtos_p):
            verify_item = signature[i]
            hash_iters = bit_string.read(data_unit)
            for _ in range(hash_iters):
                verify_item = self.hash(verify_item)
            verify.append(verify_item)
        # return the result of the comparison of the verify list with the comparison public key
        return pub_key == verify




def hex_encode(data):
    return binascii.hexlify(data)


if __name__ == "__main__":


    message = b"Hello"

    w = Winterniz(alg_type=WinternizAlgorithm.WOTS_SHA256_N32_W8)

    pub, priv = w.generate_key_pair()

    print("==== Private key =====")
    for j in range(len(priv)):
        print("Priv[{}]: {}".format(j, hex_encode(priv[j])))

    print("\r\n==== Public key =====")
    for j in range(len(pub)):
        print("Pub[{}]: {}".format(j, hex_encode(pub[j])))

    print("\r\n==== Message to sign ===============")
    print("m:\t\t{}".format(message))
    print("H(m)=\t{}".format(hex_encode(w.hash(message))))

    print("\r\n==== Signature =====================")
    sign = w.sign(priv, message)
    for j in range(len(pub)):
        print("Sig[{}]: {}".format(j, hex_encode(sign[j])))

    print("\r\nSIGNATURE_VALID: ", w.verify(sign, message, pub))