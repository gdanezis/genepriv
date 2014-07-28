# Copyright (c) 2014, George Danezis (University College London) All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from crypto import _C, _FFI
from os import urandom
import math
from utils import *

# --------------------------
# Protocol 1 (Smartcard)

## User:

def user_get_key():
    #  - Generate AES Key
    fresh_random = urandom(128 / 8)
    return fresh_random

## Certified sequencer:
#  - Get AES key, bulk encrypt all SNP information
#  - Given encrypted data to all

def sequencer_encrypt(snps, key):
    enc_key = _FFI.new("unsigned char []", int(_C.AES_size()))
    AES_KEY = _FFI.cast("AES_KEY *", enc_key)

    assert len(key) == 16
    bytes = str2uchar(key)
    chk(_C.AES_set_encrypt_key(bytes, 128, AES_KEY))

    L = len(snps)
    IVr = urandom(128 / 8)
    IV = str2uchar(IVr)
    data = size2uchar( L )
    
    sdata = _FFI.cast("signed char *", data)
    names = []
    for i in range(L):
        name, value = snps[i]
        names += [name]
        sdata[i] = value
    
    blocks = int(math.ceil(float(L) / 16))
    cipher = size2uchar( (blocks * 16)  )

    assert blocks * 16 >= L
    _C.AES_cbc_encrypt(data, cipher, len(snps), AES_KEY, IV, _C.AES_ENCRYPT)

    return L, names, IVr, cipher

def sequencer_decrypt(ciphertext, key):
    (L, names, IVr, cipher) = ciphertext

    enc_key = _FFI.new("unsigned char []", int(_C.AES_size()))
    AES_KEY = _FFI.cast("AES_KEY *", enc_key)

    assert len(key) == 16
    bytes = str2uchar(key)
    
    _C.AES_set_decrypt_key(bytes, 128, AES_KEY)

    blocks = int(math.ceil(float(L) / 16))
    data = size2uchar( (blocks * 16)  )

    IV = str2uchar(IVr)
    
    _C.AES_cbc_encrypt(cipher, data, (blocks * 16) , AES_KEY, IV, _C.AES_DECRYPT)
    
    array = _FFI.cast("signed char *", data)
    out = []
    for i in range(L):
        out += [(names[i], array[i])]

    return out

## Pharma:
#  - Generate a PK key pair
#  - Make decryption table
#  - Encrypt all SNP weights under 

def pharma_get_key():
    Group = get_group()
    return pk_get_key(Group)

def pharma_get_weights(weights, pk):
    group = get_group()
    (G, g, q) = group

    pub, priv = pk
    Ewi = []
    for snpi, wi in weights:
        m = assign_number(wi)
        A,B = pk_encrypt(group, pub, m)
        _C.BN_clear_free(m)
        ## TODO: clean-up: m, gm, gkx, gk, k
        Ewi += [(snpi, A, B)]

    return Ewi

# Smartcard:
# - Select SNP to encrypt
# - Mult-ad on secret data
# - Return the total

def user_get_result(esnips, aes_key, eweights, pub):
    group = get_group()
    (G, g, q) = group

    # Initialize

    A_acc = _C.EC_POINT_new(G)
    _C.EC_POINT_set_to_infinity(G, A_acc)

    B_acc = _C.EC_POINT_new(G)
    _C.EC_POINT_set_to_infinity(G, B_acc)

    temp = (_C.EC_POINT_new(G), _C.EC_POINT_new(G))

    for (snpi, snp), (snpj, Ai, Bi) in zip(esnips, eweights):
        assert snpi == snpj

        si = assign_number(snp)
        A_acc, B_acc = pk_accumulate(group, A_acc, B_acc, Ai, Bi, si, temp)
        _C.BN_clear_free(si)

    # Rerandomize
    m = assign_number(0)
    A,B = pk_encrypt(group, pub, m)
    _C.BN_clear_free(m)

    _C.EC_POINT_add(G, A_acc, A_acc, A, _FFI.NULL)
    _C.EC_POINT_add(G, B_acc, B_acc, B, _FFI.NULL)

    ## clear memory
    map(_C.EC_POINT_clear_free, temp)

    return (A_acc, B_acc)

# Pharma:
# - Decrypt 

def pharma_decrypt_result(eresult, pk):
    (G, g, q) = get_group()
    (pub, priv) = pk
    (A, B) = eresult

    D = _C.EC_POINT_new(G)
    _C.EC_POINT_mul(G, D, _FFI.NULL, A, priv, _FFI.NULL)
    _C.EC_POINT_invert(G, D, _FFI.NULL);

    _C.EC_POINT_add(G, D, B, D, _FFI.NULL)

    return D

# ---------------------------
import random
import unittest

class TestProtocol1(unittest.TestCase):

    def test_group(self):
        (G, g, q) = get_group()

    def test_get_key(self):
        (pub, priv) = pharma_get_key()

    def test_table(self):
        T1 = pk_get_table()

        for v, e in T1[:100]:
            assert table_lookup(e, T1) == v

    def test_weights(self):
        key_pair = pharma_get_key()

        wi = [(snpi, 1) for snpi in range(100)]
        pharma_get_weights(wi, key_pair)

    def test_encode_decode(self): 
        ## Generate the keys for all
        key_pair = pharma_get_key()
        (pub, priv) = key_pair

        ## Encode the weights on the pharma side
        wi = [(snpi, 2) for snpi in range(4)]
        Ewi = pharma_get_weights(wi, key_pair)

        # Perform the operation on the smartcard
        res = user_get_result(wi, None, Ewi, pub)

        # Decode the element at the pharma
        elem = pharma_decrypt_result(res, key_pair)

        T1 = pk_get_table()
        
        result = table_lookup(elem, T1)
        print result
        assert result == (4*4)

    def test_AES(self):
        secret = user_get_key()

        wi = [(snpi, 2) for snpi in range(4)]
        C = sequencer_encrypt(wi, secret)
        P = sequencer_decrypt(C, secret)

        assert wi == P

if __name__ == '__main__':
    from StatKeeper import StatKeeper

    ## Speed tests
    stats = StatKeeper()

    ## Generate the keys for all
    with(stats["pharma_key"]):
        key_pair = pharma_get_key()
        (pub, priv) = key_pair

    ## Encode the weights on the pharma side
    SIZE = 10000
    snp_name = range(SIZE)
    snp_vals = [0,1] * (SIZE / 2)
    snps = zip(snp_name, snp_vals)

    wi_vals = ([1] * 200) + [0] * (SIZE - 200)
    random.shuffle(wi_vals)
    wi = zip(snp_name, wi_vals)
    
    with(stats["pharma_weights"]):
        Ewi = pharma_get_weights(wi, key_pair)

    # Perform the operation on the smartcard
    with(stats["user_results"]):
        res = user_get_result(snps, None, Ewi, pub)

    # Decode the element at the pharma
    with(stats["pharma_decrypt"]):
        elem = pharma_decrypt_result(res, key_pair)

    T1 = pk_get_table()
    
    result = table_lookup(elem, T1)
    print result

    stats.print_stats()


    unittest.main()
