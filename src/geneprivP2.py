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

# ---------------------------
# Protocol 2 (Secret sharing)

## User:
#  - Generate PK
#  - Generate public decryption table

def user_get_key():
    Group = get_group()

    keys =  pk_get_key(Group)
    table = pk_get_table()

    return keys, table


## Certiied sequencer:
#  - Ecnrypt SNP values using the PK

def sequencer_encrypt(snps, pub):
    group = get_group()
    (G, g, q) = group

    cipher = []
    for snpi, snpv in snps:
        m = assign_number(snpv)
        A,B = pk_encrypt(group, pub, m)
        _C.BN_clear_free(m)
        ## TODO: clean-up: m, gm, gkx, gk, k
        cipher += [(snpi, A, B)]

    return cipher

## Pharma:
#  - Split the wi into 2 shares
#  - Distriute to authorities

def pharma_split_weights(weights):
    group = get_group()
    (G, g, q) = group

    L1, L2 = [], []
    for snpi, wi in weights:
        v = assign_number(wi)
        
        s1 = _C.BN_new()
        _C.BN_rand_range(s1, q)
        s2 = _C.BN_new()
        _C.BN_mod_sub_quick(s2, v, s1 ,q)

        L1 += [(snpi, s1)]
        L2 += [(snpi, s2)]

        _C.BN_clear_free(v)

    return L1, L2

## Authorities:
#  - Multiply shares with encrypted SNPs

def authority_aggregate(pub, eweights, esnips):
    group = get_group()
    (G, g, q) = group

    # Initialize

    A_acc = _C.EC_POINT_new(G)
    _C.EC_POINT_set_to_infinity(G, A_acc)

    B_acc = _C.EC_POINT_new(G)
    _C.EC_POINT_set_to_infinity(G, B_acc)

    temp = (_C.EC_POINT_new(G), _C.EC_POINT_new(G))

    for (snpi, Ai, Bi), (snpj, si) in zip(esnips, eweights):
        assert snpi == snpj

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

## Smart Card:
#  - Add result
#  - Decrypt results

def user_combine_decrypt(A1, B1, A2, B2, pk, table):
    group = get_group()
    (G, g, q) = group

    A_acc = _C.EC_POINT_new(G)
    _C.EC_POINT_set_to_infinity(G, A_acc)

    B_acc = _C.EC_POINT_new(G)
    _C.EC_POINT_set_to_infinity(G, B_acc)

    ## Add the ciphertexts -> Add plaintexts

    _C.EC_POINT_add(G, A_acc, A1, A2, _FFI.NULL)
    _C.EC_POINT_add(G, B_acc, B1, B2, _FFI.NULL)

    ## Decrypt

    (pub, priv) = pk

    D = _C.EC_POINT_new(G)
    _C.EC_POINT_mul(G, D, _FFI.NULL, A_acc, priv, _FFI.NULL)
    _C.EC_POINT_invert(G, D, _FFI.NULL);

    _C.EC_POINT_add(G, D, B_acc, D, _FFI.NULL)

    result = table_lookup(D, table)

    return result


## ---------------------
## Unit tests live here

import unittest

class TestProtocol1(unittest.TestCase):
    def test_group(self):
        (G, g, q) = get_group()

    def test_user_key(self):
        user_get_key()

    def test_split(self):
        wi = [(snpi, 2) for snpi in range(4)]
        pharma_split_weights(wi)

    def test_all(self):
        # Example weights / snips
        wi = [(snpi, 2) for snpi in range(4)]        

        # User generates key
        pk, table = user_get_key()
        (pub, priv) = pk

        # Sequencer encodes snps
        esnips = sequencer_encrypt(wi, pub)

        # Split the weights
        L1, L2 = pharma_split_weights(wi)

        # Authroties aggregate
        (A1, B1) = authority_aggregate(pub, L1, esnips)
        (A2, B2) = authority_aggregate(pub, L2, esnips)

        # User combines and decrypts
        x = user_combine_decrypt(A1, B1, A2, B2, pk, table)
        assert x == 16

if __name__ == '__main__':
    from StatKeeper import StatKeeper
    import random
    
    ## Speed tests
    stats = StatKeeper()

    SIZE = 10000
    snp_name = range(SIZE)
    snp_vals = [0,1] * (SIZE / 2)
    snps = zip(snp_name, snp_vals)

    wi_vals = ([1] * 200) + [0] * (SIZE - 200)
    random.shuffle(wi_vals)
    wi = zip(snp_name, wi_vals)

    with(stats["user_key"]):
        pk, table = user_get_key()
        (pub, priv) = pk

    # Sequencer encodes snps
    with(stats["sequencer_encrypt"]):
        esnips = sequencer_encrypt(snps, pub)

    # Split the weights
    with(stats["pharma_split"]):
        L1, L2 = pharma_split_weights(wi)

    # Authroties aggregate
    with(stats["authority_aggregate"]):
        (A1, B1) = authority_aggregate(pub, L1, esnips)
    with(stats["authority_aggregate"]):
        (A2, B2) = authority_aggregate(pub, L2, esnips)

    # User combines and decrypts
    with(stats["combine_decrypt"]):
        x = user_combine_decrypt(A1, B1, A2, B2, pk, table)

    print x
    stats.print_stats()

    unittest.main()
