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

## utils.

def str2uchar(s):
    data = _FFI.new("unsigned char[]", len(s))
    char = _FFI.cast("char *", data)
    
    x = _FFI.buffer(char, len(s))
    x[:] = s[:]
    return data

def size2uchar(L):
    data = _FFI.new("unsigned char []", L)
    return data

def toHex(buf, blen):
    return (_FFI.buffer(buf, blen)[:]).encode("hex")

def get_group(curveID = 409):
    # Which group
    ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)

    # Optimize exps
    if not _C.EC_GROUP_have_precompute_mult(ecgroup):
        _C.EC_GROUP_precompute_mult(ecgroup, _FFI.NULL);
    
    # Get generator
    gen = _C.EC_GROUP_get0_generator(ecgroup)
    
    # Get order
    order = _C.BN_new()
    _C.EC_GROUP_get_order(ecgroup, order, _FFI.NULL);

    return ecgroup, gen, order

def assign_number(x):
    v = _C.BN_new()
    if x >= 0:
        _C.BN_set_word(v, x)
    else:
        # OpenSLL -- Cannot deal with direct assignment of negative values?
        _C.BN_set_word(v, -x)
        _C.BN_set_negative(v, 1)
    return v

def table_lookup(elem, table):
    (G, g, q) = get_group()

    for (i, e) in table:
        res = _C.EC_POINT_cmp(G, elem, e, _FFI.NULL)
        if res == 0:
            return i
    return None

def chk(ret):
    if ret == None:
        return
    if ret < 0:
        raise Exception(ret)

## Public key ops

def pk_get_key(Group):
    (G, g, q) = Group

    priv = _C.BN_new()
    _C.BN_rand_range(priv, q)

    pub = _C.EC_POINT_new(G)
    _C.EC_POINT_mul(G, pub, _FFI.NULL, g, priv, _FFI.NULL)

    return pub, priv

def pk_get_table():
    (G, g, q) = get_group()

    ## Generate the decryption table
    seq = []
    for x in range(-1000, 1000):
        y = _C.EC_POINT_new(G)
        v = assign_number(x)
        _C.EC_POINT_mul(G, y, _FFI.NULL, g, v, _FFI.NULL)

        ## TODO: clean-up: v
        seq += [(x, y)]
    return seq

def pk_encrypt(Group, pub, m):
    (G, g, q) = Group

    k = _C.BN_new()
    _C.BN_rand_range(k, q)

    gk = _C.EC_POINT_new(G)
    _C.EC_POINT_mul(G, gk, _FFI.NULL, g, k, _FFI.NULL)

    gkx = _C.EC_POINT_new(G)
    _C.EC_POINT_mul(G, gkx, _FFI.NULL, pub, k, _FFI.NULL)
        
    gm = _C.EC_POINT_new(G)
    _C.EC_POINT_mul(G, gm, _FFI.NULL, g, m, _FFI.NULL)

    gkxm = _C.EC_POINT_new(G)
    _C.EC_POINT_add(G, gkxm, gkx, gm, _FFI.NULL)

    _C.EC_POINT_clear_free(gkx)
    _C.EC_POINT_clear_free(gm)
    _C.BN_clear_free(k)
    return (gk, gkxm)

def pk_accumulate(Group, accA, accB, A, B, k, temp=None):
    (G, g, q) = Group

    if temp == None:
        tempA = _C.EC_POINT_new(G)
        tempB = _C.EC_POINT_new(G)
    else:
        tempA, tempB = temp

    _C.EC_POINT_mul(G, tempA, _FFI.NULL, A, k, _FFI.NULL)
    _C.EC_POINT_mul(G, tempB, _FFI.NULL, B, k, _FFI.NULL)

    _C.EC_POINT_add(G, accA, accA, tempA, _FFI.NULL)
    _C.EC_POINT_add(G, accB, accB, tempB, _FFI.NULL)

    if temp == None:
        _C.EC_POINT_clear_free(tempA)
        _C.EC_POINT_clear_free(tempB)    

    return accA, accB


