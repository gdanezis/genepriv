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

import cffi
from StatKeeper import StatKeeper

_FFI = cffi.FFI()

_FFI.cdef("""


typedef enum {
  /* values as defined in X9.62 (ECDSA) and elsewhere */
  POINT_CONVERSION_COMPRESSED = 2,
  POINT_CONVERSION_UNCOMPRESSED = 4,
  POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef ... BN_CTX;
typedef ... BIGNUM;

EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP* x);
void EC_GROUP_clear_free(EC_GROUP *);

const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);

int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);

int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);


typedef ... EC_KEY;

EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);

int EC_KEY_up_ref(EC_KEY *);

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);

unsigned EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);

/* EC_KEY_generate_key() creates a ec private (public) key */
int EC_KEY_generate_key(EC_KEY *);
/* EC_KEY_check_key() */
int EC_KEY_check_key(const EC_KEY *);


typedef struct { 
  int nid;
  const char *comment;
  } EC_builtin_curve;

/* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number 
 * of all available curves or zero if a error occurred. 
 * In case r ist not zero nitems EC_builtin_curve structures 
 * are filled with the data of the first nitems internal groups */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

typedef unsigned int BN_ULONG;

BIGNUM *BN_new(void);
void  BN_init(BIGNUM *);
void  BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void  BN_swap(BIGNUM *a, BIGNUM *b);
int   BN_set_word(BIGNUM *a, BN_ULONG w);

int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
void  BN_set_negative(BIGNUM *b, int n);
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);


// AES functions

typedef ... AES_KEY;

#define AES_ENCRYPT ...
#define AES_DECRYPT ...

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
  size_t length, const AES_KEY *key,
  unsigned char *ivec, const int enc);

int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, unsigned int inlen);
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, unsigned int inlen);

size_t AES_size();

""")

_C = _FFI.verify("""
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/aes.h>

size_t AES_size(){
  return sizeof(AES_KEY);
}

""", libraries=["crypto"], extra_compile_args=['-Wno-deprecated-declarations'])

if __name__ == "__main__":

  # # NIST/X9.62/SECG curve over a 192 bit prime field
  # curveID = 409

  class crypto_counts:
    def __init__(self, labels, pubkey, curveID = 409):
      global _C
      self._C = _C
      self.num = len(labels)
      self.curveID = curveID
      self.pubkey = pubkey
      self.lab = {}

      # Store the group we work in
      # precompute tables and the generator
      self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
      if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
          _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
      self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

      # This is where we store the ECEG ciphertexts
      self.buf = []

      for label in labels:
        # Make session key
        session = _C.EC_KEY_new_by_curve_name(curveID)
        _C.EC_KEY_set_group(session, self.ecgroup)
        _C.EC_KEY_generate_key(session)

        s_pub = _C.EC_KEY_get0_public_key(session)
        s_priv = _C.EC_KEY_get0_private_key(session)

        alpha = _C.EC_POINT_new(self.ecgroup)
        _C.EC_POINT_copy(alpha, s_pub);

        beta = _C.EC_POINT_new(self.ecgroup)
        _C.EC_POINT_copy(beta, self.pubkey);
        _C.EC_POINT_mul(self.ecgroup, beta, _FFI.NULL, beta, s_priv, _FFI.NULL)

        _C.EC_KEY_free(session)

        # Save the ECEG ciphertext
        c = (alpha, beta)
        self.lab[label] = c
        self.buf += [c]

    def addone(self, label):
      _C = self._C
      (_, beta) = self.lab[label]
      _C.EC_POINT_add(self.ecgroup, beta, beta, self.gen, _FFI.NULL);


    def randomize(self):
      _C = self._C
      for (a,b) in self.buf:
        # Make session key
        session = _C.EC_KEY_new_by_curve_name(self.curveID)
        _C.EC_KEY_set_group(session, self.ecgroup)
        _C.EC_KEY_generate_key(session)

        s_pub = _C.EC_KEY_get0_public_key(session)
        s_priv = _C.EC_KEY_get0_private_key(session)

        alpha = _C.EC_POINT_new(self.ecgroup)
        _C.EC_POINT_copy(alpha, s_pub);

        beta = _C.EC_POINT_new(self.ecgroup)
        _C.EC_POINT_copy(beta, self.pubkey);
        _C.EC_POINT_mul(self.ecgroup, beta, _FFI.NULL, beta, s_priv, _FFI.NULL)

        _C.EC_POINT_add(self.ecgroup, a, a, alpha, _FFI.NULL);
        _C.EC_POINT_add(self.ecgroup, b, b, beta, _FFI.NULL);

        _C.EC_POINT_clear_free(alpha)
        _C.EC_POINT_clear_free(beta)

        _C.EC_KEY_free(session)

    def extract(self):
      buf = self.buf
      self.buf = None
      return buf

    def extract_into(self, data):
      if data is None:
        return self.extract()

      assert len(self.buf) == len(data)

      for ((a,b), (alpha, beta)) in zip(data, self.buf):
        _C.EC_POINT_add(self.ecgroup, a, a, alpha, _FFI.NULL);
        _C.EC_POINT_add(self.ecgroup, b, b, beta, _FFI.NULL);

      return data

    def __del__(self):
      self._C.EC_GROUP_free(self.ecgroup)
      if self.buf is not None:
        for (a,b) in self.buf:
          self._C.EC_POINT_clear_free(a)
          self._C.EC_POINT_clear_free(b)


  class partialDecryptor:
    def __init__(self, curveID = 409):
      global _C
      self._C = _C
      self.curveID = curveID

      # Store the group we work in
      # precompute tables and the generator
      self.ecgroup = _C.EC_GROUP_new_by_curve_name(curveID)
      if not _C.EC_GROUP_have_precompute_mult(self.ecgroup):
          _C.EC_GROUP_precompute_mult(self.ecgroup, _FFI.NULL);
      self.gen = _C.EC_GROUP_get0_generator(self.ecgroup)

      self.key = _C.EC_KEY_new_by_curve_name(self.curveID)
      _C.EC_KEY_set_group(self.key, self.ecgroup)
      _C.EC_KEY_generate_key(self.key)

    def __del__(self):
      _C = self._C
      _C.EC_KEY_free(self.key)
      self._C.EC_GROUP_free(self.ecgroup)

    def combinekey(self, pubkey = None):
      _C = self._C
      s_pub = _C.EC_KEY_get0_public_key(self.key)
        
      if pubkey == None:
        
        pk = _C.EC_POINT_new(self.ecgroup)
        _C.EC_POINT_copy(pk, s_pub)
        return pk

      else:
        _C.EC_POINT_add(self.ecgroup, pubkey, pubkey, s_pub, _FFI.NULL);
        return pubkey
        
    def partialdecrypt(self, buf):
      _C = self._C
      for (a,b) in buf:

        k_priv = _C.EC_KEY_get0_private_key(self.key)
        alpha = _C.EC_POINT_new(self.ecgroup)
        _C.EC_POINT_copy(alpha, a);

        _C.EC_POINT_mul(self.ecgroup, alpha, _FFI.NULL, alpha, k_priv, _FFI.NULL);
        _C.EC_POINT_invert(self.ecgroup, alpha, _FFI.NULL);
        _C.EC_POINT_add(self.ecgroup, b, b, alpha, _FFI.NULL);

        _C.EC_POINT_clear_free(alpha)


    def finaldecrypt(self, buf, table=None):
      _C = self._C
      gamma = _C.EC_POINT_new(self.ecgroup)
      _C.EC_POINT_set_to_infinity(self.ecgroup, gamma)

      point_size = 52 ## Only use the first bytes as ID
      point_oct = _FFI.new("unsigned char[]", point_size)

      lookup = {}
      for i in range(10000):
          xsize = _C.EC_POINT_point2oct(self.ecgroup, gamma,  _C.POINT_CONVERSION_COMPRESSED,
            point_oct, point_size, _FFI.NULL);

          assert 0 < xsize < point_size

          lkey = _FFI.string(point_oct)[:6]
          lookup[lkey] = i

          _C.EC_POINT_add(self.ecgroup, gamma, gamma, self.gen, _FFI.NULL);         

      _C.EC_POINT_clear_free(gamma)

      cleartext = []
      for (_, b) in buf:
          _C.EC_POINT_point2oct(self.ecgroup, b,  _C.POINT_CONVERSION_COMPRESSED,
              point_oct, point_size, _FFI.NULL);

          lkey = _FFI.string(point_oct)[:6]
          if lkey in lookup:
            cleartext += [lookup[lkey]]
          else:
            cleartext += [None]
      
      return cleartext     


  if __name__ == "__main__":
    stats = StatKeeper()

    D = []
    for _ in range(5): #changed from 5 to 10 TKGs.
      with(stats["decrypt_init"]):
        D += [partialDecryptor()]

    pk = None
    for Di in D:
      with(stats["decrypt_combinekey"]):
        pk = Di.combinekey(pk)

    labels = range(100)
    clients = []
    for _ in range(10): #changed from 10 to 1000 clients
      with(stats["client_init"]):
        c = crypto_counts(labels, pk)
        clients += [c]

    items = 1000
    for i in range(items):
      l = len(labels)
      x = clients[i % 10]
      ## Keep the last 10 as zero to test decryption
      with(stats["client_addone"]):
        x.addone(i % (l-10))

    for c in clients:
      with(stats["client_rerandomize"]):
        c.randomize()

    data = None
    for c in clients:
      with(stats["client_aggregate"]):
        data = c.extract_into(data)

    for Di in D:
      with(stats["decrypt_partial"]):
        Di.partialdecrypt(data)

    for (a,b) in data[-10:]:
      assert _C.EC_POINT_is_at_infinity(x.ecgroup, b) == 1

    with(stats["decrypt_final"]):
      res = D[-1].finaldecrypt(data)

      assert sum(res) == items

    stats.print_stats()
    ## TODO:  free the memory of "data"
