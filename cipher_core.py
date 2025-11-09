# cipher_core.py
import string
import math

ALPH = string.ascii_uppercase
ALPH_IDX = {c:i for i,c in enumerate(ALPH)}
IDX_ALPH = {i:c for i,c in enumerate(ALPH)}

def clean_text(s):
    return ''.join([c for c in s.upper() if c in ALPH])

def modinv(a, m=26):
    for x in range(1,m):
        if (a*x) % m == 1:
            return x
    return None

def affine_encrypt_idx(x,a,b):
    return (a*x + b) % 26
def affine_decrypt_idx(y,a,b):
    a_inv = modinv(a,26)
    return (a_inv * (y - b)) % 26

def vigenere_shift_idx(x,k):
    return (x + k) % 26
def vigenere_unshift_idx(y,k):
    return (y - k) % 26

def combined_encrypt(plaintext, a, b, vkey, keep_nonletters=False):
    """
    plaintext: raw text
    a,b: affine keys (integers)
    vkey: Vigenere key string (uppercase A-Z)
    keep_nonletters: if True, non-letters are preserved (indexing includes them)
    """
    if not keep_nonletters:
        pt = clean_text(plaintext)
    else:
        pt = plaintext.upper()

    ct = []
    L = len(vkey)
    for i,ch in enumerate(pt):
        if ch not in ALPH:
            ct.append(ch)
            continue
        x = ALPH_IDX[ch]
        c1 = affine_encrypt_idx(x,a,b)
        k = ALPH_IDX[vkey[i % L]]
        y = vigenere_shift_idx(c1,k)
        ct.append(IDX_ALPH[y])
    return ''.join(ct)

def combined_decrypt(ciphertext, a, b, vkey, keep_nonletters=False):
    if not keep_nonletters:
        ct = clean_text(ciphertext)
    else:
        ct = ciphertext.upper()
    pt = []
    L = len(vkey)
    a_inv = modinv(a,26)
    for i,ch in enumerate(ct):
        if ch not in ALPH:
            pt.append(ch)
            continue
        y = ALPH_IDX[ch]
        k = ALPH_IDX[vkey[i % L]]
        c1 = vigenere_unshift_idx(y,k)
        x = affine_decrypt_idx(c1,a,b)
        pt.append(IDX_ALPH[x])
    return ''.join(pt)
