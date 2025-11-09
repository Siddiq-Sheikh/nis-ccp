# attack_tools.py
import math
import random
from collections import Counter
from cipher_core import ALPH, ALPH_IDX, IDX_ALPH, clean_text, modinv

# English frequencies for chi-squared
EN_FREQ = {
 'A':8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,'F':2.228,'G':2.015,'H':6.094,
 'I':6.966,'J':0.153,'K':0.772,'L':4.025,'M':2.406,'N':6.749,'O':7.507,'P':1.929,
 'Q':0.095,'R':5.987,'S':6.327,'T':9.056,'U':2.758,'V':0.978,'W':2.360,'X':0.150,
 'Y':1.974,'Z':0.074
}

A_COPRIME = [a for a in range(1,26) if math.gcd(a,26)==1]

def index_of_coincidence(text):
    n = len(text)
    if n <= 1: return 0.0
    freqs = Counter(text)
    return sum(v*(v-1) for v in freqs.values()) / (n*(n-1))

def guess_key_length_ic(ciphertext, max_len=20):
    ct = clean_text(ciphertext)
    best_L=1; best_score=0.0; results=[]
    for L in range(1, max_len+1):
        ics=[]
        for i in range(L):
            sub = ct[i::L]
            ics.append(index_of_coincidence(sub))
        avg_ic = sum(ics)/len(ics)
        results.append((L,avg_ic))
        if avg_ic > best_score:
            best_score=avg_ic; best_L=L
    return best_L, results

def chi_squared_score(text):
    n = len(text)
    if n == 0: return float('inf')
    obs = Counter(text)
    score = 0.0
    for ch in ALPH:
        expected = EN_FREQ[ch] * n / 100.0
        o = obs.get(ch,0)
        score += (o - expected)**2 / (expected + 1e-9)
    return score

# Replace break_combined_frequency with this (demo-identical)
def break_combined_frequency(ciphertext, max_vig_keylen=20):
    """
    Match demo attack_via_ic_and_freq exactly:
    - use guess_key_length_ic to get IC results
    - take top 3 candidate lengths
    - for each L and each a in A_COPRIME, find best s_list per column by chi-sq
    - DO NOT brute-force b; s represents (b + k_i) as in the demo
    """
    ct = clean_text(ciphertext)
    if not ct:
        return "No ciphertext (letters) to attack."

    # get IC-based candidates
    guessed_L, ic_results = guess_key_length_ic(ct, max_len=max_vig_keylen)
    # take top 3 candidate lengths (or fewer if not available)
    sorted_by_ic = sorted(ic_results, key=lambda x: x[1], reverse=True)
    candidate_lengths = [l for l,_ in sorted_by_ic[:3]]

    best_overall = None
    best_score = float('inf')

    for L in candidate_lengths:
        for a in A_COPRIME:
            a_inv = modinv(a, 26)
            total_score = 0.0
            s_list = []
            for j in range(L):
                sub = ct[j::L]
                best_s = None
                best_s_score = float('inf')
                for s in range(26):
                    # decrypt column with candidate (a,s); s == b + k_i (demo semantics)
                    dec = []
                    for ch in sub:
                        y = ALPH_IDX[ch]
                        x = (a_inv * ((y - s) % 26)) % 26
                        dec.append(IDX_ALPH[x])
                    sc = chi_squared_score(''.join(dec))
                    if sc < best_s_score:
                        best_s_score = sc
                        best_s = s
                s_list.append(best_s)
                total_score += best_s_score
            if total_score < best_score:
                best_score = total_score
                best_overall = {'a': a, 'L': L, 's_list': s_list, 'score': total_score}

    if best_overall is None:
        return "Attack failed."

    a_best = best_overall['a']
    L_best = best_overall['L']
    s_best = best_overall['s_list']
    a_inv = modinv(a_best, 26)

    dec = []
    for i, ch in enumerate(ct):
        y = ALPH_IDX[ch]
        s = s_best[i % L_best]
        x = (a_inv * ((y - s) % 26)) % 26
        dec.append(IDX_ALPH[x])
    plain_guess = ''.join(dec)

    return (f"Guessed a={a_best}, L={L_best}\n"
            f"Recovered plaintext (first 300 chars):\n{plain_guess[:300]}")

# Replace known_plaintext_attack with this (demo-identical)
def known_plaintext_attack(known_fragment, ciphertext, vkey_length):
    """
    Known-plaintext attack where offset is unknown.
    Matches demo logic: try all offsets and all a in A_COPRIME.
    Does NOT try b explicitly; computes s_i = (y - a*x) % 26 and stores
    into s_list at (offset + i) % vkey_length.
    Returns a human-readable result (first candidate).
    """
    pt = clean_text(known_fragment)
    ct = clean_text(ciphertext)
    m = len(pt)
    if m == 0 or len(ct) < m:
        return "Known fragment empty or longer than ciphertext."

    candidates = []

    for offset in range(len(ct) - m + 1):
        window = ct[offset: offset + m]
        for a in A_COPRIME:
            s_candidate = [None] * vkey_length
            consistent = True
            for i in range(m):
                x = ALPH_IDX[pt[i]]
                y = ALPH_IDX[window[i]]
                s_i = (y - (a * x)) % 26
                pos = (offset + i) % vkey_length
                if s_candidate[pos] is None:
                    s_candidate[pos] = s_i
                elif s_candidate[pos] != s_i:
                    consistent = False
                    break
            if consistent:
                candidates.append({'offset': offset, 'a': a, 's_list': s_candidate})

    if not candidates:
        return "No candidates found."

    # choose first candidate (same as demo); you can later rank if desired
    cand = candidates[0]
    a_k = cand['a']
    s_list_k = cand['s_list']
    offset_k = cand['offset']
    a_inv = modinv(a_k, 26)

    dec = []
    for i, ch in enumerate(ct):
        s = s_list_k[i % vkey_length]
        s_val = 0 if s is None else s   # demo used 0 fallback for unknown slots
        y = ALPH_IDX[ch]
        x = (a_inv * ((y - s_val) % 26)) % 26
        dec.append(IDX_ALPH[x])

    plain_guess = ''.join(dec)
    return (f"Recovered a={a_k}, guessed offset={offset_k}\n"
            f"Partial decryption (first 300 chars):\n{plain_guess[:300]}")
