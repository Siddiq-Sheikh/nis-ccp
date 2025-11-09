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

def known_plaintext_attack(known_fragment, ciphertext, vkey_length, top_n=5):
    """
    Improved known-plaintext attack:
      - attacker does NOT know offset
      - tries all offsets and all a in A_COPRIME
      - fills unknown s slots by per-column chi-sq (same method used in demo)
      - ranks candidates and returns top_n candidates (human-readable)
    Returns a formatted string listing top candidates.
    """
    pt = clean_text(known_fragment)
    ct = clean_text(ciphertext)
    m = len(pt)
    if m == 0 or len(ct) < m:
        return "Known fragment empty or longer than ciphertext."

    prelim_candidates = []

    # 1) collect preliminary candidates (offset + a + partial s_list)
    for offset in range(len(ct) - m + 1):
        window = ct[offset: offset + m]
        for a in A_COPRIME:
            s_partial = [None] * vkey_length
            consistent = True
            for i in range(m):
                x = ALPH_IDX[pt[i]]
                y = ALPH_IDX[window[i]]
                s_i = (y - (a * x)) % 26
                pos = (offset + i) % vkey_length
                if s_partial[pos] is None:
                    s_partial[pos] = s_i
                elif s_partial[pos] != s_i:
                    consistent = False
                    break
            if consistent:
                filled = sum(1 for v in s_partial if v is not None)
                prelim_candidates.append({'offset': offset, 'a': a, 's_partial': s_partial, 'filled': filled})

    if not prelim_candidates:
        return "No candidates found from known fragment."

    scored_candidates = []

    # helper: score text using chi-sq (lower = more English-like)
    def score_plaintext(text):
        return chi_squared_score(text)

    # 2) for each preliminary candidate, fill unknown slots by per-column chi-sq
    for cand in prelim_candidates:
        offset = cand['offset']; a = cand['a']
        s_list = list(cand['s_partial'])  # copy
        a_inv = modinv(a, 26)

        # fill each None position using chi-sq on that column
        for pos in range(vkey_length):
            if s_list[pos] is not None:
                continue
            # build column ciphertext for this key position: take ct[pos::vkey_length]
            column = ct[pos::vkey_length]
            best_s = None
            best_sc = float('inf')
            # try all s values 0..25
            for s_try in range(26):
                dec_col = []
                for ch in column:
                    y = ALPH_IDX[ch]
                    x = (a_inv * ((y - s_try) % 26)) % 26
                    dec_col.append(IDX_ALPH[x])
                sc = chi_squared_score(''.join(dec_col))
                if sc < best_sc:
                    best_sc = sc
                    best_s = s_try
            s_list[pos] = best_s

        # now we have a full s_list -> decrypt whole ciphertext
        dec = []
        for i, ch in enumerate(ct):
            y = ALPH_IDX[ch]
            s = s_list[i % vkey_length]
            x = (a_inv * ((y - s) % 26)) % 26
            dec.append(IDX_ALPH[x])
        plain_guess = ''.join(dec)
        total_score = score_plaintext(plain_guess)

        scored_candidates.append({
            'offset': offset,
            'a': a,
            's_list': s_list,
            'filled': cand['filled'],
            'score': total_score,
            'plaintext': plain_guess
        })

    # 3) rank candidates:
    # primary: more originally-filled slots (filled desc),
    # secondary: chi-sq score (asc)
    scored_candidates.sort(key=lambda c: (-c['filled'], c['score']))

    # 4) format top_n results
    out_lines = []
    n = min(top_n, len(scored_candidates))
    out_lines.append(f"Found {len(scored_candidates)} candidates; showing top {n}:\n")
    for i in range(n):
        c = scored_candidates[i]
        out_lines.append(f"Candidate #{i+1}: offset={c['offset']}, a={c['a']}, filled_slots={c['filled']}, chi2_score={c['score']:.1f}")
        out_lines.append(f"s_list: {c['s_list']}")
        out_lines.append(f"Plaintext (first 400 chars):\n{c['plaintext'][:400]}\n")
    return '\n'.join(out_lines)
