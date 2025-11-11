# attack_tools.py
import math
import random
from collections import Counter
from cipher_core import ALPH, ALPH_IDX, IDX_ALPH, clean_text, modinv
import time
from collections import Counter

# Global counters for performance tracking
class AttackStats:
    def __init__(self):
        self.trials = 0
        self.start_time = 0
        self.characters_processed = 0
        
    def reset(self):
        self.trials = 0
        self.start_time = time.time()
        self.characters_processed = 0

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

# def break_combined_frequency(ciphertext, max_vig_keylen=20):
#     """ Match demo attack_via_ic_and_freq exactly: 
#     - use guess_key_length_ic to get IC results
#     - take top 3 candidate lengths
#     - for each L and each a in A_COPRIME, find best s_list per column by chi-sq
#     - DO NOT brute-force b; s represents (b + k_i) as in the demo
#     """
#     ct = clean_text(ciphertext)
#     if not ct:
#         return "No ciphertext (letters) to attack."

#     # get IC-based candidates
#     guessed_L, ic_results = guess_key_length_ic(ct, max_len=max_vig_keylen)

#     # take top 3 candidate lengths (or fewer if not available)
#     sorted_by_ic = sorted(ic_results, key=lambda x: x[1], reverse=True)
#     candidate_lengths = [l for l,_ in sorted_by_ic[:3]]

#     best_overall = None
#     best_score = float('inf')

#     for L in candidate_lengths:
#         for a in A_COPRIME:
#             a_inv = modinv(a, 26)
#             total_score = 0.0
#             s_list = []
#             for j in range(L):
#                 sub = ct[j::L]
#                 best_s = None
#                 best_s_score = float('inf')
#                 for s in range(26):
#                     # decrypt column with candidate (a,s); s == b + k_i (demo semantics)
#                     dec = []
#                     for ch in sub:
#                         y = ALPH_IDX[ch]
#                         x = (a_inv * ((y - s) % 26)) % 26
#                         dec.append(IDX_ALPH[x])
#                     sc = chi_squared_score(''.join(dec))
#                     if sc < best_s_score:
#                         best_s_score = sc
#                         best_s = s
#                 s_list.append(best_s)
#                 total_score += best_s_score

#             if total_score < best_score:
#                 best_score = total_score
#                 best_overall = {'a': a, 'L': L, 's_list': s_list, 'score': total_score}

#     if best_overall is None:
#         return "Attack failed."

#     a_best = best_overall['a']
#     L_best = best_overall['L']
#     s_best = best_overall['s_list']
#     a_inv = modinv(a_best, 26)

#     dec = []
#     for i, ch in enumerate(ct):
#         y = ALPH_IDX[ch]
#         s = s_best[i % L_best]
#         x = (a_inv * ((y - s) % 26)) % 26
#         dec.append(IDX_ALPH[x])

#     plain_guess = ''.join(dec)

#     return (f"Guessed a={a_best}, L={L_best}\n"
#             f"Recovered plaintext (first 300 chars):\n{plain_guess[:300]}")


# def known_plaintext_attack(known_fragment, ciphertext, vkey_length=None,
#                           max_vkey_len=20, top_n=5,
#                           max_conflicts_per_slot=2, min_support_ratio=0.5):
#     """
#     Improved known-plaintext attack that auto-detects key length (if vkey_length is None)
#     and ranks candidates so those whose plaintext contains the known fragment come first.
#     """
#     pt = clean_text(known_fragment)
#     ct = clean_text(ciphertext)
#     m = len(pt)
#     if m == 0:
#         return "Known fragment empty after cleaning (no letters)."
#     if len(ct) < m:
#         return f"Ciphertext too short: letters={len(ct)} < known fragment letters={m}."

#     # 1) determine lengths to try
#     lengths = []
#     if vkey_length is not None:
#         lengths = [vkey_length]
#     else:
#         try:
#             _, ic_results = guess_key_length_ic(ct, max_len=max_vkey_len)
#             sorted_by_ic = sorted(ic_results, key=lambda x: x[1], reverse=True)
#             lengths = [l for l,_ in sorted_by_ic[:3]]
#         except Exception:
#             lengths = []
#         if 1 not in lengths:
#             lengths.append(1)
#         # append a few small lengths for safety
#         for L in range(2, min(max_vkey_len, 12) + 1):
#             if L not in lengths:
#                 lengths.append(L)

#     prelim_candidates = []
#     # 2) collect candidates (mode per slot, tolerant)
#     for L in lengths:
#         for offset in range(len(ct) - m + 1):
#             window = ct[offset: offset + m]
#             for a in A_COPRIME:
#                 obs_per_slot = [[] for _ in range(L)]
#                 for i in range(m):
#                     x = ALPH_IDX[pt[i]]
#                     y = ALPH_IDX[window[i]]
#                     s_i = (y - (a * x)) % 26
#                     pos = (offset + i) % L
#                     obs_per_slot[pos].append(s_i)

#                 s_partial = [None] * L
#                 filled = 0
#                 consistent = True
#                 for pos, obs in enumerate(obs_per_slot):
#                     if not obs:
#                         continue
#                     counts = {}
#                     for v in obs:
#                         counts[v] = counts.get(v, 0) + 1
#                     mode_val, mode_count = max(counts.items(), key=lambda kv: kv[1])
#                     conflicts = len(obs) - mode_count
#                     if conflicts > max_conflicts_per_slot or (mode_count / len(obs)) < min_support_ratio:
#                         consistent = False
#                         break
#                     s_partial[pos] = mode_val
#                     filled += 1
#                 if consistent:
#                     prelim_candidates.append({'L': L, 'offset': offset, 'a': a, 's_partial': s_partial, 'filled': filled})

#     if not prelim_candidates:
#         return ("No consistent candidates found under current tolerances. "
#                 "Try a longer known fragment or relax max_conflicts_per_slot/min_support_ratio.")

#     # 3) Fill unknown slots by chi-sq (demo method), decrypt, score, and check containment
#     scored = []
#     def score_plaintext(text): return chi_squared_score(text)

#     for cand in prelim_candidates:
#         L = cand['L']; a = cand['a']; offset = cand['offset']
#         s_list = list(cand['s_partial'])
#         a_inv = modinv(a, 26)

#         # fill missing slots
#         for pos in range(L):
#             if s_list[pos] is not None: continue
#             column = ct[pos::L]
#             best_s = None; best_sc = float('inf')
#             for s_try in range(26):
#                 dec_col = []
#                 for ch in column:
#                     y = ALPH_IDX[ch]
#                     x = (a_inv * ((y - s_try) % 26)) % 26
#                     dec_col.append(IDX_ALPH[x])
#                 sc = chi_squared_score(''.join(dec_col))
#                 if sc < best_sc:
#                     best_sc = sc; best_s = s_try
#             s_list[pos] = best_s

#         # decrypt full ciphertext
#         dec_chars = []
#         for i, ch in enumerate(ct):
#             y = ALPH_IDX[ch]
#             s = s_list[i % L]
#             x = (a_inv * ((y - s) % 26)) % 26
#             dec_chars.append(IDX_ALPH[x])
#         plain_guess = ''.join(dec_chars)
#         total_score = score_plaintext(plain_guess)
#         contains_known = (pt in plain_guess)

#         scored.append({'L': L, 'offset': offset, 'a': a, 's_list': s_list,
#                        'filled': cand['filled'], 'score': total_score,
#                        'plaintext': plain_guess, 'contains_known': contains_known})

#         # fast accept: fully-filled and contains known fragment
#         if contains_known and cand['filled'] == L:
#             return (f"Recovered (fast accept): L={L}, offset={offset}, a={a}, filled_slots={cand['filled']}\n"
#                     f"s_list: {s_list}\nPlaintext (first 400 chars):\n{plain_guess[:400]}")

#     # 4) rank: contains_known first, then filled desc, then chi2 asc
#     scored.sort(key=lambda c: (not c['contains_known'], -c['filled'], c['score']))

#     # format top_n
#     n = min(top_n, len(scored))
#     out = []
#     out.append(f"Known fragment (cleaned): {pt}\nCiphertext letters: {len(ct)}\nTried lengths: {sorted(set([c['L'] for c in scored]))[:10]}\n")
#     out.append(f"Found {len(scored)} candidates; showing top {n}:\n")
#     for i in range(n):
#         c = scored[i]
#         out.append(f"Candidate #{i+1}: L={c['L']}, offset={c['offset']}, a={c['a']}, filled_slots={c['filled']}, chi2={c['score']:.1f}, contains_known={c['contains_known']}")
#         out.append(f"s_list: {c['s_list']}")
#         out.append(f"Plaintext (first 400 chars):\n{c['plaintext'][:400]}\n")
#     return '\n'.join(out)



# # cipher = ("TVKISMWVOKHLKPTGOULIEJIGWUKGSIXPQMNEXEXIPAVPIJRBRZTNLCEZEVQJLWGOQOBJEYAFT"
# #           "VTQMVTHKPHYZUFQYSNPQESBOOHQHICFPPRONIGVKSWJYMQAZIKISPUNXITYXLP")

# # # call with defaults (auto-refine b for short texts)
# # # res = break_combined_frequency(cipher,debug=True)
# # # print(res)

# # # or force refinement and tweak params:
# # res2 = break_combined_frequency(cipher)
# # print(res2)

# Modify break_combined_frequency function
def break_combined_frequency(ciphertext, max_vig_keylen=10):
    """Match demo attack_via_ic_and_freq exactly with performance tracking"""
    stats = AttackStats()
    stats.reset()
    ct = clean_text(ciphertext)
    stats.characters_processed = len(ct)
    
    if not ct:
        return "No ciphertext (letters) to attack."

    # get IC-based candidates
    guessed_L, ic_results = guess_key_length_ic(ct, max_len=max_vig_keylen)
    sorted_by_ic = sorted(ic_results, key=lambda x: x[1], reverse=True)
    candidate_lengths = [l for l,_ in sorted_by_ic[:3]]

    best_overall = None
    best_score = float('inf')

    for L in candidate_lengths:
        for a in A_COPRIME:
            stats.trials += 1
            a_inv = modinv(a, 26)
            total_score = 0.0
            s_list = []
            for j in range(L):
                sub = ct[j::L]
                best_s = None
                best_s_score = float('inf')
                for s in range(26):
                    stats.trials += 1
                    # decrypt column with candidate (a,s)
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

    elapsed_time = time.time() - stats.start_time
    
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
    
    # Calculate success estimate based on chi-squared score
    success_estimate = max(0, min(100, (100 - best_score/10)))
    
    # Performance matrix
    performance_matrix = (
        f"=== PERFORMANCE MATRIX ===\n"
        f"Characters processed: {stats.characters_processed}\n"
        f"Time taken: {elapsed_time:.2f} seconds\n"
        f"Trials conducted: {stats.trials}\n"
        f"Success estimate: {success_estimate:.1f}%\n"
        f"Key length tested: {L_best}\n"
        f"Affine keys tested: {len(A_COPRIME)}\n"
        f"==========================\n\n"
    )

    return (performance_matrix +
            f"Guessed a={a_best}, L={L_best}\n"
            f"Recovered plaintext (first 500 chars):\n{plain_guess[:500]}")

# Modify known_plaintext_attack function
def known_plaintext_attack(known_fragment, ciphertext, vkey_length=None,
                          max_vkey_len=10, top_n=5,
                          max_conflicts_per_slot=2, min_support_ratio=0.5):
    """Improved known-plaintext attack with performance tracking"""
    stats = AttackStats()
    stats.reset()
    
    pt = clean_text(known_fragment)
    ct = clean_text(ciphertext)
    stats.characters_processed = len(ct)
    
    m = len(pt)
    if m == 0:
        return "Known fragment empty after cleaning (no letters)."
    if len(ct) < m:
        return f"Ciphertext too short: letters={len(ct)} < known fragment letters={m}."

    # 1) determine lengths to try
    lengths = []
    if vkey_length is not None:
        lengths = [vkey_length]
    else:
        try:
            _, ic_results = guess_key_length_ic(ct, max_len=max_vkey_len)
            sorted_by_ic = sorted(ic_results, key=lambda x: x[1], reverse=True)
            lengths = [l for l,_ in sorted_by_ic[:3]]
        except Exception:
            lengths = []
        if 1 not in lengths:
            lengths.append(1)

    prelim_candidates = []
    
    # 2) collect candidates (mode per slot, tolerant)
    for L in lengths:
        for offset in range(len(ct) - m + 1):
            stats.trials += 1
            window = ct[offset: offset + m]
            for a in A_COPRIME:
                stats.trials += 1
                obs_per_slot = [[] for _ in range(L)]
                for i in range(m):
                    x = ALPH_IDX[pt[i]]
                    y = ALPH_IDX[window[i]]
                    s_i = (y - (a * x)) % 26
                    pos = (offset + i) % L
                    obs_per_slot[pos].append(s_i)

                s_partial = [None] * L
                filled = 0
                consistent = True
                for pos, obs in enumerate(obs_per_slot):
                    if not obs:
                        continue
                    counts = {}
                    for v in obs:
                        counts[v] = counts.get(v, 0) + 1
                    mode_val, mode_count = max(counts.items(), key=lambda kv: kv[1])
                    conflicts = len(obs) - mode_count
                    if conflicts > max_conflicts_per_slot or (mode_count / len(obs)) < min_support_ratio:
                        consistent = False
                        break
                    s_partial[pos] = mode_val
                    filled += 1
                if consistent:
                    prelim_candidates.append({'L': L, 'offset': offset, 'a': a, 's_partial': s_partial, 'filled': filled})

    elapsed_time = time.time() - stats.start_time

    if not prelim_candidates:
        return ("No consistent candidates found under current tolerances. "
                "Try a longer known fragment or relax max_conflicts_per_slot/min_support_ratio.")

    # 3) Fill unknown slots by chi-sq, decrypt, score, and check containment
    scored = []
    def score_plaintext(text): return chi_squared_score(text)

    for cand in prelim_candidates:
        L = cand['L']; a = cand['a']; offset = cand['offset']
        s_list = list(cand['s_partial'])
        a_inv = modinv(a, 26)

        # fill missing slots
        for pos in range(L):
            if s_list[pos] is not None: continue
            column = ct[pos::L]
            best_s = None; best_sc = float('inf')
            for s_try in range(26):
                stats.trials += 1
                dec_col = []
                for ch in column:
                    y = ALPH_IDX[ch]
                    x = (a_inv * ((y - s_try) % 26)) % 26
                    dec_col.append(IDX_ALPH[x])
                sc = chi_squared_score(''.join(dec_col))
                if sc < best_sc:
                    best_sc = sc; best_s = s_try
            s_list[pos] = best_s

        # decrypt full ciphertext
        dec_chars = []
        for i, ch in enumerate(ct):
            y = ALPH_IDX[ch]
            s = s_list[i % L]
            x = (a_inv * ((y - s) % 26)) % 26
            dec_chars.append(IDX_ALPH[x])
        plain_guess = ''.join(dec_chars)
        total_score = score_plaintext(plain_guess)
        contains_known = (pt in plain_guess)

        scored.append({'L': L, 'offset': offset, 'a': a, 's_list': s_list,
                       'filled': cand['filled'], 'score': total_score,
                       'plaintext': plain_guess, 'contains_known': contains_known})

        # fast accept: fully-filled and contains known fragment
        if contains_known and cand['filled'] == L:
            success_rate = 95.0  # Known-plaintext with good fragment has high success
            performance_matrix = (
                f"=== PERFORMANCE MATRIX ===\n"
                f"Characters processed: {stats.characters_processed}\n"
                f"Time taken: {elapsed_time:.2f} seconds\n"
                f"Trials conducted: {stats.trials}\n"
                f"Success estimate: {success_rate:.1f}%\n"
                f"Known fragment length: {len(pt)}\n"
                f"Candidates tested: {len(prelim_candidates)}\n"
                f"==========================\n\n"
            )
            return (performance_matrix +
                    f"Recovered (fast accept): L={L}, offset={offset}, a={a}, filled_slots={cand['filled']}\n"
                    f"s_list: {s_list}\nPlaintext (first 400 chars):\n{plain_guess[:400]}")

    # 4) rank: contains_known first, then filled desc, then chi2 asc
    scored.sort(key=lambda c: (not c['contains_known'], -c['filled'], c['score']))

    # Calculate success rate based on best candidate
    best_candidate = scored[0] if scored else None
    if best_candidate:
        success_rate = 80.0 if best_candidate['contains_known'] else 40.0
    else:
        success_rate = 0.0

    # Performance matrix
    performance_matrix = (
        f"=== PERFORMANCE MATRIX ===\n"
        f"Characters processed: {stats.characters_processed}\n"
        f"Time taken: {elapsed_time:.2f} seconds\n"
        f"Trials conducted: {stats.trials}\n"
        f"Success estimate: {success_rate:.1f}%\n"
        f"Known fragment length: {len(pt)}\n"
        f"Total candidates found: {len(scored)}\n"
        f"==========================\n\n"
    )

    # format top_n
    n = min(top_n, len(scored))
    out = []
    out.append(performance_matrix)
    out.append(f"Known fragment (cleaned): {pt}\nCiphertext letters: {len(ct)}\nTried lengths: {sorted(set([c['L'] for c in scored]))[:10]}\n")
    out.append(f"Found {len(scored)} candidates; showing top {n}:\n")
    for i in range(n):
        c = scored[i]
        out.append(f"Candidate #{i+1}: L={c['L']}, offset={c['offset']}, a={c['a']}, filled_slots={c['filled']}, chi2={c['score']:.1f}, contains_known={c['contains_known']}")
        out.append(f"s_list: {c['s_list']}")
        out.append(f"Plaintext (first 500 chars):\n{c['plaintext'][:500]}\n")
    return '\n'.join(out)