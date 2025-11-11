Combined Cipher (Affine + Vigenere) — GUI & Tools

Files:
- main.py               -> Launches the GUI (Encrypt/Decrypt, Attack, Efficiency)
- cipher_core.py        -> Core cipher functions (vigenere, affine, combined)
- attack_tools.py       -> Frequency analysis / known-plaintext and brute-forcing helpers
- efficiency_analysis.py-> Timing and performance test runner
- requirements.txt      -> (no external packages)
- README.txt            -> this file

Setup:
- Requires Python 3.x.
- tkinter is included with most Python installations. On some Linux systems you may need to install package:
  Ubuntu/Debian: sudo apt-get install python3-tk

Run:
1. (Optional) create and activate a virtual environment:
   python -m venv env
   # Windows:
   env\\Scripts\\activate
   # macOS/Linux:
   source env/bin/activate

2. Run the GUI:
   python main.py

Notes:
- Key must be at least 10 characters.
- The combined cipher first applies Vigenere (polyalphabetic) then Affine (monoalphabetic).
- Attack tab includes:
  - Frequency analysis (letter distribution & chi-squared)
  - Known-plaintext attack (attempts to align known segment, brute-force affine parameters, derive key fragment)
  - Break-by-frequency (tries affine parameter space + simple Vigenere chi-sq guesses)
- Efficiency tab runs timing tests for various message sizes and displays summary.

If you want me to:
- Add progress bars for long-breaking attempts,
- Save attack results to a file,
- Support loading/saving ciphertext and logs,
tell me which features and I'll update the code.

