# gui_app.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cipher_core import combined_encrypt, combined_decrypt, clean_text, ALPH, modinv
import attack_tools
import random

SAMPLE = ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG MANY TIMES AS IT RUNS ACROSS THE FIELD "
"AND THROUGH THE HEDGEROW THE FARMER WATCHES FROM HIS GATE AND SHAKES HIS HEAD AT THE PLAYFUL "
"SCENE THE CHILDREN CLAP AND LAUGH WHILE BIRDS CALL FROM THE TREES THE SKY IS CLEAR AND THE "
"AIR SMELLS OF CUT GRASS AND WARM EARTH")

class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Combined Cipher Tool — Vigenere + Affine (Demo-alike)")
        self.geometry("1050x760")
        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # --- Tab 1: Encrypt / Decrypt ---
        tab1 = ttk.Frame(nb)
        nb.add(tab1, text="Encrypt / Decrypt")

        top = ttk.Frame(tab1, padding=6)
        top.pack(fill=tk.BOTH, expand=True)

        ttk.Label(top, text="Plaintext / Ciphertext:").pack(anchor=tk.W)
        self.input_text = tk.Text(top, height=12, wrap=tk.WORD)
        self.input_text.pack(fill=tk.X)

        
         # Label to show character count
        self.char_count_var = tk.StringVar(value="Chars (no spaces): 0")
        ttk.Label(top, textvariable=self.char_count_var).pack(anchor=tk.W, pady=(2,0))

        # Bind the input text to update char count
        self.input_text.bind("<KeyRelease>", self.update_char_count)

        key_row = ttk.Frame(top)
        key_row.pack(fill=tk.X, pady=(6,0))
        ttk.Label(key_row, text="Vigenere key (min 1 char):").pack(side=tk.LEFT)
        self.vkey_var = tk.StringVar(value="XALRQAHNTNWP")
        ttk.Entry(key_row, textvariable=self.vkey_var, width=36).pack(side=tk.LEFT, padx=6)

        ttk.Label(key_row, text="Affine a:").pack(side=tk.LEFT, padx=(10,0))
        self.a_var = tk.StringVar(value="5")
        ttk.Entry(key_row, textvariable=self.a_var, width=4).pack(side=tk.LEFT, padx=4)

        ttk.Label(key_row, text="Affine b:").pack(side=tk.LEFT, padx=(6,0))
        self.b_var = tk.StringVar(value="8")
        ttk.Entry(key_row, textvariable=self.b_var, width=4).pack(side=tk.LEFT, padx=4)

        self.keep_nonletters = tk.BooleanVar(value=False)
        ttk.Checkbutton(key_row, text="Keep non-letters", variable=self.keep_nonletters).pack(side=tk.LEFT, padx=8)

        btn_row = ttk.Frame(top)
        btn_row.pack(fill=tk.X, pady=8)
        ttk.Button(btn_row, text="Encrypt →", command=self.on_encrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Decrypt ←", command=self.on_decrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Load file...", command=self.on_load).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Save result...", command=self.on_save).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Clear", command=self.on_clear).pack(side=tk.RIGHT)

        ttk.Label(top, text="Result:").pack(anchor=tk.W)
        self.result_text = tk.Text(top, height=12, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # --- Tab 2: Attack / Demo ---
        tab2 = ttk.Frame(nb)
        nb.add(tab2, text="Attack / Demo")

        atk_frame = ttk.Frame(tab2, padding=6)
        atk_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(atk_frame, text="Ciphertext for analysis (paste here):").pack(anchor=tk.W)
        self.atk_cipher_text = tk.Text(atk_frame, height=7, wrap=tk.WORD)
        self.atk_cipher_text.pack(fill=tk.X)

        atk_opts = ttk.Frame(atk_frame)
        atk_opts.pack(fill=tk.X, pady=6)
        ttk.Button(atk_opts, text="Break by Frequency (demo method)", command=self.run_break_combined).pack(side=tk.LEFT, padx=6)
        ttk.Button(atk_opts, text="Run Demo (random keys)", command=self.run_demo).pack(side=tk.LEFT, padx=6)

        # Known plaintext inputs
        kp_frame = ttk.Frame(atk_frame)
        kp_frame.pack(fill=tk.X, pady=(8,0))
        ttk.Label(kp_frame, text="Known plaintext fragment (optional):").pack(anchor=tk.W)
        self.known_plain_entry = ttk.Entry(kp_frame, width=60)
        self.known_plain_entry.pack(anchor=tk.W, pady=(2,0))

        ttk.Button(kp_frame, text="Known-Plaintext Attack (demo method)", command=self.run_known_plain).pack(anchor=tk.W, pady=6)

        ttk.Label(atk_frame, text="Attack Output:").pack(anchor=tk.W, pady=(8,0))
        self.atk_output = tk.Text(atk_frame, height=14, wrap=tk.WORD)
        self.atk_output.pack(fill=tk.BOTH, expand=True)


    def update_char_count(self, event=None):
        text = self.input_text.get("1.0", tk.END)
        count = len([c for c in text if not c.isspace()])  # Exclude all whitespace
        self.char_count_var.set(f"Chars (no spaces): {count}")

    # ---- Tab 1 handlers ----
    def validate_vkey(self, key):
        if len(key) < 1:
            messagebox.showerror("Key Error", "Vigenere key must be at least 1 character long.")
            return False
        # ensure uppercase A-Z
        if any(ch not in ALPH for ch in key.upper()):
            messagebox.showerror("Key Error", "Vigenere key must contain only letters A-Z.")
            return False
        return True

    def validate_affine(self, a_str, b_str):
        try:
            a = int(a_str); b = int(b_str)
        except:
            messagebox.showerror("Affine error", "Affine a and b must be integers.")
            return None
        if math.gcd(a,26) != 1:
            messagebox.showerror("Affine error", f"Affine a={a} is not coprime with 26.")
            return None
        return a, b

    def on_encrypt(self):
        text = self.input_text.get(1.0, tk.END).rstrip('\n')
        vkey = self.vkey_var.get().upper()
        if not self.validate_vkey(vkey): return
        try:
            a = int(self.a_var.get()); b = int(self.b_var.get())
        except:
            messagebox.showerror("Input error", "Affine a and b must be integers.")
            return
        if math.gcd(a,26) != 1:
            messagebox.showerror("Affine error", f"Affine a={a} is not coprime with 26.")
            return
        try:
            res = combined_encrypt(text, a, b, vkey, keep_nonletters=self.keep_nonletters.get())
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, res)

    def on_decrypt(self):
        text = self.input_text.get(1.0, tk.END).rstrip('\n')
        vkey = self.vkey_var.get().upper()
        if not self.validate_vkey(vkey): return
        try:
            a = int(self.a_var.get()); b = int(self.b_var.get())
        except:
            messagebox.showerror("Input error", "Affine a and b must be integers.")
            return
        if math.gcd(a,26) != 1:
            messagebox.showerror("Affine error", f"Affine a={a} is not coprime with 26.")
            return
        try:
            res = combined_decrypt(text, a, b, vkey, keep_nonletters=self.keep_nonletters.get())
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, res)

    def on_load(self):
        path = filedialog.askopenfilename(title="Open text file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path: return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Open file error", str(e))
            return
        self.input_text.delete(1.0, tk.END)
        self.input_text.insert(tk.END, data)

    def on_save(self):
        path = filedialog.asksaveasfilename(title="Save result", defaultextension='*.txt', filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path: return
        try:
            data = self.result_text.get(1.0, tk.END)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def on_clear(self):
        self.input_text.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)

    # ---- Tab 2 handlers ----
    def run_break_combined(self):
        cipher = self.atk_cipher_text.get(1.0, tk.END).strip()
        if not cipher:
            messagebox.showinfo("Input required", "Please paste ciphertext into the field above.")
            return
        self.atk_output.delete(1.0, tk.END)
        self.atk_output.insert(tk.END, "Running break-by-frequency (this may take a few seconds)...\n")
        self.update_idletasks()
        res = attack_tools.break_combined_frequency(cipher, max_vig_keylen=12)
        self.atk_output.insert(tk.END, res)

    def run_known_plain(self):
        cipher_raw = self.atk_cipher_text.get(1.0, tk.END).strip()
        known_raw = self.known_plain_entry.get().strip()
        if not cipher_raw or not known_raw:
            messagebox.showinfo("Input required", "Provide both ciphertext and known plaintext fragment.")
            return

        # Normalize both exactly as attack expects
        known_clean = clean_text(known_raw)
        ct_letters_only = clean_text(cipher_raw)

        # Basic diagnostics
        self.atk_output.delete(1.0, tk.END)
        self.atk_output.insert(tk.END, f"Known (raw): {known_raw}\nKnown (cleaned): {known_clean}\nCiphertext letters: {len(ct_letters_only)}\n\n")
        if not known_clean:
            self.atk_output.insert(tk.END, "Known fragment contains no letters after cleaning. Aborting.\n")
            return

        # Run improved known-plaintext attack (shows top candidates)
        self.atk_output.insert(tk.END, "Running known-plaintext attack (filling unknown s slots by chi-sq)...\n")
        self.update_idletasks()
        res = attack_tools.known_plaintext_attack(known_clean, cipher_raw, vkey_length=10, top_n=5)
        self.atk_output.insert(tk.END, res)


    def run_demo(self):
        # run the demo logic: random key and random known fragment offset
        self.atk_output.delete(1.0, tk.END)
        text_len = 250; vkey_len = 10; known_len = 30
        plain = clean_text((SAMPLE + " ") * ((text_len // len(SAMPLE)) + 3))[:text_len]
        vkey = ''.join(random.choice(ALPH) for _ in range(vkey_len))
        a = random.choice([x for x in range(1,26) if math.gcd(x,26)==1])
        b = random.randrange(26)
        ct = combined_encrypt(plain, a, b, vkey)
        dec = combined_decrypt(ct, a, b, vkey)
        self.atk_output.insert(tk.END, f"=== Demo parameters ===\nPlaintext len: {len(plain)}\na={a}, b={b}, vkey={vkey}\nDecrypted ok? {dec==plain}\n\n")
        self.atk_output.insert(tk.END, "--- Frequency-based attack (demo method) ---\n")
        res = attack_tools.break_combined_frequency(ct, max_vig_keylen=12)
        self.atk_output.insert(tk.END, res + "\n\n")
        # known-plaintext: pick random offset and try known-plaintext attack
        known_start = random.randint(0, len(plain)-known_len)
        known_fragment = plain[known_start:known_start+known_len]
        self.atk_output.insert(tk.END, f"--- Known-plaintext attack (fragment length {known_len}) ---\nPicked fragment at unknown offset (hidden to attacker)\n")
        res2 = attack_tools.known_plaintext_attack(known_fragment, ct, vkey_length=vkey_len)
        self.atk_output.insert(tk.END, res2 + "\n")

if __name__ == "__main__":
    import math
    app = MainApp()
    app.mainloop()
