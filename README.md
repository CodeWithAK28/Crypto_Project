# An Experimental Analysis of Message Tampering and Verification in RSA Digital Signatures Using SHA-256

A Python project that signs messages with RSA-PSS and SHA-256, tampers with them in different ways, and measures whether, and how, the tampering is detected.

---

## 1. Project overview

Once a message is signed and sent, someone could change it on the way. This project tests whether an **RSA digital signature using SHA-256 (RSA-PSS)** detects every kind of change, and measures how much each change alters the message and its SHA-256 hash.

The program plays three roles:

1. **Sender:** the user types a message. It is hashed with SHA-256 and signed with the private key.
2. **Channel (attacker):** the user can send the packet unchanged or tamper with it in one of 8 ways.
3. **Receiver:** the received message is verified with the public key, giving **VALID** or **INVALID**.

An analysis step then names the **category of tampering** and measures the **damage**:

- characters changed in the message (edit distance and %)
- SHA-256 hash bits changed (out of 256)
- signature bits flipped (out of 2048)

Every test is saved as a row in `demo_results.csv`.

> **Note:** a digital signature only says *valid* or *invalid*. The tampering category and damage are worked out by the test program, which compares the original and received message. The signature detects tampering; it does not diagnose it.

---

## 2. Project structure

```
Crypto_Project/
├── rsa_keygeneration.py   # Step 1: generates the 2048-bit RSA key pair (e = 65537)
├── sign_verify.py         # Step 2: signs a user-typed message and verifies it
├── tamper_demo.py         # Step 3: interactive tampering demo with category + damage analysis
├── public_key.pem         # Public key (shared, used to verify)
├── demo_results.csv       # Results of tampering tests (one row per test)
├── requirements.txt       # Python dependencies
├── .gitignore             # Keeps private_key.pem and .venv out of Git
└── README.md
```

Files created when you run the code:

| File | Created by | Purpose |
|---|---|---|
| `private_key.pem` | `rsa_keygeneration.py` | Private key, used to sign. **Not uploaded to GitHub** (listed in `.gitignore`). |
| `public_key.pem` | `rsa_keygeneration.py` | Public key, used to verify |
| `message.txt` | `sign_verify.py` | The signed message ("sent" to the receiver) |
| `signature.bin` | `sign_verify.py` | The 256-byte signature |
| `demo_results.csv` | `tamper_demo.py` | Results table; new rows are added on every test |

---

## 3. Requirements

- Python 3.9 or newer (tested with Python 3.13 and 3.14)
- [`cryptography`](https://pypi.org/project/cryptography/) library
- `hashlib`, `csv`, `random`, `string`, `os`, `datetime` (built into Python, no install needed)

---

## 4. Steps to run the code

### Step 1: Get the code

```bash
git clone https://github.com/CodeWithAK28/Crypto_Project.git
cd Crypto_Project
```

(Or unzip the submitted folder and open a terminal inside it.)

### Step 2: Create a virtual environment and install the library

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (Command Prompt)**

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Your prompt should now start with `(.venv)`.

### Step 3: Generate the RSA key pair

```bash
python rsa_keygeneration.py
```

This creates `private_key.pem` and `public_key.pem` in the project folder and prints the key size (2048 bits), the public exponent (65537) and the public key.

> **Run this first.** The private key is not in the repository for security reasons, so the other two programs need this step before they work. Running it again creates a **new** key pair and overwrites both files.

### Step 4: Sign and verify a message

```bash
python sign_verify.py
```

1. Type any message and press Enter.
2. The program signs it with the private key (RSA-PSS + SHA-256), saves `message.txt` and `signature.bin`, then verifies them with the public key.

Expected output:

```
Enter the message to sign: Transfer 500 rupees to Alice

Message signed successfully
Signature length: 256 bytes
Signature (hex): 9f887dfe...
Saved message.txt and signature.bin

Verification: VALID - the message is authentic and unchanged
```

### Step 5: Run the tampering demo

```bash
python tamper_demo.py
```

1. **Sender:** type the message to send. It is hashed and signed.
2. **Channel:** choose how the attacker changes the packet:

   | Option | Tampering |
   |---|---|
   | 1 | Send it unchanged |
   | 2 | Type your own changed message |
   | 3 | Change one random character |
   | 4 | Replace a word |
   | 5 | Add text at the end |
   | 6 | Cut text from the end |
   | 7 | Damage the signature (flip bits) |
   | 8 | Receiver uses a wrong public key |

3. **Receiver:** the program verifies the packet and shows VALID or INVALID.
4. **Analysis:** the program shows the tampering category and the damage, and saves the result to `demo_results.csv`.
5. Press **Enter** to tamper the same message again, **n** for a new message, or **q** to quit.

Example (option 2, "500" changed to "900"):

```
========== RECEIVER ==========
Received message  : Transfer 900 rupees to Alice
Verification      : INVALID -> tampering detected, message rejected

========== ANALYSIS (our lab report) ==========
Tampering category: Single character substitution
Message damage    : 1 of 28 characters changed (3.6%)
SHA-256 damage    : 129 of 256 hash bits changed (50.4%)
Signature damage  : 0 of 2048 signature bits flipped (0.00%)
Detected by signature: Yes (rejected)
```

---

## 5. Results file (`demo_results.csv`)

| Column | Meaning |
|---|---|
| `time` | When the test was run |
| `original_message` / `received_message` | Message before and after the channel |
| `category` | Type of tampering identified by the analysis step |
| `verification` | `VALID` or `INVALID` from the signature check |
| `chars_changed`, `message_damage_pct` | Edit distance between the messages, and as a % of the message length |
| `hash_bits_changed`, `hash_damage_pct` | SHA-256 bits that differ (out of 256), and as a % |
| `signature_bits_flipped` | Signature bits flipped (option 7 only, out of 2048) |

The file can be opened in Excel or loaded with pandas for tables and graphs.

### Sample results

Message: "Transfer 500 rupees to Alice" (28 characters)

| Tampering | Result | Message changed | SHA-256 bits changed |
|---|---|---|---|
| No change | VALID | 0% | 0 / 256 |
| 1 character changed | INVALID | 3.6% | 129 / 256 |
| Word replaced | INVALID | 17.9% | 123 / 256 |
| Text appended | INVALID | 22.2% | 131 / 256 |
| Text truncated | INVALID | 21.4% | 140 / 256 |
| Completely different message | INVALID | 85.7% | 119 / 256 |
| 1 signature bit flipped | INVALID | 0% | 0 / 256 |
| Wrong public key | INVALID | 0% | 0 / 256 |

**Key findings**

- The unchanged message was accepted; every tampered packet was rejected.
- Changing just 1 character (3.6% of the message) changed about half of the SHA-256 bits. This is SHA-256's **avalanche effect**.
- Flipping a single bit of the 2048-bit signature, or using the wrong public key, also failed, even with the message untouched.
- Signatures are all-or-nothing: they detect every change, but cannot say what changed.

Exact numbers vary slightly between runs, because of the random PSS salt and random tampering choices.

---

## 6. Algorithms and parameters

| Item | Value |
|---|---|
| Signature scheme | RSA-PSS (RSASSA-PSS) |
| Hash function | SHA-256 (also used inside MGF1) |
| Key size | 2048 bits |
| Public exponent | e = 65537 |
| PSS salt length | Maximum allowed (`padding.PSS.MAX_LENGTH`) |
| Key format | PEM: PKCS8 (private), SubjectPublicKeyInfo (public) |

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'cryptography'` | Activate the virtual environment, then `pip install -r requirements.txt` |
| `zsh: command not found: pip` (macOS) | Use `pip3`, or activate `.venv` first |
| `externally-managed-environment` error | Use a virtual environment (Step 2) instead of installing globally |
| `FileNotFoundError: private_key.pem` | Run `python rsa_keygeneration.py` first (Step 3) |

---

## 8. References and online sources

1. cryptography.io: RSA (key generation, PSS signing and verification): https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
2. cryptography.io: Key serialization (PEM, PKCS8, SubjectPublicKeyInfo): https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
3. Python documentation: `hashlib` (SHA-256): https://docs.python.org/3/library/hashlib.html
