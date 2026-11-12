import csv
import hashlib
import os
import random
import string
from datetime import datetime
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
RESULTS_FILE = "demo_results.csv"
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)
def load_keys():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key
def sign(private_key, message):
    return private_key.sign(message.encode("utf-8"), PSS, hashes.SHA256())
def verify(public_key, message, signature):
    try:
        public_key.verify(signature, message.encode("utf-8"), PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
def sha256_hex(message):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()
def bits_different(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
def hash_bits_changed(original, received):
    h1 = hashlib.sha256(original.encode("utf-8")).digest()
    h2 = hashlib.sha256(received.encode("utf-8")).digest()
    return bits_different(h1, h2)
def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
def detect_category(original, received):
    if received == original:
        return "No change"
    if received.startswith(original):
        return "Text appended at the end"
    if original.startswith(received):
        return "Text truncated from the end"
    distance = edit_distance(original, received)
    if distance == 1:
        if len(received) == len(original):
            return "Single character substitution"
        if len(received) > len(original):
            return "Single character insertion"
        return "Single character deletion"
    old_words, new_words = original.split(), received.split()
    if len(old_words) == len(new_words):
        changed = sum(1 for a, b in zip(old_words, new_words) if a != b)
        if changed == 1:
            return "Word replacement"
        if changed < len(old_words):
            return f"Multiple word replacement ({changed} words)"
    if distance >= 0.7 * max(len(original), len(received)):
        return "Completely different message"
    return "Multiple edits (mixed)"
def change_one_character(message):
    i = random.randrange(len(message))
    choices = [c for c in string.ascii_letters + string.digits if c != message[i]]
    return message[:i] + random.choice(choices) + message[i + 1:]
def replace_word(message):
    words = message.split()
    print("Words in the message:", words)
    old = input("Which word do you want to replace? ").strip()
    if old not in words:
        print("That word is not in the message, so the message is unchanged.")
        return message
    new = input("Replace it with: ").strip()
    i = words.index(old)
    words[i] = new
    return " ".join(words)
def flip_signature_bits(signature, count):
    data = bytearray(signature)
    positions = random.sample(range(len(data) * 8), count)
    for p in positions:
        data[p // 8] ^= 1 << (p % 8)
    return bytes(data)
def save_result(row):
    new_file = not os.path.exists(RESULTS_FILE)
    with open(RESULTS_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if new_file:
            writer.writeheader()
        writer.writerow(row)
def attacker_menu():
    print("\n========== CHANNEL (attacker) ==========")
    print("How should the packet be changed on the way?")
    print(" 1. Send it unchanged")
    print(" 2. Type your own changed message")
    print(" 3. Change one random character")
    print(" 4. Replace a word")
    print(" 5. Add text at the end")
    print(" 6. Cut text from the end")
    print(" 7. Damage the signature (flip bits)")
    print(" 8. Receiver uses a wrong public key")
    return input("Choose 1-8: ").strip()
def run_once(private_key, public_key, message, signature):
    received_message = message
    received_signature = signature
    receiver_key = public_key
    category = None
    sig_bits = 0
    choice = attacker_menu()
    if choice == "2":
        received_message = input("Type the changed message: ")
    elif choice == "3":
        received_message = change_one_character(message)
    elif choice == "4":
        received_message = replace_word(message)
    elif choice == "5":
        received_message = message + input("Text to add at the end: ")
    elif choice == "6":
        n = input(f"How many characters to cut (1-{len(message) - 1})? ").strip()
        n = int(n) if n.isdigit() and 0 < int(n) < len(message) else 1
        received_message = message[:-n]
    elif choice == "7":
        n = input("How many bits of the signature to flip (1-2048)? ").strip()
        sig_bits = int(n) if n.isdigit() and 0 < int(n) <= 2048 else 1
        received_signature = flip_signature_bits(signature, sig_bits)
        category = "Signature tampering"
    elif choice == "8":
        print("Generating a different 2048-bit key pair for the receiver...")
        receiver_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        category = "Wrong public key"
    elif choice != "1":
        print("Invalid choice, sending the packet unchanged.")
    print("\n========== RECEIVER ==========")
    print("Received message  :", received_message)
    print("Received signature:", received_signature.hex()[:32], "...")
    print("Receiver computes SHA-256 of the received message:")
    print("  ", sha256_hex(received_message))
    print("Receiver checks the signature with the public key...")
    valid = verify(receiver_key, received_message, received_signature)
    if valid:
        print("Verification      : VALID   -> message is authentic and unchanged")
    else:
        print("Verification      : INVALID -> tampering detected, message rejected")
    if category is None:
        category = detect_category(message, received_message)
    chars = edit_distance(message, received_message)
    length = max(len(message), len(received_message))
    char_pct = 100 * chars / length
    hash_bits = hash_bits_changed(message, received_message)
    hash_pct = 100 * hash_bits / 256
    sig_pct = 100 * sig_bits / 2048
    print("\n========== ANALYSIS (our lab report) ==========")
    print("Original message  :", message)
    print("Received message  :", received_message)
    print("Tampering category:", category)
    print(f"Message damage    : {chars} of {length} characters changed ({char_pct:.1f}%)")
    print(f"SHA-256 damage    : {hash_bits} of 256 hash bits changed ({hash_pct:.1f}%)")
    print(f"Signature damage  : {sig_bits} of 2048 signature bits flipped ({sig_pct:.2f}%)")
    if category == "Wrong public key":
        print("Note              : message and signature are untouched, but the key does not match")
    print("Detected by signature:", "No (accepted)" if valid else "Yes (rejected)")
    save_result({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original_message": message,
        "received_message": received_message,
        "category": category,
        "verification": "VALID" if valid else "INVALID",
        "chars_changed": chars,
        "message_damage_pct": round(char_pct, 2),
        "hash_bits_changed": hash_bits,
        "hash_damage_pct": round(hash_pct, 2),
        "signature_bits_flipped": sig_bits,
    })
    print(f"(Result saved to {RESULTS_FILE})")
def main():
    private_key, public_key = load_keys()
    print("RSA-PSS + SHA-256 Tampering Demo (2048-bit key)")
    while True:
        print("\n========== SENDER ==========")
        message = input("Enter the message to send: ")
        while not message.strip():
            message = input("Message cannot be empty. Enter the message to send: ")
        print("SHA-256 of the message:")
        print("  ", sha256_hex(message))
        signature = sign(private_key, message)
        print(f"Signed with the private key. Signature size: {len(signature)} bytes")
        print("Signature (start):", signature.hex()[:32], "...")
        print("Packet sent: (message, signature)")
        while True:
            run_once(private_key, public_key, message, signature)
            again = input("\nPress Enter to tamper this message again, 'n' for a new message, 'q' to quit: ").strip().lower()
            if again == "q":
                print("Goodbye!")
                return
            if again == "n":
                break
if __name__ == "__main__":
    main()

