"""Laboratory Work No. 2: Cryptanalysis of Monoalphabetic Ciphers.

Author: Luchiciov Alexei | Group: FAF-241 | Teacher: Maia Zaica
This program helps with a frequency-analysis attack on an English message.
"""

from collections import Counter
from pathlib import Path
import argparse
import csv
import json
import re
import string
import textwrap

ALPHABET = string.ascii_uppercase
ENGLISH_FREQUENCIES = dict(zip(ALPHABET, [
    8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.01, 6.09, 6.97,
    0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.09, 5.99,
    6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
]))
FOLDER = Path(__file__).resolve().parent


def letter_counts(text):
    """Count English letters only, ignoring letter case."""
    return Counter(letter.upper() for letter in text
                   if letter in string.ascii_letters)


def frequency_table(text):
    counts = letter_counts(text)
    total = sum(counts.values())
    return [(letter, counts[letter],
             100 * counts[letter] / total if total else 0.0)
            for letter in sorted(ALPHABET,
                                 key=lambda letter: (-counts[letter], letter))]


def common_groups(text, length, limit=10):
    """Count overlapping groups within words, without crossing spaces."""
    groups = Counter()
    for word in re.findall(r"[A-Za-z]+", text):
        word = word.upper()
        groups.update(word[i:i + length]
                      for i in range(len(word) - length + 1))
    return sorted(groups.items(), key=lambda item: (-item[1], item[0]))[:limit]


def add_mapping(mapping, cipher_letter, plain_letter):
    """Keep the substitution one-to-one; allow changing a previous guess."""
    cipher_letter, plain_letter = cipher_letter.upper(), plain_letter.upper()
    if (len(cipher_letter) != 1 or cipher_letter not in ALPHABET
            or len(plain_letter) != 1 or plain_letter not in ALPHABET):
        raise ValueError("Use exactly one English letter A-Z for each value.")
    for current_cipher, current_plain in mapping.items():
        if current_cipher != cipher_letter and current_plain == plain_letter:
            raise ValueError(
                f"{plain_letter} is already assigned to {current_cipher}. "
                "Remove that mapping first."
            )
    mapping[cipher_letter] = plain_letter


def replace_letters(text, mapping, partial=False):
    """Preserve nonletters. A partial preview uses lowercase for solved letters."""
    result = []
    for letter in text:
        if letter in string.ascii_letters and letter.upper() in mapping:
            value = mapping[letter.upper()]
            result.append(value.lower() if partial or letter.islower() else value)
        else:
            result.append(letter.upper() if partial
                          and letter in string.ascii_letters else letter)
    return "".join(result)


def show_frequencies(text):
    print("\nCipher letter | Count | Frequency")
    for letter, count, percentage in frequency_table(text):
        print(f"      {letter}       | {count:5} | {percentage:7.2f}%")
    print("Total letters:", sum(letter_counts(text).values()))
    print("English reference order:",
          "".join(sorted(ALPHABET,
                         key=lambda letter: (-ENGLISH_FREQUENCIES[letter], letter))))
    print("Frequency order gives hints; it is not a guaranteed decryption key.")


def show_key(mapping):
    print("Cipher: " + ALPHABET)
    print("Plain:  " + "".join(mapping.get(letter, "?") for letter in ALPHABET))
    print("Direction: ciphertext letter -> plaintext letter.")


def save_results(text, mapping, folder):
    folder.mkdir(parents=True, exist_ok=True)
    missing = sorted(set(letter_counts(text)) - set(mapping))
    (folder / "plaintext.txt").write_text(
        replace_letters(text, mapping), encoding="utf-8"
    )
    (folder / "key.json").write_text(
        json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (folder / "frequencies.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Cipher letter", "Count", "Frequency (%)"])
        writer.writerows((letter, count, f"{frequency:.4f}")
                         for letter, count, frequency in frequency_table(text))
    if missing:
        print("Saved a partial result. Unresolved letters:", ", ".join(missing))
    else:
        print("Saved the complete plaintext, recovered key and frequency table.")


def load_solution():
    return json.loads((FOLDER / "solution.json").read_text(encoding="utf-8"))


def demonstrate(text):
    solution = load_solution()
    mapping = {}
    print("Variant:", solution["variant"])
    show_frequencies(text)
    print("Common bigrams:", common_groups(text, 2))
    print("Common trigrams:", common_groups(text, 3))
    for number, step in enumerate(solution["steps"], 1):
        print(f"\nStep {number}: {step['title']}")
        print(step["reason"])
        for cipher_letter, plain_letter in step["mappings"].items():
            add_mapping(mapping, cipher_letter, plain_letter)
        preview = replace_letters(text, mapping, partial=True)
        print(textwrap.fill(preview[:600], width=90))
    print("\nRECOVERED KEY")
    show_key(mapping)
    print("\nDECRYPTED MESSAGE")
    print(replace_letters(text, mapping))
    save_results(text, mapping, FOLDER / "output")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=FOLDER / "ciphertext.txt",
                        help="UTF-8 file containing the intercepted message")
    parser.add_argument("--demo", action="store_true",
                        help="replay the documented attack on the assigned variant")
    args = parser.parse_args()
    try:
        text = args.file.read_text(encoding="utf-8")
    except OSError as error:
        parser.error(str(error))
    if not letter_counts(text):
        parser.error("The message must contain at least one English letter.")
    print("Laboratory Work No. 2 - Monoalphabetic Cryptanalysis")
    print("Author: Luchiciov Alexei | Group: FAF-241")
    if args.demo:
        if args.file.resolve() != (FOLDER / "ciphertext.txt").resolve():
            parser.error("The documented attack is for ciphertext.txt only.")
        demonstrate(text)
        return

    mapping = {}
    while True:
        print("\n1. Letter frequencies")
        print("2. Common bigrams and trigrams")
        print("3. Add or change a letter mapping")
        print("4. Remove a letter mapping")
        print("5. Show partial plaintext")
        print("6. Show current key")
        print("7. Load the recovered solution for the assigned variant")
        print("8. Save the result")
        print("0. Exit")
        choice = input("Choose an option: ").strip()
        try:
            if choice == "1":
                show_frequencies(text)
            elif choice == "2":
                print("Bigrams:", common_groups(text, 2))
                print("Trigrams:", common_groups(text, 3))
            elif choice == "3":
                cipher_letter = input("Ciphertext letter: ")
                plain_letter = input("Plaintext letter: ")
                add_mapping(mapping, cipher_letter, plain_letter)
                print("Mapping saved.")
            elif choice == "4":
                letter = input("Ciphertext letter to remove: ").upper()
                if letter not in mapping:
                    raise ValueError("That letter has no current mapping.")
                del mapping[letter]
                print("Mapping removed.")
            elif choice == "5":
                print("Solved letters are lowercase; unknown letters are uppercase.")
                print(replace_letters(text, mapping, partial=True))
            elif choice == "6":
                show_key(mapping)
            elif choice == "7":
                if args.file.resolve() != (FOLDER / "ciphertext.txt").resolve():
                    raise ValueError("The recovered solution is for ciphertext.txt only.")
                recovered = {}
                for step in load_solution()["steps"]:
                    for cipher_letter, plain_letter in step["mappings"].items():
                        add_mapping(recovered, cipher_letter, plain_letter)
                mapping = recovered
                print("Recovered solution loaded.")
                show_key(mapping)
            elif choice == "8":
                save_results(text, mapping, FOLDER / "output")
            elif choice == "0":
                print("Goodbye!")
                return
            else:
                print("Invalid choice. Allowed values: 0-8.")
        except (ValueError, OSError) as error:
            print("Error:", error)


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nProgram closed.")
