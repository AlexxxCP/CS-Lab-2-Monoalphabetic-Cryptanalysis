"""Checks for counting, substitution and preservation of nonletters."""
import unittest
import json
from pathlib import Path
from cryptanalysis import (
    add_mapping, common_groups, frequency_table, letter_counts, replace_letters,
)


class CryptanalysisTests(unittest.TestCase):
    def test_counts_ignore_nonletters_and_case(self):
        self.assertEqual(letter_counts("AaB b! 123, äß"), {"A": 2, "B": 2})

    def test_frequencies_use_only_letters(self):
        rows = frequency_table("AaB!")
        self.assertEqual(rows[0][:2], ("A", 2))
        self.assertAlmostEqual(rows[0][2], 200 / 3)
        self.assertAlmostEqual(sum(row[2] for row in rows), 100)
        self.assertTrue(all(row[2] == 0 for row in frequency_table("123!")))

    def test_groups_overlap_but_do_not_cross_words(self):
        self.assertEqual(common_groups("AAAA AB", 2), [("AA", 3), ("AB", 1)])
        self.assertEqual(common_groups("AB CD", 3), [])

    def test_mapping_is_one_to_one(self):
        mapping = {}
        add_mapping(mapping, "x", "e")
        add_mapping(mapping, "X", "T")
        self.assertEqual(mapping, {"X": "T"})
        with self.assertRaises(ValueError):
            add_mapping(mapping, "Y", "T")
        for cipher, plain in (("AA", "E"), ("1", "E"), ("X", "!")):
            with self.subTest(cipher=cipher, plain=plain):
                with self.assertRaises(ValueError):
                    add_mapping(mapping, cipher, plain)

    def test_full_substitution_preserves_case_and_nonletters(self):
        self.assertEqual(replace_letters("Xx Yy, 1900!\n—", {"X": "E", "Y": "T"}),
                         "Ee Tt, 1900!\n—")

    def test_partial_preview_marks_solved_letters(self):
        self.assertEqual(replace_letters("Xx yY!", {"X": "E"}, partial=True),
                         "ee YY!")

    def test_recovered_variant_14(self):
        folder = Path(__file__).resolve().parent
        text = (folder / "ciphertext.txt").read_text(encoding="utf-8")
        solution = json.loads((folder / "solution.json").read_text(encoding="utf-8"))
        mapping = {}
        for step in solution["steps"]:
            for cipher, plain in step["mappings"].items():
                add_mapping(mapping, cipher, plain)
        self.assertEqual(solution["variant"], 14)
        self.assertEqual(sum(letter_counts(text).values()), 3190)
        self.assertEqual(len(mapping), 26)
        self.assertEqual(len(set(mapping.values())), 26)
        plaintext = replace_letters(text, mapping)
        self.assertTrue(plaintext.startswith("Secret Office and their domestic ones"))
        self.assertIn("government", plaintext)
        self.assertIn("organization", plaintext)
        inverse = {plain: cipher for cipher, plain in mapping.items()}
        self.assertEqual(replace_letters(plaintext, inverse), text)
        for original, decoded in zip(text, plaintext):
            if not original.isascii() or not original.isalpha():
                self.assertEqual(original, decoded)

    def test_substitution_round_trip(self):
        text = "The message: 42% safe?\nKeep spaces, quotes 'A' and punctuation."
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = dict(zip(alphabet, alphabet[5:] + alphabet[:5]))
        inverse = {plain: cipher for cipher, plain in key.items()}
        self.assertEqual(
            replace_letters(replace_letters(text, key), inverse), text
        )


if __name__ == "__main__":
    unittest.main()
