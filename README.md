# Laboratory Work No. 2: Cryptanalysis of Monoalphabetic Ciphers

- **Author:** Luchiciov Alexei
- **Group:** FAF-241
- **Teacher:** Maia Zaica
- **Assigned variant:** V14
- **Repository:** https://github.com/AlexxxCP/CS-Lab-2-Monoalphabetic-Cryptanalysis

The laboratory recovers the English message in variant V14 using letter
frequencies and recognizable word patterns. Only letters are replaced;
spaces, punctuation, digits and line breaks are preserved.

## Run the program

Open a terminal in this folder:

```powershell
python cryptanalysis.py
```

The menu can display frequencies, count common bigrams and trigrams,
add or remove guesses, preview the message, show the key and save results.

Start with a blank key and use option 3 to enter guesses. For example,
ciphertext letter `V` and plaintext letter `E` means **V decrypts to E**.
In a partial preview, solved letters are lowercase and unresolved letters
are uppercase. Option 7 loads the final key for the assigned variant.

## Replay the documented attack

```powershell
python cryptanalysis.py --demo
```

This replays the eight explained stages in `solution.json` and saves
the result to `output/`. It reproduces the documented manual attack;
it is not an automatic solver for every substitution cipher.

For another English ciphertext, use the interactive mode:

```powershell
python cryptanalysis.py --file your_message.txt
```

## Files

- `cryptanalysis.py`: program, using only the Python standard library.
- `ciphertext.txt`: the assigned ciphertext from the PDF.
- `solution.json`: recovered substitutions and the reason for each stage.
- `analysis_steps/`: complete partial plaintext after each stage.
- `output/plaintext.txt`: complete decoded text, preserving source formatting.
- `output/key.json`: recovered key, in ciphertext-to-plaintext direction.
- `output/frequencies.csv`: sorted counts and frequencies.
- `output/crypto_corner_verification.json`: counts and stage results from
  the required online activity.
- `screenshots/`: actual screenshots used in the report.
- `Report_Lab2_Luchiciov_Alexei.pdf`: final report.
- `Report_Lab2_Luchiciov_Alexei.docx`: editable Word report.
- `Report_Lab2_Luchiciov_Alexei.md`: readable Markdown report.

The source PDF contains joined words and some spaces inside words.
The decoded output keeps these exactly as they occur in `ciphertext.txt`.

## Required online activity

https://crypto.interactive-maths.com/frequency-analysis-breaking-the-code.html

Paste the ciphertext, click **Find Frequencies**, enter substitutions
under the ciphertext letters, and click **Make Substitutions**.
Keep **Remove spaces** unchecked. All 26 counts and all eight substitution
stages were checked against the Python program.

## Verification

```powershell
python -m unittest -v test_cryptanalysis.py
```

Checks cover letter counts, percentages, overlapping groups, one-to-one
mappings, partial previews, preserved nonletters and the recovered V14 key.
Re-encrypting the recovered plaintext with the inverse key must reproduce
the original ciphertext exactly.

Submit the PDF report to ELSE according to the teacher's instructions.
