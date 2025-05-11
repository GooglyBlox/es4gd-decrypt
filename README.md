# ES4GD Save File Decryptor

A simple tool to decrypt and encrypt save files for [Encrypted Storage Extension for GDevelop](https://pandako.itch.io/es4gd).

**Short version**

Every character of the "encrypted" string is just the original character with + 1234 added to its Unicode code-point.
Subtract 1234 (decimal = 0x4D2) from every code-point and you get the plaintext.

---

### Decrypted text

```json
[{"Money":21321313123123,"Name":"asd","Score":111111111111111},
 "0ef304dea9b190d910e791a41c67f67069d4c180e5dfbe083b6dead8f56835e7"]
```

* Index 0 is the real save-data object (minified JSON).
* Index 1 is an HMAC-SHA-256 digest that verifies the integrity of the save data. It is calculated using:
  - Key: `str(KeyNumber) + "KEY"` (e.g. "1234KEY")
  - Data: The minified JSON string from index 0

---

### Logic

1. **Look for a repeated pattern.**
   The encrypted block has a run of 15 identical symbols (`ԃԃԃ…`).
   The cleartext in this example has a run of fifteen `1`s.

2. **Compare code-points.**

   ```
   ord('1')  =  49
   ord('ԃ') = 1283
   1283 − 49 = 1234
   ```

   Re-checking a dozen other characters gave the same offset (or the same offset ± multiples of 1 where noise had been inserted).

3. **Test the hypothesis.**

   ```python
   plain = ''.join(chr(ord(c) - 1234) for c in encrypted)
   ```

   It immediately produced perfectly readable JSON plus a hash.

---

### Universal decoder

```python
def decrypt_save(cipher: str) -> str:
    """Decrypt a save-string produced by the +1234 scheme."""
    return ''.join(chr(ord(ch) - 1234) for ch in cipher)

if __name__ == "__main__":
    encrypted = "ԭՍӴԟՁՀԷՋӴԌԄԃԅԄԃԅԃԅԃԄԅԃԄԅӾӴԠԳԿԷӴԌӴԳՅԶӴӾӴԥԵՁՄԷӴԌԃԃԃԃԃԃԃԃԃԃԃԃԃԃԃՏӾӴԂԷԸԅԂԆԶԷԳԋԴԃԋԂԶԋԃԂԷԉԋԃԳԆԃԵԈԉԸԈԉԂԈԋԶԆԵԃԊԂԷԇԶԸԴԷԂԊԅԴԈԶԷԳԶԊԸԇԈԊԅԇԷԉӴԯ"
    print(decrypt_save(encrypted))
```

Run it and you'll see the plaintext shown above. For a more robust implementation that handles all cases correctly, see [`codec.py`](https://github.com/GooglyBlox/es4gd-decrypt/blob/master/codec.py).
