<p align="center">
  A super simple Password Strength Estimator<br>
  Written in the Nim language
</p>

<p align="center">
  <code>nimble install blackpaper</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/blackpaper/">API reference</a><br>
  <img src="https://github.com/openpeeps/blackpaper/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/blackpaper/workflows/docs/badge.svg" alt="Github Actions">
</p>

## Key Features
- Fast implementation in Nim with no runtime dependencies besides openparser
- Scores length, character diversity, repetition, sequential patterns and leet substitutions
- Optional common password list that penalizes known weak passwords
- SIMD-accelerated fuzzy matching through openparser/fuzzy, with leet-aware normalization
- Prepared dictionaries for reuse across many checks, with incremental updates
- Framework-agnostic, usable in any Nim project

> [!NOTE]
> This package does not ship a common password list. Bring your own (leaked password datasets, surnames, dictionary words) and feed it to the estimator.

## How scoring works
`passwordStrength` returns a `PasswordStrengthResult` with three fields: `strength` (Weak, Medium or Strong), `score` (a float where higher is stronger) and `reason` (a hint for user feedback).

Score bands: Weak below 3.0, Medium from 3.0 up to 3.8, Strong at 3.8 and above. Passwords shorter than 8 characters are always Weak (`TooShort`). A close resemblance to a known weak password reports `SimilarToCommon` and caps the strength (Weak on close matches, at most Medium on loose ones).

## Examples
### Basic check without a wordlist
```nim
import blackpaper

let res = passwordStrength("P@ssw0rd123")
echo res.strength  # Weak
echo res.reason    # TooPredictable
echo res.score     # 2.2
```

### Check against a list of common passwords
```nim
import blackpaper

let commonPasswords = @["password", "123456", "qwerty", "abc123",
                        "word", "fox", "jumped", "over", "lazy", "dogs"]

for pwd in ["password", "P@ssw0rd", "3s4F5j~@!1Z6woG"]:
  let res = passwordStrength(pwd, commonPasswords)
  echo pwd, " -> ", res.strength, " (", res.reason, ")"

# password -> Weak (SimilarToCommon)
# P@ssw0rd -> Weak (NotEnoughVariety)
# 3s4F5j~@!1Z6woG -> Strong (GoodComplexity)
```

### Prepared dictionary for repeated checks
Preprocessing the wordlist once pays off when you evaluate many passwords (for example at registration). Matching is leet-aware, so `tayl0r` is caught by `taylor`, and affixed variants such as `Miller99!` match `miller`:

```nim
import blackpaper

let dict = preparePasswordStrengthDictionary(@[
  "password", "qwerty", "miller", "taylor", "anderson"])

for pwd in ["tayl0r", "Miller99!", "3s4F5j~@!1Z6woG"]:
  let res = passwordStrength(pwd, dict)
  echo pwd, " -> ", res.strength, " (", res.reason, ")"

# tayl0r -> Weak (SimilarToCommon)
# Miller99! -> Weak (SimilarToCommon)
# 3s4F5j~@!1Z6woG -> Strong (GoodComplexity)
```

### Grow a dictionary incrementally
```nim
import blackpaper

var dict = preparePasswordStrengthDictionary(@["password", "qwerty"])
dict.addToDictionary(["superman", "dragon", "miller"])

for pwd in ["dragon", "superman2024!", "Miller99!"]:
  let res = passwordStrength(pwd, dict)
  echo pwd, " -> ", res.strength, " (", res.reason, ")"

# dragon -> Weak (SimilarToCommon)
# superman2024! -> Medium (SimilarToCommon)
# Miller99! -> Weak (SimilarToCommon)
```

### Direct similarity score
`fuzzySimilarity` returns a normalized 0..1 score between two strings (1.0 is an exact match, 0.0 is no match). It is the same measure the estimator uses internally:

```nim
import blackpaper

echo fuzzySimilarity("miller", "miller")    # 1.0
echo fuzzySimilarity("miller", "miller99")  # 0.75
echo fuzzySimilarity("xqztkb", "anderson")  # 0.0
```

## Development
Run the test suite with `clue test` (or `nimble test`).

### Contributions
- Found a bug? [Create a new Issue](https://github.com/openpeeps/blackpaper/issues)
- Want to help? [Fork it!](https://github.com/openpeeps/blackpaper/fork)

### License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps and Contributors. All rights reserved.
