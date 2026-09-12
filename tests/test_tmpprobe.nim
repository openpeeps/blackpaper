import std/strutils
import ../src/blackpaper

let surnames = readFile("tests/surnames.txt").splitLines()
for mld in [3, 4]:
  let dict = preparePasswordStrengthDictionary(surnames, minTokenLen = 3, maxLenDelta = mld)
  for pwd in ["tayl0r", "m1ller99!", "w1ls0n88#", "th0mas2024!", "jacks0n_77$",
              "anders0n#13", "Miller Wilson 19!", "3s4F5j~@!1Z6woG_$o*037C"]:
    let res = passwordStrength(pwd, dict)
    echo "d", mld, " ", pwd, " -> ", res.strength, " / ", res.reason,
      " / ", res.score, " / max=", fuzzyMaxScore(pwd, dict)

# Probe planned README examples
block:
  let res = passwordStrength("P@ssw0rd123")
  echo "basic: ", res.strength, " / ", res.reason, " / ", res.score

block:
  let commonPasswords = @["password", "123456", "qwerty", "abc123"]
  for pwd in ["password", "P@ssw0rd", "3s4F5j~@!1Z6woG"]:
    let res = passwordStrength(pwd, commonPasswords)
    echo "seq: ", pwd, " -> ", res.strength, " / ", res.reason, " / ", res.score

block:
  let dict = preparePasswordStrengthDictionary(@["password", "qwerty", "miller", "taylor", "anderson"])
  for pwd in ["tayl0r", "Miller99!", "anders0n#13", "3s4F5j~@!1Z6woG"]:
    let res = passwordStrength(pwd, dict)
    echo "dict: ", pwd, " -> ", res.strength, " / ", res.reason, " / ", res.score

block:
  var dict = preparePasswordStrengthDictionary(@["password"])
  dict.addToDictionary(["superman", "dragon"])
  let res = passwordStrength("superman2024!", dict)
  echo "grow: superman2024! -> ", res.strength, " / ", res.reason, " / ", res.score

block:
  echo "sim jackson/jacksontts: ", fuzzySimilarity("jackson", "jacksontts")
  echo "sim anderson/andersonle: ", fuzzySimilarity("anderson", "andersonle")
