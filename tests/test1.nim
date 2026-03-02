import strutils, unittest
import blackpaper

test "Common weak passwords are classified as weak":
  let res = passwordStrength("password", @["password", "123456", "qwerty"])
  check res.strength == Weak
  check res.score < 1.0'f32

test "Strong password is classified as strong":
  let res = passwordStrength("3s4F5j~@!1Z6woG")
  check res.strength == Strong
  check res.score > 3.0'f32

test "Passphrase with common words is penalized":
  let res = passwordStrength("Word Fox Jumped Over 13 Lazy Dogs!", @["word", "fox", "jumped", "over", "lazy", "dogs"])
  check res.strength != Strong
  check res.reason == SimilarToCommon

let surnames = readFile("tests/surnames.txt").splitLines()
test "Dictionary fuzzy matching penalizes similar passwords":
  let dict = preparePasswordStrengthDictionary(surnames, minTokenLen = 3, maxLenDelta = 3)

  let res = passwordStrength("tayl0r", dict)
  check res.strength == Weak
  check res.reason == SimilarToCommon
  echo res.strength, " ", res.score, " ", res.reason

suite "Surname-based password weaknesses":
  test "Surname-like passwords are penalized (leet + suffixes)":
    let dict = preparePasswordStrengthDictionary(surnames, minTokenLen = 3, maxLenDelta = 3)
    for pwd in @[
      "m1ller99!",
      "w1ls0n88#",
      "th0mas2024!",
      "jacks0n_77$",
      "anders0n#13"
    ]:
      let res = passwordStrength(pwd, dict)
      check res.reason == SimilarToCommon
      check res.strength != Strong

  test "Surname combinations are penalized":
    let dict = preparePasswordStrengthDictionary(surnames, minTokenLen = 3, maxLenDelta = 3)
    for pwd in @[
      "Miller Wilson 19!",
      "Taylor Anderson 88#",
      "Jackson Thomas 42$"
    ]:
      let res = passwordStrength(pwd, dict)
      check res.reason == SimilarToCommon
      check res.strength != Strong

  test "Random complex password is not flagged as common surname":
    let dict = preparePasswordStrengthDictionary(surnames, minTokenLen = 3, maxLenDelta = 3)
    let res = passwordStrength("3s4F5j~@!1Z6woG_$o*037C", dict)
    check res.reason != SimilarToCommon
    check res.strength == Strong