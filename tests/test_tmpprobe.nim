import ../src/blackpaper

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
