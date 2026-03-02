<p align="center">
  A super simple Password Strength Estimator for Nim language
  things. 👑 Written in Nim language
</p>

<p align="center">
  <code>nimble install blackpaper</code>
</p>

<p align="center">
  <a href="https://github.com/">API reference</a><br>
  <img src="https://github.com/openpeeps/pistachio/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/pistachio/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- 🚀 Fast and efficient implementation in Nim language
- 👌 Estimate on length &bullet; character diversity &bullet; repetition &bullet; sequential patterns &bullet; leet substitutions
- 🔎 Optional common password list for penalizing known weak/common passwords
- 🚀 SIMD-accelerated fuzzy matching for lightning-fast detection of passwords similar to common or breached passwords
- 💪 Framework-agnostic, can be used in any Nim project

> [NOTE]
> This package does not provide a common password list. You can eassily find one online and feed it to the estimator. [pkg/floof](https://github.com/arashi-software/floof)

## Examples
Here is an example password strength estimation using Blackpaper without a common password list:
```nim
import blackpaper

let res = passwordStrength("P@ssw0rd123")
echo "Score: ", res.score
echo "Strength: ", res.strength       # Weak
echo "Reason: ", res.reason           # TooPredictable
```

And here is an example with a common password list. 
```nim
import blackpaper

let commonPasswords = @["password", "123456", "qwerty", "abc123", "P@ssw0rd123",
                      "word", "fox", "jumped", "over", "lazy", "dogs"]

for pwd in ["Word Fox Jumped Over", "P@ssw0rd", "3s4F5j~@!1Z6woG"]:
  let res = passwordStrength(pwd, commonPasswords)
  echo "Password: ", pwd
  echo "Score: ", res.score
  echo "Strength: ", res.strength
  echo "Reason: ", res.reason
  echo "-----------------------------"
```

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](/issues)
- 👋 Wanna help? [Fork it!](/fork)
- 😎 [Get €20 in cloud credits from Hetzner](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4)

### 🎩 License
{PKG} | MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
