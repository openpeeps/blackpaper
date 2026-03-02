# A password strength estimator based on length, char diversity, repetition
# sequential patterns, and leet substitutions, with optional fuzzy
# matching against common passwords.
#
#   (c) 2026 MIT License | Made by Humans from OpenPeeps
#   https://github.com/openpeeps/blackpaper

import std/[strutils, sequtils, math, tables]
import pkg/floof

import ./blackpaper/dictionary
export dictionary

## This module implements a password strength estimator that
## assesses password strength based on multiple factors including length,
## character diversity, repetition, sequential patterns, and leet substitutions.
## 
## It provides a comprehensive analysis of password strength and offers
## feedback for improvement.
## 
## Optionally, you can feed the estimator a list of common passwords or
## breached passwords to further penalize passwords that are known to be weak.
## 
## This module has no external dependencies and can be easily integrated into any Nim project
## that requires password strength evaluation, such as user registration or password change forms.

type
  PasswordStrength* = enum
    ## Represents the strength of a password.
    Weak, Medium, Strong

  PasswordStrengthReason* = enum
    ## Reasons for password strength classification, useful for user feedback.
    TooShort, NotEnoughVariety, TooPredictable, SimilarToCommon, GoodComplexity

  PasswordStrengthResult* = object
    ## The result of a password strength evaluation,
    ## including the strength category,
    strength*: PasswordStrength
      ## A float score representing the calculated strength
      ## of the password. Higher is stronger.
    score*: float32
      ## A human-readable reason explaining the strength
      ## assessment, useful for feedback to users.
    reason*: PasswordStrengthReason

proc normalizeLeetForSequence(s: string): string =
  # Keep digits intact; only normalize common symbol substitutions.
  result = s.toLowerAscii().multiReplace(
    ("@", "a"),
    ("$", "s")
  )

proc normalizeLeetForWordPattern(s: string): string =
  # Normalize leet only in alpha context to avoid false positives.
  let lower = s.toLowerAscii()
  result = newString(lower.len)
  for i, c in lower:
    var output = c
    if c in {'0','1','3','4','5','7','8','9','@','$'}:
      let leftAlpha = i > 0 and lower[i - 1].isAlphaAscii
      let rightAlpha = i + 1 < lower.len and lower[i + 1].isAlphaAscii
      if leftAlpha and rightAlpha:
        output = mapLeetChar(c)
    result[i] = output

proc leetInWordCount(s: string): int =
  # Count leet-like chars only when embedded BETWEEN letters.
  let lower = s.toLowerAscii()
  for i, c in lower:
    let isLeet = c in {'0','1','3','4','5','7','8','9','@','$'}
    if not isLeet: continue
    let leftAlpha = i > 0 and lower[i-1].isAlphaAscii
    let rightAlpha = i+1 < lower.len and lower[i+1].isAlphaAscii
    if leftAlpha and rightAlpha:
      inc(result)

proc longestAlphaRun(s: string): int =
  # Longest contiguous alphabetic run.
  var cur = 0
  for c in s:
    if c.isAlphaAscii:
      inc(cur)
      if cur > result: result = cur
    else:
      cur = 0

proc longestSequentialRun(s: string): int =
  # Longest ascending/descending run for letters or digits.
  if s.len == 0: return 0
  var best = 1
  for i in 0 ..< s.len:
    var asc = 1
    var j = i + 1
    while j < s.len and
          ((s[j-1].isAlphaAscii and s[j].isAlphaAscii) or
           (s[j-1].isDigit and s[j].isDigit)) and
          ord(s[j]) == ord(s[j-1]) + 1:
      inc(asc)
      inc(j)
    if asc > best: best = asc

    var desc = 1
    j = i + 1
    while j < s.len and
          ((s[j-1].isAlphaAscii and s[j].isAlphaAscii) or
           (s[j-1].isDigit and s[j].isDigit)) and
          ord(s[j]) == ord(s[j-1]) - 1:
      inc(desc)
      inc(j)
    if desc > best: best = desc
  result = best

proc hasSequential(s: string, minLen: int = 3): bool =
  # Checks for ascending or descending sequences of minLen or more
  for i in 0 ..< s.len - minLen + 1:
    var asc = true
    var desc = true
    for j in 1 ..< minLen:
      if s[i+j] != chr(ord(s[i]) + j): asc = false
      if s[i+j] != chr(ord(s[i]) - j): desc = false
    if asc or desc: return true
  return false

proc wordLikeTokenCount(s: string): int =
  # Counts tokens that look like normal words (mostly alphabetic, len >= 3)
  # 
  # This is a heuristic to detect sentence-like passphrases, which may be weaker
  # than random strings of the same length.
  #
  # For example, "Correct Horse Battery Staple" has 4 word-like tokens,
  # which may warrant a mild penalty
  for tok in s.splitWhitespace():
    var alpha = 0
    var alnum = 0
    for c in tok:
      if c.isAlphaAscii: inc(alpha)
      if c.isAlphaNumeric: inc(alnum)
    if alnum >= 3 and (alpha * 100 div alnum) >= 80:
      inc(result)

proc normalizeToken(s: string): string =
  # Lowercase + keep only alnum chars, so "Dogs!" > "dogs"
  for c in s.toLowerAscii():
    if c.isAlphaNumeric:
      result.add(c)

#
# Public API
#
proc passwordStrength*(password: string): PasswordStrengthResult =
  ## Evaluates the strength of a password based on multiple factors including length,
  ## character diversity, repetition, sequential patterns, and leet substitutions.
  ## Provides a strength category, score, and feedback reason.
  if password.len < 8:
    return PasswordStrengthResult() # default is Weak with TooShort reason

  let hasUpper = password.anyIt(it.isUpperAscii)
  let hasLower = password.anyIt(it.isLowerAscii)
  let hasDigit = password.anyIt(it.isDigit)
  let hasSymbol = password.anyIt(not it.isAlphaNumeric)

  var diversity = 0
  if hasUpper: inc(diversity)
  if hasLower: inc(diversity)
  if hasDigit: inc(diversity)
  if hasSymbol: inc(diversity)

  # Penalize repeated characters
  var charCounts = initCountTable[char]()
  for c in password: charCounts.inc(c)
  let maxRepeat = charCounts.values.toSeq.max
  let uniqueRatio = float32(charCounts.len) / float32(password.len)

  # Penalize sequential patterns, original + leet-normalized-for-sequence
  let seqLenRaw = longestSequentialRun(password)
  let seqLenNorm = longestSequentialRun(normalizeLeetForSequence(password))
  let seqLen = max(seqLenRaw, seqLenNorm)

  # Penalize leet substitutions used inside words
  let leetWordHits = leetInWordCount(password)

  # Penalize word-like patterns after leet normalization
  let normalizedWord = normalizeLeetForWordPattern(password)
  let alphaRun = longestAlphaRun(normalizedWord)

  # Score calculation
  var score = float32(password.len) / 8.0
  score += float32(diversity) * 0.75
  score += uniqueRatio * 1.0
  if maxRepeat > 2: score -= float32(maxRepeat - 2) * 0.5
  if seqLen >= 3:
    score -= 1.0 + float32(seqLen - 3) * 0.5

  # Stronger leet-in-word penalty (capped)
  score -= min(float32(leetWordHits) * 0.30, 1.2)

  # Optional: mild penalty for sentence-like passphrases

  let tokenCount = password.splitWhitespace().len
  let wordLike = wordLikeTokenCount(password)
  if tokenCount >= 4 and wordLike >= 4:
    score -= 0.6

  # Penalty for long hidden alphabetic words (capped)
  if alphaRun >= 6:
    score -= min(1.2 + float32(alphaRun - 6) * 0.15, 2.2)

  # Slightly relaxed thresholds
  var strength: PasswordStrength
  var reason: PasswordStrengthReason
  
  if diversity < 2 or score < 2.2:
    strength = Weak
    reason = TooPredictable
  elif score < 3.8:
    strength = Medium
    reason = NotEnoughVariety
  else:
    strength = Strong
    reason = GoodComplexity
    
  result = PasswordStrengthResult(
    strength: strength,
    score: score,
    reason: reason
  )

proc passwordStrength*(password: string, dict: PasswordStrengthDictionary): PasswordStrengthResult =
  ## Complexity score + optional fuzzy penalty using a prepared dictionary.
  ## 
  ## This allows you to further penalize passwords that are similar to known weak passwords,
  ## while still providing a complexity-based strength assessment.
  result = passwordStrength(password)

  let maxCommonScore = fuzzyMaxScore(password, dict)
  let isSimilar = maxCommonScore >= 0.50'f32   # was likely too strict

  result.score -= maxCommonScore * 3.0'f32
  if result.score < 0.0'f32:
    result.score = 0.0'f32

  if isSimilar:
    if maxCommonScore >= 0.70'f32:
      result.strength = Weak
    elif result.strength == Strong:
      result.strength = Medium
    result.reason = SimilarToCommon

  # Do not override reason if already flagged as similar
  if not isSimilar:
    if result.score < 2.2'f32:
      result.strength = Weak
      result.reason = NotEnoughVariety
    elif result.score < 3.8'f32 and result.strength == Strong:
      result.strength = Medium
      result.reason = NotEnoughVariety

proc passwordStrength*(password: string, commonPasswords: seq[string]): PasswordStrengthResult =
  ## Complexity score + optional fuzzy penalty against provided common passwords.
  result = passwordStrength(password)

  if password.len == 0 or commonPasswords.len == 0:
    return # no need to apply fuzzy matching if password is empty or no common passwords provided

  # Pre-normalize common passwords once
  var commonNorm: seq[string] = @[]
  for c in commonPasswords:
    let n = normalizeToken(c)
    if n.len > 0:
      commonNorm.add(n)

  # Fuzzy match against common passwords
  var maxCommonScore = 0.0'f32
  let fullNorm = normalizeToken(password)

  if fullNorm.len > 0:
    for common in commonNorm:
      let s = scoreMatchSSE2(fullNorm, common)
      if s > maxCommonScore:
        maxCommonScore = s

  for tok in password.splitWhitespace():
    let tokNorm = normalizeToken(tok)
    if tokNorm.len < 3: # skip tiny tokens
      continue
    for common in commonNorm:
      let s = scoreMatchSSE2(tokNorm, common)
      if s > maxCommonScore:
        maxCommonScore = s

  if maxCommonScore >= 0.75'f32:
    result.strength = Weak
    result.reason = SimilarToCommon
  elif maxCommonScore >= 0.55'f32:
    if result.strength == Strong:
      result.strength = Medium
    result.reason = SimilarToCommon

  # apply penalty and downgrade classification if needed
  result.score -= maxCommonScore * 3.0'f32
  if result.score < 0.0'f32:
    reset(result.score)

  if maxCommonScore >= 0.75'f32:
    result.strength = Weak
    result.reason = SimilarToCommon
  elif maxCommonScore >= 0.55'f32:
    if result.strength == Strong:
      result.strength = Medium
    result.reason = SimilarToCommon

  if result.strength != Weak:
    if result.score < 2.2'f32:
      result.strength = Weak
      result.reason = TooPredictable
    elif result.score < 3.8'f32 and result.strength == Strong:
      result.strength = Medium
      result.reason = NotEnoughVariety
