# A password strength estimator based on length, char diversity, repetition
# sequential patterns, and leet substitutions, with optional fuzzy
# matching against common passwords.
#
#   (c) 2026 MIT License | Made by Humans from OpenPeeps
#   https://github.com/openpeeps/blackpaper


import std/[strutils, sequtils, math, tables, sets, algorithm]
import pkg/floof

## This module implements a dictionary for the password strength estimator,
## allowing for efficient exact and fuzzy matching against a list of common passwords,
## usually sourced from leaked password datasets, or dictionary of common words (nammes, places, etc)
## to catch people using easily guessable passwords.

type
  PasswordStrengthDictionary* = ref object
    ## Preprocessed dictionary for fast common-password/similarity checks.
    minTokenLen*: int
      ## Minimum token length to consider for fuzzy matching.
      ## Shorter tokens are ignored to reduce noise and improve
      ## performance.
    maxLenDelta*: int
      ## Maximum allowed length difference for fuzzy matching.
      ## This helps limit the number of comparisons and focus on
      ## more relevant candidates.
    entries*: seq[string]
      ## Original list of common passwords, used for exact matches
      ## and as a source for fuzzy candidates.
    byLen: Table[int, seq[string]]
      # Index of passwords by their length, for efficient length-based
      # filtering during fuzzy matching.
    seen: HashSet[string]
      # Set of seen passwords for O(1) exact match checks.

proc mapLeetChar*(c: char): char =
  case c
  of '0': 'o'
  of '1': 'l'
  of '3': 'e'
  of '4': 'a'
  of '5': 's'
  of '7': 't'
  of '8': 'b'
  of '9': 'g'
  of '@': 'a'
  of '$': 's'
  else: c

proc normalizeTokenLeet(s: string): string =
  ## Lowercase + alnum + leet normalization for query tokens.
  for c in s.toLowerAscii():
    if c.isAlphaNumeric or c in {'@', '$'}:
      result.add(mapLeetChar(c))

proc normalizeToken(s: string): string =
  # Lowercase + keep only alnum chars, so "Dogs!" -> "dogs"
  for c in s.toLowerAscii():
    if c.isAlphaNumeric:
      result.add(c)

proc addToDictionary*(dict: PasswordStrengthDictionary, words: openArray[string]) =
  ## Add words into a prepared dictionary (normalized + dedup + bucketed by length)
  if dict.isNil: return
  for w in words:
    let n = normalizeToken(w)
    if n.len < dict.minTokenLen: continue
    if dict.seen.containsOrIncl(n): continue
    dict.entries.add(n)
    if not dict.byLen.hasKey(n.len):
      dict.byLen[n.len] = @[]
    dict.byLen[n.len].add(n)

proc preparePasswordStrengthDictionary*(words: openArray[string],
        minTokenLen: int = 3,
        maxLenDelta: int = 3
  ): PasswordStrengthDictionary =
  ## Initializes a reusable dictionary for passwordStrength(password, dict)
  new(result)
  result.minTokenLen = max(1, minTokenLen)
  result.maxLenDelta = max(0, maxLenDelta)
  result.addToDictionary(words)
  result.entries.sort(system.cmp[string])

proc fuzzyMaxScore*(password: string, dict: PasswordStrengthDictionary): float32 =
  ## Computes the maximum fuzzy similarity score between the password and entries in the dictionary.
  if dict.isNil or dict.entries.len == 0 or password.len == 0:
    return 0.0'f32

  proc scoreAgainstBuckets(token: string, best: var float32) =
    if token.len < dict.minTokenLen: return
    # exact normalized hit
    if dict.seen.contains(token):
      best = 1.0'f32
      return
    let lo = max(dict.minTokenLen, token.len - dict.maxLenDelta)
    let hi = token.len + dict.maxLenDelta
    for L in lo .. hi:
      if not dict.byLen.hasKey(L): continue
      for common in dict.byLen[L]:
        let s = scoreMatchSSE2(token, common)
        if s > best: best = s

  var best = 0.0'f32
  let fullNorm = normalizeToken(password)
  let fullLeet = normalizeTokenLeet(password)
  scoreAgainstBuckets(fullNorm, best)
  if best < 1.0'f32:
    scoreAgainstBuckets(fullLeet, best)

  for tok in password.splitWhitespace():
    let t = normalizeToken(tok)
    let tl = normalizeTokenLeet(tok)
    scoreAgainstBuckets(t, best)
    if best < 1.0'f32:
      scoreAgainstBuckets(tl, best)
  result = best
