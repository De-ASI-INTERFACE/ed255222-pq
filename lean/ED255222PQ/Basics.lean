-- ED255222PQ.Basics
-- Core types and parameter constants for ED255222-PQ formal specification.
-- Author: Richard Patterson
-- Spec:   draft-patterson-cfrg-ed255222-pq-00

namespace ED255222PQ

abbrev Octet    := UInt8
abbrev Message  := List Octet
abbrev PublicKey  := List Octet
abbrev SecretKey  := List Octet
abbrev Signature  := List Octet
abbrev Context    := List Octet
abbrev Seed       := List Octet

-- Parameter constants (ML-DSA-44, FIPS 204)
def seedLen  : Nat := 32
def pkLen    : Nat := 1312
def skLen    : Nat := 2560
def sigLen   : Nat := 2420
def maxCtxLen: Nat := 255

-- Domain separation tags (ASCII bytes)
def dstKeyGen : List Octet :=
  "ED255222-PQ-KEYGEN".toList.map (·.toNat.toUInt8)

def dstSign : List Octet :=
  "ED255222-PQ-SIGN".toList.map (·.toNat.toUInt8)

-- Validity predicates
def validSeed (s : Seed) : Prop     := s.length = seedLen
def validPublicKey (pk : PublicKey) : Prop := pk.length = pkLen
def validSecretKey (sk : SecretKey) : Prop := sk.length = skLen
def validSignature (σ : Signature)  : Prop := σ.length  = sigLen
def validContext (ctx : Context)    : Prop := ctx.length ≤ maxCtxLen

end ED255222PQ
