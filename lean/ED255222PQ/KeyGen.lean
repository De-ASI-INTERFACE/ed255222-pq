-- ED255222PQ.KeyGen
-- Abstract specification of ED255222-PQ key generation.
-- Author: Richard Patterson

import ED255222PQ.Basics

namespace ED255222PQ

-- Abstract SHAKE256 XOF: (input bytes, output length) -> output bytes
axiom shake256 : List Octet → Nat → List Octet

-- Output length law (assumed; to be verified against concrete impl)
axiom shake256_length : ∀ (input : List Octet) (n : Nat),
    (shake256 input n).length = n

-- Abstract ML-DSA-44 key generation from a 32-byte seed.
axiom mlDsa44KeyGen : List Octet → Option (SecretKey × PublicKey)

-- ML-DSA-44 keygen preserves key lengths.
axiom mlDsa44KeyGen_lengths : ∀ (seed : List Octet) (sk : SecretKey) (pk : PublicKey),
    mlDsa44KeyGen seed = some (sk, pk) →
    sk.length = skLen ∧ pk.length = pkLen

-- Domain-separated seed expansion.
def expandSeed (seed : Seed) : List Octet :=
  shake256 (dstKeyGen ++ seed) 32

-- ED255222-PQ key generation.
def keyGen (seed : Seed) : Option (SecretKey × PublicKey) :=
  if seed.length = seedLen then
    mlDsa44KeyGen (expandSeed seed)
  else
    none

-- Lemma: keyGen output has correct lengths.
lemma keyGen_lengths (seed : Seed)
    (h_seed : seed.length = seedLen)
    (sk : SecretKey) (pk : PublicKey)
    (h_kg : keyGen seed = some (sk, pk)) :
    sk.length = skLen ∧ pk.length = pkLen := by
  simp [keyGen, h_seed] at h_kg
  exact mlDsa44KeyGen_lengths _ sk pk h_kg

end ED255222PQ
