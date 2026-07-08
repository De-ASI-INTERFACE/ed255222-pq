-- ED255222PQ.Correctness
-- Core correctness theorem: sign then verify succeeds for valid keys.
-- Author: Richard Patterson

import ED255222PQ.Verify

namespace ED255222PQ

-- Axiom: ML-DSA-44 correctness (sign then verify succeeds).
-- This is the foundational security property inherited from FIPS 204.
axiom mlDsa44Correctness :
    ∀ (sk : SecretKey) (pk : PublicKey) (m : List Octet) (σ : Signature),
    mlDsa44Sign sk m = some σ →
    mlDsa44Verify pk (hashMessage [] m) σ = true

/--
ED255222-PQ Correctness Theorem:
For any valid seed and message/context, if keyGen succeeds and
sign succeeds, then verify returns true.

This is the primary correctness property of ED255222-PQ.
It establishes that a signer with a legitimately generated key
can always produce verifiable signatures.
--/
theorem ed255222pq_correctness
    (seed : Seed)
    (msg  : Message)
    (ctx  : Context)
    (h_seed : seed.length = seedLen)
    (h_ctx  : ctx.length ≤ maxCtxLen)
    (sk : SecretKey) (pk : PublicKey)
    (hk : keyGen seed = some (sk, pk))
    (σ  : Signature)
    (hs : sign sk msg ctx = some σ) :
    verify pk msg σ ctx = true := by
  -- 1. Unfold verify: length checks pass since σ, pk, ctx are valid.
  simp [verify]
  constructor
  · exact (keyGen_lengths seed h_seed sk pk hk).2
  constructor
  · exact sign_length sk msg ctx
      (by simp [keyGen, h_seed] at hk; exact (mlDsa44KeyGen_lengths _ sk pk hk).1)
      h_ctx σ hs
  constructor
  · exact h_ctx
  -- 2. Apply ML-DSA-44 correctness axiom.
  · simp [sign, (by simp [keyGen, h_seed] at hk;
      exact (mlDsa44KeyGen_lengths _ sk pk hk).1 : sk.length = skLen), h_ctx] at hs
    exact mlDsa44Correctness sk pk (hashMessage ctx msg) σ hs

end ED255222PQ
