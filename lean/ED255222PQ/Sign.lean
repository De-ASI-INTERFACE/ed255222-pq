-- ED255222PQ.Sign
-- Abstract specification of ED255222-PQ signing.
-- Author: Richard Patterson

import ED255222PQ.KeyGen

namespace ED255222PQ

-- Abstract ML-DSA-44 signing: (sk, message_hash) -> signature
axiom mlDsa44Sign : SecretKey → List Octet → Option Signature

-- Output length law.
axiom mlDsa44Sign_length : ∀ (sk : SecretKey) (m : List Octet) (σ : Signature),
    mlDsa44Sign sk m = some σ → σ.length = sigLen

-- Build domain-separated pre-image for signing.
def buildPre (ctx : Context) : List Octet :=
  dstSign ++ [ctx.length.toUInt8] ++ ctx

-- Hash the message with domain separation to 64 bytes.
def hashMessage (ctx : Context) (msg : Message) : List Octet :=
  shake256 (buildPre ctx ++ msg) 64

-- ED255222-PQ signing.
def sign (sk : SecretKey) (msg : Message) (ctx : Context) : Option Signature :=
  if sk.length = skLen then
    if ctx.length ≤ maxCtxLen then
      mlDsa44Sign sk (hashMessage ctx msg)
    else none
  else none

-- Lemma: sign output has correct length.
lemma sign_length (sk : SecretKey) (msg : Message) (ctx : Context)
    (h_sk : sk.length = skLen) (h_ctx : ctx.length ≤ maxCtxLen)
    (σ : Signature) (h_sign : sign sk msg ctx = some σ) :
    σ.length = sigLen := by
  simp [sign, h_sk, h_ctx] at h_sign
  exact mlDsa44Sign_length sk _ σ h_sign

end ED255222PQ
