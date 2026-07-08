-- ED255222PQ.Verify
-- Abstract specification of ED255222-PQ verification.
-- Author: Richard Patterson

import ED255222PQ.Sign

namespace ED255222PQ

-- Abstract ML-DSA-44 verification.
axiom mlDsa44Verify : PublicKey → List Octet → Signature → Bool

-- ED255222-PQ verification.
def verify (pk : PublicKey) (msg : Message) (σ : Signature) (ctx : Context) : Bool :=
  if pk.length = pkLen then
    if σ.length = sigLen then
      if ctx.length ≤ maxCtxLen then
        mlDsa44Verify pk (hashMessage ctx msg) σ
      else false
    else false
  else false

end ED255222PQ
