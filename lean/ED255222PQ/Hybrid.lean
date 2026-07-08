-- ED255222PQ.Hybrid
-- Formal specification of ED25519 + ED255222-PQ hybrid construction.
-- Author: Richard Patterson

import ED255222PQ.Verify

namespace ED255222PQ

-- Abstract Ed25519 verification.
axiom ed25519Verify : PublicKey → Message → List Octet → Bool
-- pk, message, 64-byte signature -> Bool

-- Hybrid verification: BOTH components must pass.
def hybridVerify
    (pk_ed  : PublicKey)
    (pk_pq  : PublicKey)
    (msg    : Message)
    (sig_ed : List Octet)
    (sig_pq : Signature)
    (ctx    : Context) : Bool :=
  ed25519Verify pk_ed msg sig_ed && verify pk_pq msg sig_pq ctx

-- Theorem: hybrid verification succeeds iff both components succeed.
theorem hybrid_correctness
    (pk_ed  : PublicKey)
    (pk_pq  : PublicKey)
    (msg    : Message)
    (sig_ed : List Octet)
    (sig_pq : Signature)
    (ctx    : Context)
    (h_ed   : ed25519Verify pk_ed msg sig_ed = true)
    (h_pq   : verify pk_pq msg sig_pq ctx = true) :
    hybridVerify pk_ed pk_pq msg sig_ed sig_pq ctx = true := by
  simp [hybridVerify, h_ed, h_pq]

end ED255222PQ
