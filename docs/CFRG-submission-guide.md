# CFRG IETF Submission Guide for ED255222-PQ

**Draft:** `draft-patterson-cfrg-ed255222-pq-00`  
**Author:** Richard Patterson  
**Repository:** https://github.com/De-ASI-INTERFACE/ed255222-pq

---

## Step 1: Format the draft for IETF Datatracker

IETF drafts must be plain text or XML (RFC 7991).
The file `docs/draft-patterson-cfrg-ed255222-pq-00.txt` in this repo
is already formatted for plain-text submission.

Optionally, install `xml2rfc` to produce the XML variant:
```bash
pip install xml2rfc
xml2rfc draft-patterson-cfrg-ed255222-pq-00.xml
```

## Step 2: Submit to IETF Datatracker

1. Go to: https://datatracker.ietf.org/submit/
2. Upload `docs/draft-patterson-cfrg-ed255222-pq-00.txt`
3. Confirm metadata:
   - Document name: `draft-patterson-cfrg-ed255222-pq-00`
   - Author: Richard Patterson
   - Group: CFRG (Crypto Forum Research Group)
4. After upload, IETF will send a confirmation email to verify authorship.
5. The draft appears publicly at:
   https://datatracker.ietf.org/doc/draft-patterson-cfrg-ed255222-pq/

## Step 3: Post to the CFRG Mailing List

1. Subscribe to CFRG mailing list:
   https://www.ietf.org/mailman/listinfo/cfrg
2. Send an announcement email to: cfrg@irtf.org

Sample subject:
```
[CFRG] New draft: draft-patterson-cfrg-ed255222-pq-00
```

Sample body:
```
Dear CFRG,

I have submitted a new Internet-Draft:

  Title:    ED255222-PQ: A Post-Quantum Signature Profile Based on ML-DSA-44
  Draft:    draft-patterson-cfrg-ed255222-pq-00
  URL:      https://datatracker.ietf.org/doc/draft-patterson-cfrg-ed255222-pq/
  Repo:     https://github.com/De-ASI-INTERFACE/ed255222-pq

ED255222-PQ is a named, versioned profile of ML-DSA-44 (NIST FIPS 204)
designed as a post-quantum replacement for Ed25519 in high-throughput
distributed ledgers, with primary integration on Solana.

The draft defines key generation, signing, verification, domain separation,
a hybrid Ed25519+PQ construction, test vectors, and a Solana program interface.
A Lean 4 formal specification with a correctness theorem is included.

Comments, review, and crypto-analytic feedback are welcome.

Reference implementation: https://github.com/De-ASI-INTERFACE/ed255222-pq

Best regards,
Richard Patterson
```

## Step 4: CFRG Review Process

Per CFRG process guidelines:
- Initial review period: typically 2-4 weeks.
- Reviewers will check: security assumptions, parameter rationale,
  test vectors, formal security claims.
- You should expect requests for:
  - Clarification of novel elements vs ML-DSA.
  - Performance benchmarks.
  - Third-party security review.

See: https://wiki.ietf.org/group/cfrg/CFRG-Process

## Step 5: Respond and Iterate

- Address reviewer comments via updated drafts (-01, -02, ...).
- Each revision should update the version number in the filename.
- Keep the reference implementation in sync with spec changes.
