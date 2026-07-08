//! ED255222-PQ Solana program processor.

use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
    program_error::ProgramError,
};
use borsh::{BorshDeserialize, BorshSerialize};

use ed255222_pq::{
    keypair::PublicKey as PqPublicKey,
    verify as pq_verify,
    constants::SIG_LEN,
};
use ed25519_dalek::{VerifyingKey as Ed25519Vk, Verifier, Signature as Ed25519Sig};

use crate::instructions::Ed255222PQInstruction;
use crate::state::HybridSignerV1;

pub fn process(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let ix = Ed255222PQInstruction::try_from_slice(input)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix {
        Ed255222PQInstruction::CreateHybridSigner { ed25519_pk, pq_pk } => {
            let acc_iter = &mut accounts.iter();
            let signer_acc = next_account_info(acc_iter)?;
            let state = HybridSignerV1 {
                version:    HybridSignerV1::VERSION,
                ed25519_pk,
                pq_pk,
                phase:      1,
            };
            state.serialize(&mut &mut signer_acc.data.borrow_mut()[..])?;
            msg!("ED255222-PQ: HybridSignerV1 created (Phase 1)");
            Ok(())
        }

        Ed255222PQInstruction::VerifyHybrid { message, ed25519_sig, pq_sig, context } => {
            let acc_iter = &mut accounts.iter();
            let signer_acc = next_account_info(acc_iter)?;
            let state = HybridSignerV1::try_from_slice(&signer_acc.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?;

            // Ed25519 verification.
            let ed_vk = Ed25519Vk::from_bytes(&state.ed25519_pk)
                .map_err(|_| ProgramError::Custom(10))?;
            let ed_sig = Ed25519Sig::from_bytes(&ed25519_sig);
            let v_e = ed_vk.verify(&message, &ed_sig).is_ok();

            // PQ verification.
            let pq_pk = PqPublicKey(state.pq_pk);
            let pq_sig_arr: [u8; SIG_LEN] = pq_sig.try_into()
                .map_err(|_| ProgramError::Custom(11))?;
            let v_p = pq_verify(&pq_pk, &message, &pq_sig_arr, &context).is_ok();

            if v_e && v_p {
                msg!("ED255222-PQ: hybrid verification PASSED");
                Ok(())
            } else {
                msg!("ED255222-PQ: hybrid verification FAILED (ed25519={}, pq={})", v_e, v_p);
                Err(ProgramError::Custom(2))
            }
        }

        Ed255222PQInstruction::UpgradeToPQOnly { auth_pq_sig } => {
            let acc_iter = &mut accounts.iter();
            let signer_acc = next_account_info(acc_iter)?;
            let mut state = HybridSignerV1::try_from_slice(&signer_acc.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?;

            // Verify authority PQ signature over upgrade message.
            let upgrade_msg = b"ED255222-PQ-UPGRADE-TO-PQ-ONLY";
            let pq_pk = PqPublicKey(state.pq_pk);
            pq_verify(&pq_pk, upgrade_msg, &auth_pq_sig, b"UPGRADE")
                .map_err(|_| ProgramError::Custom(3))?;

            state.phase = 2;
            state.serialize(&mut &mut signer_acc.data.borrow_mut()[..])?;
            msg!("ED255222-PQ: upgraded to PQ-Only (Phase 2)");
            Ok(())
        }
    }
}
