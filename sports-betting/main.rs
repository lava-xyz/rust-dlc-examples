extern crate bitcoin;
extern crate dlc;
extern crate secp256k1_zkp;

use bitcoin::{OutPoint, Script};
use dlc::{OracleInfo, PartyParams, Payout, TxInputInfo};
use secp256k1_zkp::{
    bitcoin_hashes::sha256::Hash as Sha256,
    rand::{rngs::ThreadRng, RngCore},
    schnorrsig::{
        KeyPair as SchnorrKeyPair, PublicKey as SchnorrPublicKey, Signature as SchnorrSignature,
    },
    All, Message, PublicKey, Secp256k1, SecretKey,
};

fn generate_new_address() -> Script {
    Script::new()
}

fn create_counterparty(
    secp: &Secp256k1<All>,
    rng: &mut ThreadRng,
    input_amount: u64,
    collateral: u64,
    id: u64,
) -> (PartyParams, SecretKey) {
    let secret_key = SecretKey::new(rng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let change_script_pubkey = generate_new_address();
    let payout_script_pubkey = generate_new_address();

    let input = TxInputInfo {
        outpoint: OutPoint::null(),
        max_witness_len: 108,
        redeem_script: Script::new(),
        serial_id: id,
    };

    let params = PartyParams {
        fund_pubkey: public_key,

        input_amount,
        collateral,

        change_script_pubkey,
        change_serial_id: id,

        payout_script_pubkey,
        payout_serial_id: id,

        inputs: vec![input],
    };

    (params, secret_key)
}

fn sports_bet_payout() -> Vec<Payout> {
    // denote alice and bob as offerer and accepter respectively
    let duke_wins = Payout {
        offer: 0,
        accept: 100_000,
    };
    let unc_wins = Payout {
        offer: 100_000,
        accept: 0,
    };
    vec![duke_wins, unc_wins]
}

struct OracleSecret {
    sk_nonce: [u8; 32],
    kp: SchnorrKeyPair,
}

fn get_oracle_details(secp: &Secp256k1<All>, rng: &mut ThreadRng) -> (OracleInfo, OracleSecret) {
    let (oracle_kp, oracle_pubkey) = secp.generate_schnorrsig_keypair(rng);

    let mut sk_nonce = [0u8; 32];
    rng.fill_bytes(&mut sk_nonce);

    let oracle_r_kp =
        secp256k1_zkp::schnorrsig::KeyPair::from_seckey_slice(secp, &sk_nonce).unwrap();
    let nonce = SchnorrPublicKey::from_keypair(secp, &oracle_r_kp);

    let oracle_secret = OracleSecret {
        sk_nonce,
        kp: oracle_kp,
    };

    let oracle_info = OracleInfo {
        public_key: oracle_pubkey,
        nonces: vec![nonce],
    };

    (oracle_info, oracle_secret)
}

fn oracle_attest_to_event(
    secp: &Secp256k1<All>,
    oracle_secret: &OracleSecret,
) -> (Winner, SchnorrSignature) {
    let winner = Winner::Duke; // might as well just be hard-coded
    let message = Message::from_hashed_data::<Sha256>(&[winner as u8]);
    let signature = dlc::secp_utils::schnorrsig_sign_with_nonce(
        secp,
        &message,
        &oracle_secret.kp,
        &oracle_secret.sk_nonce,
    );
    (winner, signature)
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Winner {
    Unc,
    Duke,
}

fn main() {
    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();

    let blockchain = MockBlockchain::new();

    // generate our two parties
    let alice = create_counterparty(&secp, &mut rng, 100_000_000, 50_000, 0);
    let bob = create_counterparty(&secp, &mut rng, 75_000, 50_000, 1);

    // decontruct our two parties
    let (alice_params, alice_secret) = alice;
    let (bob_params, bob_secret) = bob;

    let (oracle_info, oracle_secret) = get_oracle_details(&secp, &mut rng);

    let payouts = sports_bet_payout();

    let refund_lock_time = 100;
    let fee_rate_per_vb = 4;
    let fund_lock_time = 10;
    let cet_lock_time = 10;
    let fund_output_serial_id = 0;

    let dlc_transactions = dlc::create_dlc_transactions(
        &alice_params,
        &bob_params,
        &payouts,
        refund_lock_time,
        fee_rate_per_vb,
        fund_lock_time,
        cet_lock_time,
        fund_output_serial_id,
    )
    .expect("error generating dlc transactions");

    // generate all of the messages that could occur
    let messages = vec![
        vec![vec![Message::from_hashed_data::<Sha256>(&[
            Winner::Unc as u8
        ])]],
        vec![vec![Message::from_hashed_data::<Sha256>(&[
            Winner::Duke as u8
        ])]],
    ];

    // Create Alice's adaptor signatures for the contract
    let cets = &dlc_transactions.cets;
    let funding_script_pubkey =
        dlc::make_funding_redeemscript(&alice_params.fund_pubkey, &bob_params.fund_pubkey);
    let fund_output_value = dlc_transactions.fund.output[0].value;

    let alice_adaptor_sigs = dlc::create_cet_adaptor_sigs_from_oracle_info(
        &secp,
        cets,
        &[oracle_info.clone()], // we are only using one oracle!
        &alice_secret,
        &funding_script_pubkey,
        fund_output_value,
        &messages,
    )
    .unwrap();

    // Bob can now verify Alice's signatures!
    for (i, (cet, sig)) in cets.iter().zip(alice_adaptor_sigs.iter()).enumerate() {
        dlc::verify_cet_adaptor_sig_from_oracle_info(
            &secp,
            sig,
            cet,
            &[oracle_info.clone()],
            &alice_params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
            &messages[i],
        )
        .expect("invalid cet!");
    }

    // in reality, bob would generate adaptor signatures just as alice did for alice to verify and store in the event
    // she wants the ability to close the contract

    // Now broadcast the funding transaction to the bitcoin blockchain
    let funding_transaction = &dlc_transactions.fund;
    blockchain.broadcast(funding_transaction);

    // the game occurs, let's see what the oracle said!
    let (winner, oracle_signature) = oracle_attest_to_event(&secp, &oracle_secret);

    let mut valid_cet = match winner {
        Winner::Duke => cets[1].clone(),
        Winner::Unc => cets[0].clone(),
    };

    // because duke won, bob can take alice's adaptor signatures and oracle signature to produce a
    // valid signed cet

    dlc::sign_cet(
        &secp,
        &mut valid_cet,
        &alice_adaptor_sigs[0],
        &[vec![oracle_signature]],
        &bob_secret,
        &alice_params.fund_pubkey,
        &funding_script_pubkey,
        fund_output_value,
    )
    .unwrap();

    blockchain.broadcast(&valid_cet);
}

// TODO: put mock blockchain in a library shared between all tutorails
// perhaps can make it check if transaction is valid and store them

use bitcoin::Transaction;

struct MockBlockchain {}

impl MockBlockchain {
    fn new() -> MockBlockchain {
        MockBlockchain {}
    }

    fn broadcast(&self, _transaction: &Transaction) {
        // noop!
    }
}
