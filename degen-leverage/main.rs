extern crate bitcoin;
extern crate dlc;
extern crate dlc_trie;
extern crate rust_decimal;
extern crate rust_decimal_macros;
extern crate secp256k1_zkp;

use std::{collections::HashMap, convert::TryInto};

use bitcoin::{Address, Network, OutPoint, Script, Transaction};
use dlc::{
    secp_utils::schnorrsig_decompose, OracleInfo, PartyParams, Payout, RangePayout, TxInputInfo,
};
use dlc_trie::{multi_oracle_trie_with_diff::MultiOracleTrieWithDiff, DlcTrie, OracleNumericInfo};
use rust_decimal::prelude::*;
use rust_decimal_macros::dec;
use secp256k1_zkp::{
    hashes::sha256::Hash as Sha256,
    rand::{rngs::ThreadRng, RngCore},
    schnorrsig::{
        KeyPair as SchnorrKeyPair, PublicKey as SchnorrPublicKey, Signature as SchnorrSignature,
    },
    All, Message, PublicKey, Secp256k1, SecretKey,
};

fn generate_new_address(secp: &Secp256k1<All>, rng: &mut ThreadRng) -> Script {
    let sk = bitcoin::PrivateKey {
        key: SecretKey::new(rng),
        network: Network::Testnet,
        compressed: true,
    };
    let pk = bitcoin::PublicKey::from_private_key(secp, &sk);
    Address::p2wpkh(&pk, Network::Testnet)
        .unwrap()
        .script_pubkey()
}

fn create_counterparty(
    secp: &Secp256k1<All>,
    rng: &mut ThreadRng,
    input_amount: u64,
    collateral: u64,
    id: u64,
) -> (PartyParams, SecretKey) {
    // check out the `sports-betting` example to learn more about the different things in this
    // function

    let secret_key = SecretKey::new(rng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let change_script_pubkey = generate_new_address(secp, rng);
    let payout_script_pubkey = generate_new_address(secp, rng);

    // here i use two transaction inputs for each counterparty as example
    let inputs = vec![
        TxInputInfo {
            outpoint: OutPoint::null(),
            max_witness_len: 108,
            redeem_script: Script::new(),
            serial_id: id,
        },
        TxInputInfo {
            outpoint: OutPoint::null(),
            max_witness_len: 108,
            redeem_script: Script::new(),
            serial_id: id + 1,
        },
    ];

    let params = PartyParams {
        fund_pubkey: public_key,

        input_amount,
        collateral,

        change_script_pubkey,
        change_serial_id: id,

        payout_script_pubkey,
        payout_serial_id: id,

        inputs,
    };

    (params, secret_key)
}

fn generate_payouts(
    max_price_btc: u64,
    current_bitcoin_price: u64,
    maker_collateral: u64,
    taker_collateral: u64,
    leverage_bp: u64,
) -> Vec<RangePayout> {
    // this function will generate the payout alice will receive for leveraging given the current
    // price of bitcoin
    // in effect the function that maps price of bitcoin to alice's payout looks like this
    //
    //                                        ----------
    //                                      /
    //                                     /
    // alice's payout                     /
    //                                   /
    //                                  /
    //                                 /
    //                   -------------
    //
    //                   0            a  b  c      max_price_btc
    //
    // where a, is the price of bitcoin at which alice blows through here leverage and is out of
    // money, b is the amount she starts off with (if the price of bitcoin does not move at all)
    // and c is the price of bitcoin at which she has gained all that she can from bob (bob did not
    // put enough collateral to account for any higher than this)

    // leverage_bp is the amount of leverage to take out in terms of basis points
    // leverage_bp = (50000) -> 5x leverage

    // also not i didnt place much time in confirmation what i had written below. please take its
    // correctedness with a grain of salt

    // temporarily convert these to decimals for precision
    let current_bitcoin_price = Decimal::new(current_bitcoin_price.try_into().unwrap(), 0);
    let maker_collateral = Decimal::new(maker_collateral.try_into().unwrap(), 8); // sats to bitcoin 8 decimal places
    let taker_collateral = Decimal::new(taker_collateral.try_into().unwrap(), 8);
    let leverage = Decimal::new(leverage_bp.try_into().unwrap(), 4);

    let total_collateral = maker_collateral + taker_collateral;

    // (y - taker_collateral) = leverage * (x - current_bitcoin_price)

    // => a = - taker_collateral / leverage + current_bitcoin_price
    let a = dec!(-1) * current_bitcoin_price * taker_collateral / leverage + current_bitcoin_price;
    let a = a.round();

    // => c = maker_collateral / leverage + current_bitcoin_price
    let c = current_bitcoin_price * maker_collateral / leverage + current_bitcoin_price;
    let c = c.round();

    println!("{}", maker_collateral);
    println!("{}-{}", a, c);

    let mut range_payouts = vec![];

    // all collateral flows to the maker when the price of bitcoin goes sufficiently low
    range_payouts.push(RangePayout {
        start: 0,
        count: a.to_usize().unwrap(),
        payout: Payout {
            offer: 0,
            accept: total_collateral.to_u64().unwrap(),
        },
    });

    for bitcoin_price in a.to_usize().unwrap()..=c.to_usize().unwrap() {
        let bitcoin_price_dec = Decimal::new(bitcoin_price.try_into().unwrap(), 0);
        let taker_payout =
            leverage * (bitcoin_price_dec - current_bitcoin_price) + taker_collateral;
        let taker_payout = taker_payout.round().to_u64().unwrap();
        let maker_payout = total_collateral.round().to_u64().unwrap() - taker_payout;
        let payout = Payout {
            offer: maker_payout,
            accept: taker_payout,
        };
        let range_payout = RangePayout {
            start: bitcoin_price,
            count: 1,
            payout,
        };
        range_payouts.push(range_payout);
    }

    // range payout for when the maker runs out of collateral. it all flows to the taker
    let count = max_price_btc as usize - c.to_usize().unwrap();
    range_payouts.push(RangePayout {
        start: c.to_usize().unwrap(),
        count,
        payout: Payout {
            offer: total_collateral.to_u64().unwrap(),
            accept: 0,
        },
    });

    println!("{:?}", range_payouts);

    range_payouts
}

struct OracleSecret {
    sk_nonces: Vec<[u8; 32]>,
    kp: SchnorrKeyPair,
}

fn get_oracles_details(
    secp: &Secp256k1<All>,
    rng: &mut ThreadRng,
    nb_digits: usize,
    nb_oracles: usize,
) -> Vec<(OracleInfo, OracleSecret)> {
    // in reality you don't get to dictate the number of digits the oracle attests to but FID!
    (0..nb_oracles)
        .map(|_| {
            let (oracle_kp, oracle_pubkey) = secp.generate_schnorrsig_keypair(rng);

            let n = (0..nb_digits)
                .map(|_| {
                    let mut sk_nonce = [0u8; 32];
                    rng.fill_bytes(&mut sk_nonce);

                    let oracle_r_kp = SchnorrKeyPair::from_seckey_slice(secp, &sk_nonce).unwrap();
                    let nonce = SchnorrPublicKey::from_keypair(secp, &oracle_r_kp);

                    (sk_nonce, nonce)
                })
                .collect::<Vec<_>>();

            let sk_nonces = n.iter().map(|x| x.0).collect::<Vec<_>>();
            let nonces = n.iter().map(|x| x.1).collect::<Vec<_>>();

            let oracle_info = OracleInfo {
                public_key: oracle_pubkey,
                nonces,
            };

            let oracle_secret = OracleSecret {
                sk_nonces,
                kp: oracle_kp,
            };

            (oracle_info, oracle_secret)
        })
        .collect()
}

fn generate_precomputed_points(
    secp: &Secp256k1<All>,
    oracle_details: &[OracleInfo],
) -> Vec<Vec<Vec<PublicKey>>> {
    oracle_details
        .iter()
        .map(|dets| {
            let pubkey = dets.public_key;
            let nonces = &dets.nonces;
            nonces
                .iter()
                .map(|nonce| {
                    (0u8..=1)
                        .map(|outcome| {
                            let message = Message::from_hashed_data::<Sha256>(&[outcome]);
                            dlc::secp_utils::schnorrsig_compute_sig_point(
                                secp, &pubkey, nonce, &message,
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

struct OracleAttestation {
    price_btc: usize,
    // the schnorr signature for each digit
    signatures: Vec<SchnorrSignature>,
}

fn retrieve_oracle_attestations(
    secp: &Secp256k1<All>,
    oracles_secrets: &[OracleSecret],
    // messages: &[Vec<Vec<Message>>],
) -> HashMap<usize, OracleAttestation> {
    // this function returns a hash map that maps an oracle index to the attestation associated
    // with such oracle index. the oracle index is the index by which its details was passed into
    // the trie functions in the precomputed points 3d vector

    let messages = (0..2) // n_outcomes
        .map(|x| {
            (0..5) // n_oracles
                .map(|y| {
                    (0..18) // n_digits
                        .map(|z| Message::from_hashed_data::<Sha256>(&[((y + x + z) as u8)]))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // return any number of oracle attestations so long as the number we return is bigger than the
    // threshold
    let oracle_indices = [1usize, 3, 4, 5];

    let mut map = HashMap::new();

    for &i in oracle_indices.iter() {
        let mut signatures = vec![];
        for j in 0..18 {
            let oracle_kp = &oracles_secrets[i].kp;
            let oracle_sk_nonce = &oracles_secrets[i].sk_nonces[j];
            let sig = dlc::secp_utils::schnorrsig_sign_with_nonce(
                &secp,
                &messages[0][i][j], // we are choosing 0 as our digit for every digit, effectively attesting to bitcoin at 0
                oracle_kp,
                oracle_sk_nonce,
            );
            signatures.push(sig);
        }
        let attestation = OracleAttestation {
            price_btc: 0, // RIP
            signatures,
        };
        map.insert(i, attestation);
    }

    map
}

fn main() {
    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();

    let blockchain = MockBlockchain::new();

    let alice = create_counterparty(&secp, &mut rng, 99_950_000, 10_000_000, 0);
    let bob = create_counterparty(&secp, &mut rng, 25_000_000, 20_000_000, 2);

    let (alice_params, alice_secret) = alice;
    let (bob_params, bob_secret) = bob;

    // oracles can only attest to a finite number of digits as the price of bitcoin. thus, there is
    // an effective maximum on the price of bitcoin that this contract can account for
    let nb_digits = 18;
    let max_price_bitcoin = (1 << nb_digits) - 1;

    let range_payouts = generate_payouts(
        max_price_bitcoin,
        20_000, // current price of bitcoin
        bob_params.collateral,
        alice_params.collateral,
        50_000, // 5x leverage lfg
    );

    // create dlc transaction retrieve the funding transaction, funding script and refund
    // transaction. we are going to generate the cets in a different way
    let refund_lock_time = 100;
    let fee_rate_per_vb = 4;
    let fund_lock_time = 10;
    let cet_lock_time = 10;
    let fund_output_serial_id = 0;

    let payouts = range_payouts
        .iter()
        .map(|rp| rp.payout.clone())
        .collect::<Vec<_>>();

    let dlc_transaction = dlc::create_dlc_transactions(
        &alice_params,
        &bob_params,
        &payouts,
        refund_lock_time,
        fee_rate_per_vb,
        fund_lock_time,
        cet_lock_time,
        fund_output_serial_id,
    )
    .unwrap();

    let funding_transaction = dlc_transaction.fund;
    let cets = dlc_transaction.cets;
    let funding_script_pubkey = dlc_transaction.funding_script_pubkey;
    let _refund_transaction = dlc_transaction.refund;
    let fund_output_value = funding_transaction.output[0].value;
    let nb_oracles = 5; // we are using five oracles
    let threshold = 3; // we need three of the five oracles to agree

    // all of our oracles are going to attest in base 2 and assume that all of them attest to the
    // same number of digits (i.e. 18 in this example). you could manage oracles that attested to
    // different number of digits
    let oracle_numeric_infos = OracleNumericInfo {
        base: 2,
        nb_digits: vec![nb_digits; nb_oracles],
    };

    // these two parameters deal with the error in the oracle attestation amounts.
    // `min_support_exp` is the minimum error tolerance between the oracles that the algorithm
    // MUST support. `max_error_exp` is the maxmimum error that the compression algorithm can
    // support. any difference within the range [min_support_exp, max_error_exp] is not guarenteed
    // to be accepted. naturally, min_support_exp < max_error_exp. both must be powers of two
    let min_support_exp = 32;
    let max_error_exp = 64;

    // we can use this trie to efficiently create adaptor signatures, verify adaptor signatures and
    // create transaction signatures from adaptor signatures for numeric dlcs
    let mut trie = MultiOracleTrieWithDiff::new(
        &oracle_numeric_infos,
        threshold,
        min_support_exp,
        max_error_exp,
    )
    .unwrap();

    // again we will only show the example where alice signs adaptor signatures for bob and not the
    // other way around

    let oracles = get_oracles_details(&secp, &mut rng, nb_digits, nb_oracles);
    let oracles_infos = oracles.iter().map(|o| o.0.clone()).collect::<Vec<_>>();
    let oracles_secrets = oracles.into_iter().map(|o| o.1).collect::<Vec<_>>();

    // the trie needs information about the oracles to construct the trie that will dictate
    // creation of adaptor signatures. make this super high dimensional table that will "store" the
    // oracle public information. almost all of the tables have similar forms just i would just
    // learn how to construct it and not really how it is used
    let precomputed_points = generate_precomputed_points(&secp, &oracles_infos);

    let alice_adaptor_sigs = trie
        .generate_sign(
            &secp,
            &alice_secret,
            &funding_script_pubkey,
            fund_output_value,
            &range_payouts,
            &cets,
            &precomputed_points,
            0, // this value is not incredibly important to worry about
        )
        .unwrap();

    // bob can now verify alice's adaptor signatures
    trie.verify(
        &secp,
        &alice_params.fund_pubkey,
        &funding_script_pubkey,
        fund_output_value,
        &alice_adaptor_sigs,
        &cets,
        &precomputed_points,
    )
    .expect("invalid adaptor signatures");

    // everything is good! broadcast the funding transaction
    blockchain.broadcast(&funding_transaction);

    // lets see what the oracles said!!! let's get the attestations for four of them (we only need
    // 31)
    let attestations = retrieve_oracle_attestations(&secp, &oracles_secrets);

    // for each attestation, convert the price of bitcoin into binary representation. this enables
    // the trie to lookup which information to find that would be relevant
    let paths = attestations
        .iter()
        .map(|(&oracle_index, attestation)| {
            let mut x = attestation.price_btc;
            let path = (0..nb_digits)
                .map(|_| {
                    let this = x % 2;
                    x >>= 1;
                    this
                })
                .collect::<Vec<_>>();
            (oracle_index, path)
        })
        .collect::<Vec<_>>();

    // range info will tell us which adaptor signature and cet to use
    let (range_info, indexed_paths) = trie.multi_trie.look_up(&paths).unwrap();

    // extract the signatures from the trie based on the indexed paths from abot
    let all_sigs = indexed_paths
        .iter()
        .flat_map(|(oracle_index, outcome_digits)| {
            let sigs = &attestations.get(oracle_index).unwrap().signatures;
            let outcome_digits = outcome_digits.iter().collect::<Vec<_>>();
            sigs.iter()
                .enumerate()
                .filter(|(i, _)| outcome_digits.contains(&i))
                .map(|(_, sig)| sig)
                .collect::<Vec<_>>()
        })
        .cloned()
        .collect::<Vec<_>>();

    // compress all of the signatures into one secret key that can be used to decrypt the adaptor
    // signature
    let adaptor_dec_key = signatures_to_secret(&all_sigs);

    let valid_adaptor_sig = alice_adaptor_sigs[range_info.adaptor_index];
    let alice_signature = valid_adaptor_sig.decrypt(&adaptor_dec_key).unwrap();

    let mut valid_cet = cets[range_info.cet_index].clone();

    dlc::util::sign_multi_sig_input(
        &secp,
        &mut valid_cet,
        &alice_signature,
        &alice_params.fund_pubkey,
        &bob_secret,
        &funding_script_pubkey,
        fund_output_value,
        0, // input_index that this is signing multisig for
    );

    blockchain.broadcast(&valid_cet);

    // in case something goes wrong
    // blockchain.broadcast(&_refund_transaction);
}

fn signatures_to_secret(signatures: &[SchnorrSignature]) -> SecretKey {
    let s_values = signatures
        .iter()
        .map(|sig| schnorrsig_decompose(sig).unwrap().1)
        .collect::<Vec<_>>();
    let mut secret = SecretKey::from_slice(s_values[0]).unwrap();
    for s in s_values.iter().skip(1) {
        secret.add_assign(s).unwrap()
    }
    secret
}

struct MockBlockchain {}

impl MockBlockchain {
    fn new() -> MockBlockchain {
        MockBlockchain {}
    }

    fn broadcast(&self, _: &Transaction) {
        // this isn't actually a blockchain! i wonder if they fell for it
    }
}
