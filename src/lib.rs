use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::Result;
use hkdf::Hkdf;
use k256::{PublicKey, Scalar, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

pub mod utils;

#[derive(Debug, Clone)]
pub struct PubKey {
    key: PublicKey,
}

impl PubKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = PublicKey::from_sec1_bytes(&bytes)?;
        Ok(PubKey { key })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_encoded_point(true).as_bytes().to_vec()
    }
}

#[derive(Clone)]
pub struct PrivKey {
    key: SecretKey,
}

impl PrivKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let sk = SecretKey::from_slice(bytes)?;
        Ok(PrivKey { key: sk })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }
}

pub fn generate_keypair() -> (PrivKey, PubKey) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    let priv_key = PrivKey { key: sk };
    let pub_key = PubKey { key: pk };
    (priv_key, pub_key)
}

fn derive_shared_secret(sk: &SecretKey, pk: &PublicKey) -> Vec<u8> {
    let pk_point = *pk.as_affine();
    let sk_scalar: Scalar = sk.as_scalar_primitive().into();
    let shared_point = pk_point * sk_scalar;
    let encoded = shared_point.to_encoded_point(true);
    encoded.to_bytes().to_vec()
}

fn hkdf_expand(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"ecies-secp256k1-v1", &mut okm).unwrap();
    okm
}

pub fn encrypt(message: &[u8], recipient_pub_key: &PubKey) -> Vec<u8> {
    let recipient_pk = &recipient_pub_key.key;
    let eph_sk = SecretKey::random(&mut OsRng);
    let eph_pk = eph_sk.public_key();

    let shared_secret = derive_shared_secret(&eph_sk, &recipient_pk);
    let aes_key = hkdf_expand(&shared_secret);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher.encrypt(nonce, message).unwrap();

    let mut output = vec![];
    output.extend(eph_pk.to_encoded_point(true).as_bytes());
    output.extend(&iv);
    output.extend(&ciphertext);
    output
}

pub fn decrypt(ciphertext_bytes: &[u8], recipient_priv_key: &PrivKey) -> Result<Vec<u8>> {
    let data = ciphertext_bytes;
    let eph_pk = PublicKey::from_sec1_bytes(&data[..33]).unwrap();
    let iv = &data[33..45];
    let ciphertext = &data[45..];
    let recipient_sk = recipient_priv_key.key.clone();

    let shared_secret = derive_shared_secret(&recipient_sk, &eph_pk);
    let aes_key = hkdf_expand(&shared_secret);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();

    let nonce = Nonce::from_slice(iv);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext);
    decrypted_bytes.map_err(|_| anyhow::anyhow!("Decryption failed"))
}

pub fn encrypt_padded(
    message: &[u8],
    recipient_pub_key: &PubKey,
    padded_length: usize,
) -> Result<Vec<u8>> {
    if padded_length < message.len() + 4 {
        return Err(anyhow::anyhow!(
            "Padded length ({} bytes) shorter than the message length ({} bytes + 4 bytes for length info)",
            padded_length,
            message.len()
        ));
    }
    // prepend with the message length info in little endian (4 bytes)
    let mut padded_message: Vec<u8> = (message.len() as u32).to_le_bytes().to_vec();
    padded_message.extend(message);
    padded_message.resize(padded_length, 0u8);
    Ok(encrypt(&padded_message, recipient_pub_key))
}

pub fn decrypt_padded(ciphertext_bytes: &[u8], recipient_priv_key: &PrivKey) -> Result<Vec<u8>> {
    let padded_message = decrypt(ciphertext_bytes, recipient_priv_key)?;
    if padded_message.len() < 4 {
        return Err(anyhow::anyhow!(
            "Padded message shorter than 4 bytes ({} bytes)",
            padded_message.len()
        ));
    }
    let message_len = u32::from_le_bytes(padded_message[0..4].try_into()?) as usize;
    if message_len > padded_message.len() - 4 {
        return Err(anyhow::anyhow!(
            "Message length ({} bytes + 4 bytes for length info) greater than the padded message length ({} bytes)",
            message_len,
            padded_message.len()
        ));
    }
    Ok(padded_message[4..(message_len + 4)].to_vec())
}
