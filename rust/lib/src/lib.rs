use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use k256::{PublicKey, Scalar, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

pub mod error;
pub mod utils;

use error::{Error, Result};

#[derive(Debug, Clone)]
pub struct PubKey {
    key: PublicKey,
}

impl PubKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = PublicKey::from_sec1_bytes(bytes)?;
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

fn hkdf_expand(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"ecies-secp256k1-v1", &mut okm)?;
    Ok(okm)
}

pub fn encrypt(message: &[u8], recipient_pub_key: &PubKey) -> Result<Vec<u8>> {
    let recipient_pk = &recipient_pub_key.key;
    let eph_sk = SecretKey::random(&mut OsRng);
    let eph_pk = eph_sk.public_key();

    let shared_secret = derive_shared_secret(&eph_sk, recipient_pk);
    let aes_key = hkdf_expand(&shared_secret)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)?;

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher.encrypt(nonce, message)?;

    let mut output = vec![];
    output.extend(eph_pk.to_encoded_point(true).as_bytes());
    output.extend(&iv);
    output.extend(&ciphertext);
    Ok(output)
}

pub fn decrypt(ciphertext_bytes: &[u8], recipient_priv_key: &PrivKey) -> Result<Vec<u8>> {
    if ciphertext_bytes.len() < 45 {
        return Err(Error::CryptoInvalidLength("Ciphertext too short".to_string()));
    }
    let data = ciphertext_bytes;
    let eph_pk = PublicKey::from_sec1_bytes(&data[..33])?;
    let iv = &data[33..45];
    let ciphertext = &data[45..];
    let recipient_sk = recipient_priv_key.key.clone();

    let shared_secret = derive_shared_secret(&recipient_sk, &eph_pk);
    let aes_key = hkdf_expand(&shared_secret)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)?;

    let nonce = Nonce::from_slice(iv);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)?;
    Ok(decrypted_bytes)
}

pub fn encrypt_padded(
    message: &[u8],
    recipient_pub_key: &PubKey,
    padded_length: usize,
) -> Result<Vec<u8>> {
    if padded_length < message.len() + 4 {
        return Err(Error::InvalidPaddedLength {
            found: padded_length,
            expected: message.len() + 4,
        });
    }
    // prepend with the message length info in little endian (4 bytes)
    let mut padded_message = (message.len() as u32).to_le_bytes().to_vec();
    padded_message.extend(message);
    padded_message.resize(padded_length, 0u8);
    encrypt(&padded_message, recipient_pub_key)
}

pub fn decrypt_padded_unchecked(
    ciphertext_bytes: &[u8],
    recipient_priv_key: &PrivKey,
) -> Result<Vec<u8>> {
    let padded_message = decrypt(ciphertext_bytes, recipient_priv_key)?;
    _decode_padded(&padded_message)
}

pub fn decrypt_padded(
    ciphertext_bytes: &[u8],
    recipient_priv_key: &PrivKey,
    padded_length: usize,
) -> Result<Vec<u8>> {
    let padded_message = decrypt(ciphertext_bytes, recipient_priv_key)?;
    if padded_message.len() != padded_length {
        return Err(Error::InvalidPaddedLength {
            found: padded_message.len(),
            expected: padded_length,
        });
    }
    _decode_padded(&padded_message)
}

fn _decode_padded(padded_message: &[u8]) -> Result<Vec<u8>> {
    // decode the original message length
    let message_length = u32::from_le_bytes(
        padded_message
            .get(..4)
            .ok_or(Error::InvalidPaddedLength {
                found: padded_message.len(),
                expected: 4,
            })?
            .try_into()
            .map_err(|_| Error::Decoding("Message length".to_string()))?,
    ) as usize;
    // extract the original message
    padded_message
        .get(4..(message_length + 4))
        .ok_or(Error::InvalidMessageLength {
            found: message_length,
            expected: padded_message.len() - 4,
        })
        .map(|m| m.to_vec())
}
