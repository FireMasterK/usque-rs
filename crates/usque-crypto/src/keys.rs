use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use p256::PublicKey;
use p256::SecretKey;
use pem::parse;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

pub fn generate_ec_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let signing_key = SigningKey::generate();
    let private_der = signing_key
        .to_pkcs8_der()
        .context("failed to marshal private key")?
        .as_bytes()
        .to_vec();
    let public_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .context("failed to marshal public key")?
        .to_vec();
    Ok((private_der, public_der))
}

pub fn decode_private_key(b64: &str) -> Result<SigningKey> {
    let der = STANDARD
        .decode(b64.trim())
        .context("failed to decode private key")?;
    if let Ok(key) = SigningKey::from_pkcs8_der(&der) {
        return Ok(key);
    }

    // Go configs sometimes store SEC1 EC private keys instead of PKCS#8.
    let secret = SecretKey::from_sec1_der(&der).context("failed to parse private key")?;
    Ok(SigningKey::from(secret))
}

pub fn encode_private_key(signing_key: &SigningKey) -> Result<String> {
    let der = signing_key
        .to_pkcs8_der()
        .context("failed to marshal private key")?;
    Ok(STANDARD.encode(der.as_bytes()))
}

pub fn decode_endpoint_public_key(pem_str: &str) -> Result<PublicKey> {
    let pem = parse(pem_str).context("failed to decode endpoint public key")?;
    if pem.tag() != "PUBLIC KEY" {
        bail!("expected PUBLIC KEY PEM block");
    }
    PublicKey::from_public_key_der(pem.contents()).context("failed to parse endpoint public key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let (priv_der, pub_der) = generate_ec_keypair().unwrap();
        assert!(!priv_der.is_empty());
        assert!(!pub_der.is_empty());

        let encoded = STANDARD.encode(&priv_der);
        let decoded = decode_private_key(&encoded).unwrap();
        let reencoded = encode_private_key(&decoded).unwrap();
        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn endpoint_public_key_from_pem() {
        let (_, pub_der) = generate_ec_keypair().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(&pub_der)
        );
        decode_endpoint_public_key(&pem).unwrap();
    }
}
