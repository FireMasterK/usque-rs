use anyhow::{Context, Result};
use p256::ecdsa::SigningKey;
use pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;

pub fn generate_self_signed_cert(signing_key: &SigningKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_der = signing_key
        .to_pkcs8_der()
        .context("failed to marshal private key")?;
    let key_der = PrivatePkcs8KeyDer::from(key_der.as_bytes().to_vec());
    let key_pair =
        KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &PKCS_ECDSA_P256_SHA256)
        .context("failed to build key pair")?;

    let mut params = CertificateParams::new(vec![]).context("failed to create cert params")?;
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2030, 1, 1);

    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate certificate")?;
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    Ok((cert_der, key_der))
}
