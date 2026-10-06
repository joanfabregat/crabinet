//! Throwaway certificate authorities and a minimal HTTPS server for tests of
//! `auth.oidc.ca_file`. Every key is generated in memory for one test run;
//! none is written to the repository.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509Builder, X509Name, X509NameBuilder, X509NameRef,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};

pub(crate) struct Authority {
    certificate: X509,
    key: PKey<Private>,
}

pub(crate) struct Leaf {
    certificate: X509,
    key: PKey<Private>,
}

fn new_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn name(common_name: &str) -> X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    name.build()
}

fn builder(subject: &X509NameRef, issuer: &X509NameRef, key: &PKey<Private>) -> X509Builder {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = i64::try_from(now).unwrap();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(subject).unwrap();
    builder.set_issuer_name(issuer).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(now - 3_600).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(now + 86_400).unwrap())
        .unwrap();
    builder
}

impl Authority {
    pub(crate) fn new(common_name: &str) -> Self {
        let key = new_key();
        let subject = name(common_name);
        let mut builder = builder(&subject, &subject, &key);
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let identifier = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(identifier).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        Self {
            certificate: builder.build(),
            key,
        }
    }

    pub(crate) fn pem(&self) -> Vec<u8> {
        self.certificate.to_pem().unwrap()
    }

    pub(crate) fn der(&self) -> Vec<u8> {
        self.certificate.to_der().unwrap()
    }

    /// A server certificate for the given IP addresses and DNS names.
    pub(crate) fn issue(&self, addresses: &[IpAddr], names: &[&str]) -> Leaf {
        let key = new_key();
        let mut builder = builder(&name("test server"), self.certificate.subject_name(), &key);
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder
            .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let mut alternative = SubjectAlternativeName::new();
        for address in addresses {
            alternative.ip(&address.to_string());
        }
        for name in names {
            alternative.dns(name);
        }
        let alternative = alternative
            .build(&builder.x509v3_context(Some(&self.certificate), None))
            .unwrap();
        builder.append_extension(alternative).unwrap();
        let authority_key = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(&self.certificate), None))
            .unwrap();
        builder.append_extension(authority_key).unwrap();
        builder.sign(&self.key, MessageDigest::sha256()).unwrap();
        Leaf {
            certificate: builder.build(),
            key,
        }
    }
}

/// A private key in PKCS #8 PEM, generated for the test that asks for it.
pub(crate) fn private_key_pem() -> Vec<u8> {
    new_key().private_key_to_pem_pkcs8().unwrap()
}

/// A public key in PEM, a block that is not a certificate.
pub(crate) fn public_key_pem() -> Vec<u8> {
    new_key().public_key_to_pem().unwrap()
}

/// Serves HTTPS on 127.0.0.1 with `leaf`, answering every GET with the JSON
/// that `respond` returns for its path (`404` for `None`), one request per
/// connection. Handshakes the client refuses are ignored.
pub(crate) fn serve_https(
    leaf: Leaf,
    respond: impl Fn(SocketAddr, &str) -> Option<String> + Send + Sync + 'static,
) -> SocketAddr {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_private_key(&leaf.key).unwrap();
    acceptor.set_certificate(&leaf.certificate).unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(mut stream) = acceptor.accept(stream) else {
                continue;
            };
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let head = String::from_utf8_lossy(&head);
            let path = head.split(' ').nth(1).unwrap_or("/");
            let (status, body) = match respond(address, path) {
                Some(body) => ("200 OK", body),
                None => ("404 Not Found", "{}".to_owned()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown();
        }
    });
    address
}
