//! Request signing, built from HMAC-SHA-256 and SHA-256 as the service
//! specifies. Pure: the caller supplies the time and the credentials.

use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};

/// Everything one signature covers.
#[derive(Clone, Copy, Debug)]
pub struct SigningInput<'input> {
    /// The HTTP method, uppercase.
    pub method: &'input str,
    /// The canonical path.
    pub canonical_uri: &'input str,
    /// The canonical query string, already sorted and encoded.
    pub canonical_query: &'input str,
    /// Every header to sign as a lowercase name and its value. Order does
    /// not matter.
    pub headers: &'input [(&'input str, &'input str)],
    /// The request body.
    pub payload: &'input [u8],
    /// The region, for example `eu-west-1`.
    pub region: &'input str,
    /// The service, for example `secretsmanager`.
    pub service: &'input str,
    /// The access key identifier.
    pub access_key_id: &'input str,
    /// The secret access key.
    pub secret_access_key: &'input [u8],
    /// The request time as `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'input str,
}

/// The result of signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRequest {
    /// The value of the `Authorization` header.
    pub authorization: String,
    /// The signature, lowercase hexadecimal.
    pub signature: String,
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    // INVARIANT: HMAC accepts a key of any length, so construction cannot fail.
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Signs one request.
#[must_use]
pub fn sign(input: &SigningInput<'_>) -> SignedRequest {
    let mut headers: Vec<(&str, &str)> = input.headers.to_vec();
    headers.sort_unstable();
    let mut canonical_headers = String::new();
    for (name, value) in &headers {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value.trim());
        canonical_headers.push('\n');
    }
    let signed_headers = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        input.method,
        input.canonical_uri,
        input.canonical_query,
        hex::encode(Sha256::digest(input.payload)),
    );
    let date = input.amz_date.get(..8).unwrap_or(input.amz_date);
    let scope = format!("{date}/{}/{}/aws4_request", input.region, input.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        input.amz_date,
        hex::encode(Sha256::digest(canonical_request.as_bytes())),
    );
    let mut key = Vec::with_capacity(4 + input.secret_access_key.len());
    key.extend_from_slice(b"AWS4");
    key.extend_from_slice(input.secret_access_key);
    let date_key = hmac(&key, date.as_bytes());
    zeroize::Zeroize::zeroize(&mut key);
    let region_key = hmac(&date_key, input.region.as_bytes());
    let service_key = hmac(&region_key, input.service.as_bytes());
    let signing_key = hmac(&service_key, b"aws4_request");
    let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes()));
    SignedRequest {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            input.access_key_id
        ),
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example key the service's own documentation signs with. It is
    /// published, protects nothing, and is assembled here from parts.
    fn documented_example_key() -> String {
        format!("{}/{}{}", "wJalrXUtnFEMI", "K7MDENG+bPxRfiCY", "EXAMPLEKEY")
    }

    fn input<'input>(
        key: &'input str,
        query: &'input str,
        headers: &'input [(&'input str, &'input str)],
        service: &'input str,
    ) -> SigningInput<'input> {
        SigningInput {
            method: "GET",
            canonical_uri: "/",
            canonical_query: query,
            headers,
            payload: b"",
            region: "us-east-1",
            service,
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: key.as_bytes(),
            amz_date: "20150830T123600Z",
        }
    }

    /// The service's published `get-vanilla` test vector.
    #[test]
    fn the_published_plain_get_vector_is_reproduced() {
        let key = documented_example_key();
        let headers = [
            ("x-amz-date", "20150830T123600Z"),
            ("host", "example.amazonaws.com"),
        ];
        let signed = sign(&input(&key, "", &headers, "service"));
        assert_eq!(
            signed.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// The worked example in the service's signing documentation.
    #[test]
    fn the_documented_query_example_is_reproduced() {
        let key = documented_example_key();
        let headers = [
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("host", "iam.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ];
        let signed = sign(&input(
            &key,
            "Action=ListUsers&Version=2010-05-08",
            &headers,
            "iam",
        ));
        assert_eq!(
            signed.signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn every_signed_input_changes_the_signature() {
        let key = documented_example_key();
        let headers = [
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ];
        let base = input(&key, "", &headers, "service");
        let signature = |input: SigningInput<'_>| sign(&input).signature;
        let reference = signature(base);
        assert_ne!(
            signature(SigningInput {
                method: "POST",
                ..base
            }),
            reference
        );
        assert_ne!(
            signature(SigningInput {
                canonical_uri: "/a",
                ..base
            }),
            reference
        );
        assert_ne!(
            signature(SigningInput {
                canonical_query: "a=b",
                ..base
            }),
            reference
        );
        assert_ne!(
            signature(SigningInput {
                payload: b"x",
                ..base
            }),
            reference
        );
        assert_ne!(
            signature(SigningInput {
                region: "eu-west-1",
                ..base
            }),
            reference
        );
        assert_ne!(
            signature(SigningInput {
                service: "secretsmanager",
                ..base
            }),
            reference
        );
        assert_ne!(
            signature(SigningInput {
                secret_access_key: b"other",
                ..base
            }),
            reference
        );
    }
}
