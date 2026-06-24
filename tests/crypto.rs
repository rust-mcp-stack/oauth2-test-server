#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine};
    use oauth2_test_server::crypto::{calculate_at_hash, calculate_c_hash, issue_id_token, Keys};
    use oauth2_test_server::models::IdTokenClaims;

    #[test]
    fn test_at_hash_calculation() {
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let at_hash = calculate_at_hash(access_token);
        assert!(!at_hash.is_empty());
        assert_eq!(
            general_purpose::URL_SAFE_NO_PAD
                .decode(&at_hash)
                .unwrap()
                .len(),
            16
        );
    }

    #[test]
    fn test_c_hash_calculation() {
        let code = "test-authorization-code";
        let c_hash = calculate_c_hash(code);
        assert!(!c_hash.is_empty());
        assert_eq!(
            general_purpose::URL_SAFE_NO_PAD
                .decode(&c_hash)
                .unwrap()
                .len(),
            16
        );
    }

    #[test]
    fn test_issue_id_token() {
        let keys = Keys::generate();
        let issuer = "http://localhost:8090";
        let client_id = "test-client-id";
        let user_id = "test-user-id";

        let id_token = issue_id_token(
            issuer,
            client_id,
            user_id,
            Some("test-nonce"),
            Some("at_hash_value"),
            Some("c_hash_value"),
            3600,
            serde_json::json!({"name": "Test User", "email": "test@example.com"}),
            &keys,
        )
        .unwrap();

        assert!(!id_token.is_empty());
        assert_eq!(id_token.split('.').count(), 3);

        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.iss, issuer);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.aud, client_id);
        assert_eq!(claims.nonce, Some("test-nonce".to_string()));
        assert_eq!(claims.at_hash, Some("at_hash_value".to_string()));
        assert_eq!(claims.c_hash, Some("c_hash_value".to_string()));
    }

    #[test]
    fn test_id_token_without_optional_claims() {
        let keys = Keys::generate();
        let issuer = "http://localhost:8090";
        let client_id = "test-client-id";
        let user_id = "test-user-id";

        let id_token = issue_id_token(
            issuer,
            client_id,
            user_id,
            None,
            None,
            None,
            3600,
            serde_json::json!({}),
            &keys,
        )
        .unwrap();

        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.iss, issuer);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.aud, client_id);
        assert_eq!(claims.nonce, None);
        assert_eq!(claims.at_hash, None);
        assert_eq!(claims.c_hash, None);
        assert_eq!(claims.typ, Some("IDToken".to_string()));
    }

    #[test]
    fn test_id_token_omits_nonce_key_when_not_provided() {
        let keys = Keys::generate();

        let id_token = issue_id_token(
            "http://localhost:8090",
            "test-client-id",
            "test-user-id",
            None,
            None,
            None,
            3600,
            serde_json::json!({}),
            &keys,
        )
        .unwrap();

        let parts: Vec<&str> = id_token.split('.').collect();
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_str = String::from_utf8(payload_bytes).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_str).unwrap();

        assert!(
            !payload_str.contains("\"nonce\""),
            "nonce key should be absent, got: {payload_str}"
        );
        assert!(
            !payload_str.contains("\"at_hash\""),
            "at_hash key should be absent, got: {payload_str}"
        );
        assert!(
            !payload_str.contains("\"c_hash\""),
            "c_hash key should be absent, got: {payload_str}"
        );
        assert!(payload.get("nonce").is_none());
        assert!(payload.get("at_hash").is_none());
        assert!(payload.get("c_hash").is_none());
    }

    #[test]
    fn test_id_token_includes_nonce_key_when_provided() {
        let keys = Keys::generate();

        let id_token = issue_id_token(
            "http://localhost:8090",
            "test-client-id",
            "test-user-id",
            Some("test-nonce"),
            Some("at_hash_value"),
            Some("c_hash_value"),
            3600,
            serde_json::json!({}),
            &keys,
        )
        .unwrap();

        let parts: Vec<&str> = id_token.split('.').collect();
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_str = String::from_utf8(payload_bytes).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_str).unwrap();

        assert!(
            payload_str.contains("\"nonce\""),
            "nonce key should be present"
        );
        assert!(
            payload_str.contains("\"at_hash\""),
            "at_hash key should be present"
        );
        assert!(
            payload_str.contains("\"c_hash\""),
            "c_hash key should be present"
        );
        assert_eq!(payload["nonce"], "test-nonce");
        assert_eq!(payload["at_hash"], "at_hash_value");
        assert_eq!(payload["c_hash"], "c_hash_value");
    }
}
