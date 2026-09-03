/**
 * @file tests/unit/test_direct_auth.cpp
 * @brief Unit tests for the Vibe Direct Auth v1 host state machine.
 */
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/x509.h>

#include "src/direct_auth.h"
#include "src/crypto.h"

namespace direct_auth {

  namespace {
    constexpr std::string_view kHostFp = "sha256/ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
    constexpr std::string_view kClientFp = "sha256/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8";
    constexpr std::string_view kOtherFp = "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    constexpr std::string_view kSpkiFixture = R"PEM(-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA+MSYwJAYDVQQDDB1WaWJl
IERpcmVjdCBBdXRoIFRlc3QgRml4dHVyZTEUMBIGA1UECgwLT3BlbkFJIFRlc3Qw
HhcNMjYwOTAyMTYzODU5WhcNMzYwODMwMTYzODU5WjA+MSYwJAYDVQQDDB1WaWJl
IERpcmVjdCBBdXRoIFRlc3QgRml4dHVyZTEUMBIGA1UECgwLT3BlbkFJIFRlc3Qw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDXwzNQaj9WhwJkrckr1xR
wCpl28yn5EMzc8v86Qui950zW/Wy6eAqHvwgUC+yb3Wn8l5ZED/JbQ+9Iw7ram3S
+Xwub6tMPcTZPGv2pNtFFh/4s3fvLMEWqdmh6KdJCzdK5zXWmdr2cwfnKk+/7ovU
nb147wjhZFnq9Ir6ZSXhq9Qg3IRP0SL33dyV7rLnvNuWOztJwklRQU9RNeH0sDT7
AmXHsYJrlWmQLVSA8bcL9OldbCM5uvPLCwyyl3iHFzscnNgvRy2AbqGKE11Sn6DI
2CBNZtMNQC8iQmnV2kAxvTFfmpXDRvIbXSZRu2chliQ2Mr5uKbB2ZQxKSfGQ7xHN
AgMBAAGjUzBRMB0GA1UdDgQWBBSsQYW5YfEgZ4aaGGn3XlgIZ5V0ezAfBgNVHSME
GDAWgBSsQYW5YfEgZ4aaGGn3XlgIZ5V0ezAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA4IBAQCsfWG2RqgVClhsBgpp3F3fTmUNfqhMLpwklOMeFXloT/fe
u3tQ4dgLkjuGsAyRAlvko+ASn70qwitqGGwEgwbUuzB8n0wnulo/S4rDTzCILOUi
Lk0au6PCHEkwrVoa7eqniQ8VGeCYhlE2loNWl885E+K2j7BTHUi0nrX1X+MB2kR8
QWHmOp5W2K0oth1k5q58w0XOadMr6z4Infd3fE6hcQ0u4RNlMOME7Oy+WkzeRhrm
81g4JjaItcxBDJORrOK2D6I5Purn1MRrhG7XvDpsWZaLHGeq8t/Sk38iWsAcGkzs
dh3vK0Qq77Zu9jum0Obe80Zl6S+LO+i5630HwKB7
-----END CERTIFICATE-----
)PEM";

    std::string raw_secret_from_setup_uri(const EnrollmentInfo &info) {
      const auto secret_pos = info.setup_uri.find("secret=");
      if (secret_pos == std::string::npos) return {};
      const auto start = secret_pos + 7;
      const auto end = info.setup_uri.find('&', start);
      const auto encoded = info.setup_uri.substr(start, end == std::string::npos ? std::string::npos : end - start);
      std::string decoded;
      if (!DirectAuthManager::base64url_decode(encoded, decoded)) return {};
      return decoded;
    }
    std::string sample_cert() {
      const auto creds = crypto::gen_creds("direct-auth-test", 2048);
      return creds.x509;
    }

    std::string issue_cert_with_existing_key(const std::string &pkey_pem, long serial, const char *cn) {
      auto key = crypto::pkey(pkey_pem);
      if (!key) return {};
      crypto::x509_t cert {X509_new()};
      if (!cert) return {};
      X509_set_version(cert.get(), 2);
      ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
      X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
      X509_gmtime_adj(X509_get_notAfter(cert.get()), 60L * 60L * 24L * 365L);
      if (X509_set_pubkey(cert.get(), key.get()) != 1) return {};
      auto *name = X509_get_subject_name(cert.get());
      if (!name || X509_NAME_add_entry_by_txt(
                     name, "CN", MBSTRING_ASC,
                     reinterpret_cast<const unsigned char *>(cn), -1, -1, 0) != 1) {
        return {};
      }
      if (X509_set_issuer_name(cert.get(), name) != 1 || X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
        return {};
      }
      return crypto::pem(cert);
    }

    class DirectAuthTest: public ::testing::Test {
    protected:
      void SetUp() override {
        cert = sample_cert();
        trusted_certs.push_back(cert);
      }

      bool is_trusted(const std::string &pem) const {
        return pem == cert;
      }

      std::string cert;
      std::vector<std::string> trusted_certs;
    };
  }  // namespace

  TEST_F(DirectAuthTest, Base64UrlRoundTrip) {
    const std::string bytes { "\x00\x01\x02\x03\xfb\xfc\xfd\xfe", 8 };
    const auto encoded = DirectAuthManager::base64url_encode(bytes);
    EXPECT_EQ(encoded, "AAECA_v8_f4");
    std::string decoded;
    EXPECT_TRUE(DirectAuthManager::base64url_decode(encoded, decoded));
    EXPECT_EQ(decoded, bytes);
  }

  TEST_F(DirectAuthTest, Base64UrlRejectsMalformed) {
    std::string decoded;
    EXPECT_FALSE(DirectAuthManager::base64url_decode("a", decoded));
    EXPECT_FALSE(DirectAuthManager::base64url_decode("ab+", decoded));
    EXPECT_FALSE(DirectAuthManager::base64url_decode("YQ==", decoded));
    EXPECT_FALSE(DirectAuthManager::base64url_decode("YQ=", decoded));
    EXPECT_TRUE(DirectAuthManager::base64url_decode("", decoded));
  }

  TEST_F(DirectAuthTest, SharedRawSecretHmacVector) {
    std::string raw_secret;
    ASSERT_TRUE(DirectAuthManager::base64url_decode(
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", raw_secret));
    ASSERT_EQ(raw_secret.size(), 32u);
    const auto input = DirectAuthManager::enrollment_proof_input(
      "AAECAwQFBgcICQoLDA0ODw", kHostFp, kClientFp);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(raw_secret, input);
    EXPECT_EQ(proof, "awwBc9c00_rpQnt1xbwwANc60VXIldr84rRH3-gx0Pg");
    EXPECT_NE(proof, "ZZpUGm1z5MWJP1cj-6GvS_tEVIClsbYbMgjcV_pjxeU");
    EXPECT_EQ(
      DirectAuthManager::hmac_sha256_base64url(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", input),
      "ZZpUGm1z5MWJP1cj-6GvS_tEVIClsbYbMgjcV_pjxeU"
    );
  }

  TEST_F(DirectAuthTest, SharedSpkiFixtureMatchesExactly) {
    auto parsed = crypto::x509(kSpkiFixture);
    ASSERT_TRUE(parsed);
    EXPECT_EQ(
      crypto::spki_sha256_fingerprint(parsed),
      "sha256/mSTKPdEqr64GqgPRl1ciSp1PNT9onQrKfM40tSOALIM"
    );
  }

  TEST_F(DirectAuthTest, CanonicalTokenLengthValidation) {
    EXPECT_TRUE(DirectAuthManager::valid_enrollment_id_format("AAECAwQFBgcICQoLDA0ODw"));
    EXPECT_FALSE(DirectAuthManager::valid_enrollment_id_format("AAECAwQFBgcICQoLDA0O"));
    EXPECT_FALSE(DirectAuthManager::valid_enrollment_id_format("AAECAwQFBgcICQoLDA0ODw=="));
    EXPECT_TRUE(DirectAuthManager::valid_proof_format("awwBc9c00_rpQnt1xbwwANc60VXIldr84rRH3-gx0Pg"));
    EXPECT_FALSE(DirectAuthManager::valid_proof_format("AAECAwQFBgcICQoLDA0ODw"));
  }

  TEST_F(DirectAuthTest, EnrollmentRequestParserRequiresIntegerProtocolOne) {
    EnrollmentRequestFields fields;
    std::string error;

    EXPECT_FALSE(parse_enrollment_request_body(R"({"enrollment_id":"e","client_fingerprint":"f","client_name":"n","client_uuid":"u","proof":"p"})", fields, error));
    EXPECT_EQ(error, "MALFORMED");

    EXPECT_FALSE(parse_enrollment_request_body(R"({"protocol":"1","enrollment_id":"e","client_fingerprint":"f","client_name":"n","client_uuid":"u","proof":"p"})", fields, error));
    EXPECT_EQ(error, "MALFORMED");

    EXPECT_FALSE(parse_enrollment_request_body(R"({"protocol":null,"enrollment_id":"e","client_fingerprint":"f","client_name":"n","client_uuid":"u","proof":"p"})", fields, error));
    EXPECT_EQ(error, "MALFORMED");

    EXPECT_FALSE(parse_enrollment_request_body(R"({"protocol":2,"enrollment_id":"e","client_fingerprint":"f","client_name":"n","client_uuid":"u","proof":"p"})", fields, error));
    EXPECT_EQ(error, "UNSUPPORTED_VERSION");
  }

  TEST_F(DirectAuthTest, EnrollmentRequestParserRejectsWrongTypesForEveryRequiredString) {
    const std::array<const char *, 5> field_names {
      "enrollment_id", "client_fingerprint", "client_name", "client_uuid", "proof"
    };
    const std::array<nlohmann::json, 5> invalid_values {
      nlohmann::json(nullptr), nlohmann::json(12), nlohmann::json(true),
      nlohmann::json::array(), nlohmann::json::object()
    };

    for (const auto *field_name : field_names) {
      for (const auto &invalid_value : invalid_values) {
        nlohmann::json body = {
          {"protocol", 1},
          {"enrollment_id", "eid"},
          {"client_fingerprint", "fingerprint"},
          {"client_name", "client"},
          {"client_uuid", "uuid"},
          {"proof", "proof"},
        };
        body[field_name] = invalid_value;
        EnrollmentRequestFields fields;
        std::string error;
        EXPECT_FALSE(parse_enrollment_request_body(body.dump(), fields, error))
          << "field=" << field_name << " value=" << invalid_value.dump();
        EXPECT_EQ(error, "MALFORMED")
          << "field=" << field_name << " value=" << invalid_value.dump();
      }
    }
  }

  TEST_F(DirectAuthTest, EnrollmentRequestParserAcceptsValidBodyAndEnforcesBodyLimit) {
    EnrollmentRequestFields fields;
    std::string error;
    const auto valid = nlohmann::json {
      {"protocol", 1},
      {"enrollment_id", "eid"},
      {"client_fingerprint", "fingerprint"},
      {"client_name", "client"},
      {"client_uuid", "metadata-uuid"},
      {"proof", "proof"},
    }.dump();
    ASSERT_TRUE(parse_enrollment_request_body(valid, fields, error)) << error;
    EXPECT_EQ(fields.enrollment_id, "eid");
    EXPECT_EQ(fields.client_fingerprint, "fingerprint");
    EXPECT_EQ(fields.client_name, "client");
    EXPECT_EQ(fields.client_uuid, "metadata-uuid");
    EXPECT_EQ(fields.proof, "proof");

    const std::string oversized(MAX_BODY_BYTES + 1, 'x');
    EXPECT_FALSE(parse_enrollment_request_body(oversized, fields, error));
    EXPECT_EQ(error, "BODY_TOO_LARGE");
  }

  TEST_F(DirectAuthTest, ValidParsedEnrollmentBodyReachesManager) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    const auto body = nlohmann::json {
      {"protocol", 1},
      {"enrollment_id", open.enrollment_id},
      {"client_fingerprint", std::string(kClientFp)},
      {"client_name", "Parsed Client"},
      {"client_uuid", "client-metadata-only"},
      {"proof", proof},
    }.dump();

    EnrollmentRequestFields fields;
    std::string parse_error;
    ASSERT_TRUE(parse_enrollment_request_body(body, fields, parse_error)) << parse_error;
    std::string pending_id;
    std::string manager_error;
    EXPECT_TRUE(manager.submit_enrollment_request(
      fields.enrollment_id,
      fields.client_fingerprint,
      fields.client_name,
      fields.client_uuid,
      fields.proof,
      std::string(kClientFp),
      cert,
      "127.0.0.1",
      &pending_id,
      &manager_error
    )) << manager_error;
    EXPECT_FALSE(pending_id.empty());
  }

  TEST_F(DirectAuthTest, PendingIdQueryRequiresExactlyOneCanonicalGeneratedToken) {
    const std::string canonical = "AAECAwQFBgcICQoLDA0ODw";
    EXPECT_TRUE(DirectAuthManager::valid_pending_id_format(canonical));
    EXPECT_FALSE(DirectAuthManager::valid_pending_id_format("AAECAwQFBgcICQoLDA0O"));
    EXPECT_FALSE(DirectAuthManager::valid_pending_id_format(canonical + "=="));

    std::string parsed;
    EXPECT_FALSE(parse_pending_id_query_values({}, parsed));
    EXPECT_FALSE(parse_pending_id_query_values({canonical, canonical}, parsed));
    EXPECT_FALSE(parse_pending_id_query_values({"not-base64url"}, parsed));
    EXPECT_TRUE(parse_pending_id_query_values({canonical}, parsed));
    EXPECT_EQ(parsed, canonical);
  }

  TEST_F(DirectAuthTest, SetupHostAcceptsOnlyAddressOrHostname) {
    EXPECT_TRUE(valid_setup_host("192.168.1.20"));
    EXPECT_TRUE(valid_setup_host("fd00::1234"));
    EXPECT_TRUE(valid_setup_host("gaming-pc"));
    EXPECT_TRUE(valid_setup_host("host.example.test"));

    EXPECT_FALSE(valid_setup_host(""));
    EXPECT_FALSE(valid_setup_host("https://192.168.1.20"));
    EXPECT_FALSE(valid_setup_host("192.168.1.20:47990"));
    EXPECT_FALSE(valid_setup_host("host/path"));
    EXPECT_FALSE(valid_setup_host("host?query=x"));
    EXPECT_FALSE(valid_setup_host("host#fragment"));
    EXPECT_FALSE(valid_setup_host(" host"));
    EXPECT_FALSE(valid_setup_host("host "));
    EXPECT_FALSE(valid_setup_host("bad..host"));
    EXPECT_FALSE(valid_setup_host("-bad.example"));
    EXPECT_FALSE(valid_setup_host("bad-.example"));
    EXPECT_FALSE(valid_setup_host(std::string("bad\nname")));
  }

  TEST_F(DirectAuthTest, EnrollmentIdRandomFailureLeavesEnrollmentClosed) {
    std::size_t calls = 0;
    DirectAuthManager manager([&](std::size_t, std::string &out) {
      ++calls;
      out.clear();
      return false;
    });

    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    EXPECT_EQ(calls, 1u);
    EXPECT_EQ(open.state, EnrollmentState::Closed);
    EXPECT_TRUE(open.enrollment_id.empty());
    EXPECT_TRUE(open.setup_uri.empty());
    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Closed);
  }

  TEST_F(DirectAuthTest, EnrollmentSecretRandomFailureLeavesEnrollmentClosed) {
    std::size_t calls = 0;
    DirectAuthManager manager([&](std::size_t bytes, std::string &out) {
      ++calls;
      if (calls == 2) {
        out.clear();
        return false;
      }
      out.assign(bytes, '\x11');
      return true;
    });

    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    EXPECT_EQ(calls, 2u);
    EXPECT_EQ(open.state, EnrollmentState::Closed);
    EXPECT_TRUE(open.enrollment_id.empty());
    EXPECT_TRUE(open.setup_uri.empty());
    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Closed);
  }

  TEST_F(DirectAuthTest, PendingIdRandomFailureDoesNotConsumeEnrollment) {
    std::size_t calls = 0;
    DirectAuthManager manager([&](std::size_t bytes, std::string &out) {
      ++calls;
      if (calls == 3) {
        out.clear();
        return false;
      }
      out.assign(bytes, static_cast<char>(0x20 + calls));
      return true;
    });

    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    ASSERT_EQ(open.state, EnrollmentState::Open);
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));

    std::string pending_id;
    std::string error;
    EXPECT_FALSE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error));
    EXPECT_EQ(error, "INTERNAL_ERROR");
    EXPECT_TRUE(pending_id.empty());
    EXPECT_TRUE(manager.pending_candidates().empty());
    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Open);

    error.clear();
    EXPECT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error)) << error;
    EXPECT_FALSE(pending_id.empty());
  }

  TEST_F(DirectAuthTest, CheckedRandomProviderUsesExactTokenSizes) {
    std::vector<std::size_t> requested_sizes;
    std::size_t calls = 0;
    DirectAuthManager manager([&](std::size_t bytes, std::string &out) {
      requested_sizes.push_back(bytes);
      ++calls;
      out.assign(bytes, static_cast<char>(0x30 + calls));
      return true;
    });

    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    ASSERT_EQ(open.state, EnrollmentState::Open);
    std::string enrollment_id_bytes;
    ASSERT_TRUE(DirectAuthManager::base64url_decode(open.enrollment_id, enrollment_id_bytes));
    EXPECT_EQ(enrollment_id_bytes.size(), 16u);
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    std::string error;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error)) << error;
    std::string pending_id_bytes;
    ASSERT_TRUE(DirectAuthManager::base64url_decode(pending_id, pending_id_bytes));
    EXPECT_EQ(pending_id_bytes.size(), 16u);
    EXPECT_EQ(requested_sizes, (std::vector<std::size_t> {16u, 32u, 16u}));
  }

  TEST_F(DirectAuthTest, SpkiFingerprintFormat) {
    crypto::x509_t parsed = crypto::x509(cert);
    ASSERT_TRUE(parsed);
    const auto fp = crypto::spki_sha256_fingerprint(parsed.get());
    EXPECT_EQ(fp.substr(0, 7), "sha256/");
    EXPECT_EQ(fp.size(), 7 + 43);
    EXPECT_TRUE(DirectAuthManager::valid_fingerprint_format(fp));
  }

  TEST_F(DirectAuthTest, EnrollmentProofInputExactBytes) {
    const auto input = DirectAuthManager::enrollment_proof_input("eid123", "hostfp", "clientfp");
    EXPECT_EQ(input, "vibe-direct-enroll-v1\neid123\nhostfp\nclientfp");
  }

  TEST_F(DirectAuthTest, ClosedByDefaultAndNoPendingCreated) {
    DirectAuthManager manager;
    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Closed);

    std::string pending_id;
    std::string error;
    const bool ok = manager.submit_enrollment_request(
      "eid", std::string(kClientFp), "Client", "uuid", "proof",
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error
    );
    EXPECT_FALSE(ok);
    EXPECT_EQ(error, "ENROLLMENT_CLOSED");
    EXPECT_TRUE(manager.pending_candidates().empty());
  }

  TEST_F(DirectAuthTest, ValidEnrollmentCreatesSinglePending) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    ASSERT_EQ(open.state, EnrollmentState::Open);
    ASSERT_FALSE(open.enrollment_id.empty());

    // Compute a valid proof using the setup URI secret. The manager API hides
    // the secret, so reconstruct from the setup URI (admin-visible only).
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);

    const auto proof_input = DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    );
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, proof_input);

    std::string pending_id;
    std::string error;
    const bool ok = manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "ThinkPad", "client-uuid", proof,
      std::string(kClientFp), cert, "192.168.1.20", &pending_id, &error
    );
    EXPECT_TRUE(ok) << error;
    EXPECT_FALSE(pending_id.empty());

    const auto pending = manager.pending_candidates();
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].name, "ThinkPad");
    EXPECT_EQ(pending[0].fingerprint, kClientFp);
  }

  TEST_F(DirectAuthTest, ReplayProofDoesNotCreateSecondPending) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof_input = DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    );
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, proof_input);

    std::string first_id;
    std::string first_error;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u1", proof,
      std::string(kClientFp), cert, "10.0.0.1", &first_id, &first_error
    ));

    // Replay consumes the same session; the second proof must not create a
    // second pending entry.
    const auto open_after = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret2 = raw_secret_from_setup_uri(open_after);
    ASSERT_EQ(secret2.size(), 32u);
    const auto proof2 = DirectAuthManager::hmac_sha256_base64url(secret2, DirectAuthManager::enrollment_proof_input(
      open_after.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    ));
    std::string second_id;
    std::string second_error;
    const bool ok = manager.submit_enrollment_request(
      open_after.enrollment_id, std::string(kClientFp), "A", "u1", proof2,
      std::string(kClientFp), cert, "10.0.0.1", &second_id, &second_error
    );
    EXPECT_FALSE(ok);
    EXPECT_EQ(second_error, "ENROLLMENT_PENDING");
    EXPECT_TRUE(second_id.empty());
  }

  TEST_F(DirectAuthTest, WrongProofRejectedNoPending) {
    DirectAuthManager manager;
    manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    std::string pending_id;
    std::string error;
    EXPECT_FALSE(manager.submit_enrollment_request(
      "bad-id", std::string(kClientFp), "A", "u", "bad-proof",
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error
    ));
    EXPECT_EQ(error, "ENROLLMENT_INVALID_PROOF");
    EXPECT_TRUE(manager.pending_candidates().empty());
  }

  TEST_F(DirectAuthTest, BodyFingerprintMismatchRejected) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof_input = DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    );
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, proof_input);

    std::string pending_id;
    std::string error;
    EXPECT_FALSE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kOtherFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error
    ));
    EXPECT_EQ(error, "ENROLLMENT_INVALID_PROOF");
    EXPECT_TRUE(manager.pending_candidates().empty());
  }

  TEST_F(DirectAuthTest, DenyWithoutPersistenceBlocksFingerprint) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof_input = DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    );
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, proof_input);

    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "10.0.0.2", &pending_id, nullptr
    ));

    // No persistence callback is supplied, so the manager itself records the
    // block/deny in its durable snapshot.
    ASSERT_TRUE(manager.deny_pending(pending_id, {}));

    EXPECT_EQ(manager.classify(std::string(kClientFp), cert, [&](const std::string &) { return false; }),
              DeviceTrustState::Blocked);
    ASSERT_EQ(manager.blocked_revoked().size(), 1u);
    EXPECT_EQ(manager.blocked_revoked()[0].reason, "denied");
  }

  TEST_F(DirectAuthTest, DenyWithPersistenceCallbackDelegatesBlocking) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof_input = DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    );
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, proof_input);

    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "10.0.0.2", &pending_id, nullptr
    ));

    std::string blocked_fingerprint;
    ASSERT_TRUE(manager.deny_pending(pending_id, [&](const std::string &fp) {
      blocked_fingerprint = fp;
    }));
    EXPECT_EQ(blocked_fingerprint, kClientFp);
    EXPECT_TRUE(manager.blocked_revoked().empty());
  }

  TEST_F(DirectAuthTest, BlockedFingerprintCannotEnrollAgain) {
    DirectAuthManager manager;
    manager.block_fingerprint(std::string(kClientFp));
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    ));

    std::string pending_id;
    std::string error;
    EXPECT_FALSE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, &error
    ));
    EXPECT_EQ(error, "DEVICE_BLOCKED");
  }

  TEST_F(DirectAuthTest, AcceptMarksPendingAndTrusts) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    ));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr
    ));

    bool accepted = false;
    ASSERT_TRUE(manager.accept_pending(pending_id, [&](const PendingInfo &info) {
      EXPECT_EQ(info.fingerprint, kClientFp);
      accepted = true;
      return true;
    }));
    EXPECT_TRUE(accepted);

    const auto status = manager.pending_status(pending_id, std::string(kClientFp));
    EXPECT_EQ(status.state, PendingState::Accepted);
    EXPECT_EQ(manager.classify(std::string(kClientFp), cert, [&](const std::string &fingerprint) { return fingerprint == kClientFp; }),
              DeviceTrustState::Trusted);
  }

  TEST_F(DirectAuthTest, ClientUuidCollisionCannotBecomeTrustedDeviceUuid) {
    auto victim = std::make_shared<crypto::named_cert_t>();
    victim->name = "Victim";
    victim->uuid = "victim-uuid";
    victim->perm = crypto::PERM::_all;
    std::vector<crypto::p_named_cert_t> devices {victim};

    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "Attacker", "victim-uuid", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr));

    std::array<std::string, 2> generated {"victim-uuid", "server-generated-b"};
    std::size_t generation_index = 0;
    crypto::p_named_cert_t accepted_device;
    ASSERT_TRUE(manager.accept_pending(pending_id, [&](const PendingInfo &info) {
      EXPECT_EQ(info.uuid, "victim-uuid");  // untrusted metadata remains metadata
      accepted_device = std::make_shared<crypto::named_cert_t>();
      accepted_device->name = info.name;
      accepted_device->uuid = generate_unique_named_device_uuid(devices, [&] {
        return generated.at(generation_index++);
      });
      accepted_device->perm = crypto::PERM::_default;
      devices.push_back(accepted_device);
      return !accepted_device->uuid.empty();
    }));

    ASSERT_TRUE(accepted_device);
    EXPECT_EQ(victim->uuid, "victim-uuid");
    EXPECT_EQ(accepted_device->uuid, "server-generated-b");
    EXPECT_NE(accepted_device->uuid, "victim-uuid");
    EXPECT_EQ(accepted_device->perm, crypto::PERM::_default);
    EXPECT_NE(accepted_device->perm, victim->perm);
    std::unordered_set<std::string> uuids;
    for (const auto &device : devices) {
      ASSERT_TRUE(device);
      EXPECT_TRUE(uuids.insert(device->uuid).second);
    }
  }

  TEST_F(DirectAuthTest, EmptyOrArbitraryClientUuidNeverControlsGeneratedUuid) {
    auto existing = std::make_shared<crypto::named_cert_t>();
    existing->uuid = "existing-uuid";
    std::vector<crypto::p_named_cert_t> devices {existing};

    for (const std::string client_uuid : {std::string {}, std::string {"arbitrary-client-value"}}) {
      PendingInfo info;
      info.uuid = client_uuid;
      const auto generated = generate_unique_named_device_uuid(devices, [] {
        return std::string("server-generated-uuid");
      });
      EXPECT_EQ(generated, "server-generated-uuid");
      EXPECT_NE(generated, info.uuid);
    }
  }

  TEST_F(DirectAuthTest, AcceptingSurvivesGenericExpiryUntilCallbackCompletes) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "client-uuid", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr));
    const auto pending = manager.pending_status(pending_id, std::string(kClientFp));
    ASSERT_EQ(pending.state, PendingState::Pending);

    std::promise<void> callback_started;
    auto callback_started_future = callback_started.get_future();
    std::promise<void> release_callback;
    auto release_callback_future = release_callback.get_future().share();
    std::atomic<bool> accept_result {false};

    std::thread accept_thread([&] {
      accept_result.store(manager.accept_pending(pending_id, [&](const PendingInfo &) {
        callback_started.set_value();
        release_callback_future.wait();
        return true;
      }));
    });

    callback_started_future.wait();
    manager.expire_stale(pending.expires_at_unix_ms + 1);
    EXPECT_EQ(manager.pending_status(pending_id, std::string(kClientFp)).state, PendingState::Accepting);

    release_callback.set_value();
    accept_thread.join();
    EXPECT_TRUE(accept_result.load());
    const auto accepted = manager.pending_status(pending_id, std::string(kClientFp));
    EXPECT_EQ(accepted.state, PendingState::Accepted);
    const auto now_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
    EXPECT_GT(accepted.expires_at_unix_ms, now_unix_ms);
  }

  TEST_F(DirectAuthTest, MultiEntryExpiryKeepsAcceptingAndCleansEveryOtherStaleEntry) {
    DirectAuthManager manager;
    std::vector<std::pair<std::string, std::string>> pendings;
    const auto make_pending = [&](const std::string &fingerprint, const std::string &name) {
      const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
      const auto secret = raw_secret_from_setup_uri(open);
      const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
        open.enrollment_id, kHostFp, fingerprint));
      std::string pending_id;
      std::string error;
      EXPECT_TRUE(manager.submit_enrollment_request(
        open.enrollment_id, fingerprint, name, "u", proof,
        fingerprint, cert, "127.0.0.1", &pending_id, &error)) << error;
      pendings.emplace_back(pending_id, fingerprint);
    };

    std::string third_digest(32, '\x03');
    const auto third_fp = "sha256/" + DirectAuthManager::base64url_encode(third_digest);
    make_pending(std::string(kClientFp), "A");
    make_pending(std::string(kOtherFp), "B");
    make_pending(third_fp, "C");
    ASSERT_EQ(pendings.size(), 3u);

    const auto accepting_before = manager.pending_status(pendings[0].first, pendings[0].second);
    const auto stale_b = manager.pending_status(pendings[1].first, pendings[1].second);
    const auto stale_c = manager.pending_status(pendings[2].first, pendings[2].second);
    const auto expire_at = std::max({accepting_before.expires_at_unix_ms, stale_b.expires_at_unix_ms, stale_c.expires_at_unix_ms}) + 1;

    std::promise<void> callback_started;
    auto callback_started_future = callback_started.get_future();
    std::promise<void> release_callback;
    auto release_callback_future = release_callback.get_future().share();
    std::atomic<bool> accept_result {false};
    std::thread accept_thread([&] {
      accept_result.store(manager.accept_pending(pendings[0].first, [&](const PendingInfo &) {
        callback_started.set_value();
        release_callback_future.wait();
        return true;
      }));
    });

    callback_started_future.wait();
    manager.expire_stale(expire_at);
    EXPECT_EQ(manager.pending_status(pendings[0].first, pendings[0].second).state, PendingState::Accepting);
    EXPECT_EQ(manager.pending_status(pendings[1].first, pendings[1].second).state, PendingState::Expired);
    EXPECT_EQ(manager.pending_status(pendings[2].first, pendings[2].second).state, PendingState::Expired);
    EXPECT_TRUE(manager.pending_candidates().empty());

    release_callback.set_value();
    accept_thread.join();
    EXPECT_TRUE(accept_result.load());
    EXPECT_EQ(manager.pending_status(pendings[0].first, pendings[0].second).state, PendingState::Accepted);
  }

  TEST_F(DirectAuthTest, PollingExpiredPendingReleasesFingerprintForReEnrollment) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr));
    const auto pending = manager.pending_status(pending_id, std::string(kClientFp));
    ASSERT_EQ(pending.state, PendingState::Pending);

    EXPECT_EQ(
      manager.pending_status(pending_id, std::string(kClientFp), pending.expires_at_unix_ms + 1).state,
      PendingState::Expired);

    const auto reopened = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret2 = raw_secret_from_setup_uri(reopened);
    const auto proof2 = DirectAuthManager::hmac_sha256_base64url(secret2, DirectAuthManager::enrollment_proof_input(
      reopened.enrollment_id, kHostFp, kClientFp));
    std::string second_pending_id;
    std::string error;
    EXPECT_TRUE(manager.submit_enrollment_request(
      reopened.enrollment_id, std::string(kClientFp), "A", "u", proof2,
      std::string(kClientFp), cert, "127.0.0.1", &second_pending_id, &error)) << error;
  }

  TEST_F(DirectAuthTest, BlockDuringAcceptingWinsAndCannotFinishAccepted) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr));

    std::promise<void> callback_started;
    auto callback_started_future = callback_started.get_future();
    std::promise<void> release_callback;
    auto release_callback_future = release_callback.get_future().share();
    std::atomic<bool> accept_result {true};
    std::thread accept_thread([&] {
      accept_result.store(manager.accept_pending(pending_id, [&](const PendingInfo &) {
        callback_started.set_value();
        release_callback_future.wait();
        return true;
      }));
    });

    callback_started_future.wait();
    manager.block_fingerprint(std::string(kClientFp), "denied");
    release_callback.set_value();
    accept_thread.join();

    EXPECT_FALSE(accept_result.load());
    EXPECT_EQ(manager.pending_status(pending_id, std::string(kClientFp)).state, PendingState::Denied);
    EXPECT_EQ(manager.classify(std::string(kClientFp), cert, [](const std::string &) { return true; }), DeviceTrustState::Blocked);
  }

  TEST_F(DirectAuthTest, FailedAcceptAfterOriginalExpiryDoesNotRemainAccepting) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "client-uuid", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr));
    const auto pending = manager.pending_status(pending_id, std::string(kClientFp));

    EXPECT_FALSE(manager.accept_pending(pending_id, [&](const PendingInfo &) {
      manager.expire_stale(pending.expires_at_unix_ms + 1);
      return false;
    }));
    EXPECT_EQ(manager.pending_status(pending_id, std::string(kClientFp)).state, PendingState::Expired);
  }

  TEST_F(DirectAuthTest, ThrowingAcceptCallbackIsContainedAndManagerRecovers) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "client-uuid", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr));

    const auto pending = manager.pending_status(pending_id, std::string(kClientFp));
    bool accepted = true;
    EXPECT_NO_THROW(accepted = manager.accept_pending(pending_id, [&](const PendingInfo &) -> bool {
      manager.expire_stale(pending.expires_at_unix_ms + 1);
      throw std::runtime_error("simulated persistence failure");
    }));
    EXPECT_FALSE(accepted);
    EXPECT_EQ(manager.pending_status(pending_id, std::string(kClientFp)).state, PendingState::Expired);
    EXPECT_EQ(manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp)).state, EnrollmentState::Open);
  }

  TEST_F(DirectAuthTest, RevokeOverridesTrustAndUnblockMakesUnknown) {
    DirectAuthManager manager;
    manager.revoke_fingerprint(std::string(kClientFp));
    EXPECT_EQ(manager.classify(std::string(kClientFp), cert, [&](const std::string &) { return true; }),
              DeviceTrustState::Revoked);
    manager.unblock_fingerprint(std::string(kClientFp));
    EXPECT_EQ(manager.classify(std::string(kClientFp), cert, [&](const std::string &) { return false; }),
              DeviceTrustState::Unknown);
  }

  TEST_F(DirectAuthTest, TrustDestructiveBlockRemovalMakesUnblockUnknown) {
    const auto parsed = crypto::x509(cert);
    ASSERT_TRUE(parsed);
    const auto fingerprint = crypto::spki_sha256_fingerprint(parsed);
    auto trusted = std::make_shared<crypto::named_cert_t>();
    trusted->uuid = "trusted-uuid";
    trusted->cert = cert;
    trusted->spki_fingerprint = fingerprint;
    auto other = std::make_shared<crypto::named_cert_t>();
    other->uuid = "other-uuid";
    other->cert = std::string(kSpkiFixture);
    std::vector<crypto::p_named_cert_t> devices {trusted, other};

    const auto removed_uuids = remove_named_devices_by_fingerprint(fingerprint, devices);
    ASSERT_EQ(removed_uuids, (std::vector<std::string> {"trusted-uuid"}));
    EXPECT_FALSE(find_named_device_by_fingerprint(fingerprint, devices));

    DirectAuthManager manager;
    manager.block_fingerprint(fingerprint, "denied");
    EXPECT_EQ(manager.classify(fingerprint, cert, [&](const std::string &fp) {
      return cert_matches_any_named_device(fp, devices);
    }), DeviceTrustState::Blocked);
    manager.unblock_fingerprint(fingerprint);
    EXPECT_EQ(manager.classify(fingerprint, cert, [&](const std::string &fp) {
      return cert_matches_any_named_device(fp, devices);
    }), DeviceTrustState::Unknown);
  }

  TEST_F(DirectAuthTest, ExpireStaleClosesEnrollment) {
    DirectAuthManager manager;
    manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp), -1);
    manager.expire_stale();
    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Closed);
  }

  TEST_F(DirectAuthTest, ResetEphemeralClosesEnrollmentAndKeepsBlocked) {
    DirectAuthManager manager;
    manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    manager.block_fingerprint(std::string(kClientFp));
    manager.reset_ephemeral();
    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Closed);
    EXPECT_TRUE(manager.is_blocked_or_revoked(std::string(kClientFp)));
  }

  TEST_F(DirectAuthTest, ConcurrentValidRequestsCreateSinglePending) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    ));

    std::atomic<int> successes {0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
      threads.emplace_back([&] {
        std::string pending_id;
        std::string error;
        if (manager.submit_enrollment_request(
              open.enrollment_id, std::string(kClientFp), "A", "u", proof,
              std::string(kClientFp), cert, "10.0.0.3", &pending_id, &error)) {
          successes.fetch_add(1);
        }
      });
    }
    for (auto &t : threads) {
      t.join();
    }
    EXPECT_EQ(successes.load(), 1);
    EXPECT_EQ(manager.pending_candidates().size(), 1u);
  }

  TEST_F(DirectAuthTest, BlockedSnapshotRoundTripsThroughLoad) {
    DirectAuthManager manager;
    manager.block_fingerprint(std::string(kClientFp), "denied", "Blocked Laptop", "laptop-uuid");
    manager.revoke_fingerprint(std::string(kOtherFp));

    const auto snapshot = manager.snapshot_blocked();
    ASSERT_EQ(snapshot.size(), 2u);

    DirectAuthManager restored;
    restored.load_blocked(snapshot);
    ASSERT_TRUE(restored.is_blocked_or_revoked(std::string(kClientFp)));
    ASSERT_TRUE(restored.is_blocked_or_revoked(std::string(kOtherFp)));

    const auto loaded_snapshot = restored.snapshot_blocked();
    ASSERT_EQ(loaded_snapshot.size(), 2u);
    const auto blocked_it = std::find_if(loaded_snapshot.begin(), loaded_snapshot.end(), [&](const BlockedInfo &info) {
      return info.fingerprint == kClientFp;
    });
    ASSERT_NE(blocked_it, loaded_snapshot.end());
    EXPECT_EQ(blocked_it->reason, "denied");
    EXPECT_EQ(blocked_it->name, "Blocked Laptop");
    EXPECT_EQ(blocked_it->uuid, "laptop-uuid");

    const auto revoked_it = std::find_if(loaded_snapshot.begin(), loaded_snapshot.end(), [&](const BlockedInfo &info) {
      return info.fingerprint == kOtherFp;
    });
    ASSERT_NE(revoked_it, loaded_snapshot.end());
    EXPECT_EQ(revoked_it->reason, "revoked");
  }

  TEST_F(DirectAuthTest, EnrollmentConsumedStateVisibleAfterValidSubmission) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47989, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, std::string(kHostFp), std::string(kClientFp)
    ));

    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "127.0.0.1", &pending_id, nullptr
    ));

    EXPECT_EQ(manager.enrollment_status().state, EnrollmentState::Consumed);
    // Once consumed, the enrollment secret/setup URI must not remain exposed.
    EXPECT_TRUE(manager.enrollment_status().setup_uri.empty());
  }

  TEST_F(DirectAuthTest, SetupUriUsesDirectHttpsPortAndEncodesIpv6Host) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("fd00::1234", 47984, std::string(kHostFp));
    ASSERT_EQ(open.state, EnrollmentState::Open);
    EXPECT_NE(open.setup_uri.find("host=fd00%3A%3A1234"), std::string::npos);
    EXPECT_NE(open.setup_uri.find("https_port=47984"), std::string::npos);
    EXPECT_EQ(open.setup_uri.find("https_port=47990"), std::string::npos);
    EXPECT_NE(open.setup_uri.find("hostfp=sha256%2F"), std::string::npos);
    EXPECT_EQ(raw_secret_from_setup_uri(open).size(), 32u);
  }

  TEST_F(DirectAuthTest, AcceptedTerminalStateIsVisibleThenCleaned) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "10.0.0.4", &pending_id, nullptr));
    ASSERT_TRUE(manager.accept_pending(pending_id, [](const PendingInfo &) { return true; }));
    const auto accepted = manager.pending_status(pending_id, std::string(kClientFp));
    ASSERT_EQ(accepted.state, PendingState::Accepted);
    manager.expire_stale(accepted.expires_at_unix_ms + 1);
    EXPECT_EQ(manager.pending_status(pending_id, std::string(kClientFp)).state, PendingState::Expired);

    const auto reopened = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret2 = raw_secret_from_setup_uri(reopened);
    const auto proof2 = DirectAuthManager::hmac_sha256_base64url(secret2, DirectAuthManager::enrollment_proof_input(
      reopened.enrollment_id, kHostFp, kClientFp));
    std::string second_pending_id;
    std::string error;
    EXPECT_TRUE(manager.submit_enrollment_request(
      reopened.enrollment_id, std::string(kClientFp), "A", "u", proof2,
      std::string(kClientFp), cert, "10.0.0.4", &second_pending_id, &error)) << error;
  }

  TEST_F(DirectAuthTest, DeniedTerminalStateIsVisibleThenCleaned) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret = raw_secret_from_setup_uri(open);
    const auto proof = DirectAuthManager::hmac_sha256_base64url(secret, DirectAuthManager::enrollment_proof_input(
      open.enrollment_id, kHostFp, kClientFp));
    std::string pending_id;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id, std::string(kClientFp), "A", "u", proof,
      std::string(kClientFp), cert, "10.0.0.5", &pending_id, nullptr));
    ASSERT_TRUE(manager.deny_pending(pending_id, {}));
    const auto denied = manager.pending_status(pending_id, std::string(kClientFp));
    ASSERT_EQ(denied.state, PendingState::Denied);
    manager.expire_stale(denied.expires_at_unix_ms + 1);
    EXPECT_EQ(manager.pending_status(pending_id, std::string(kClientFp)).state, PendingState::Expired);
    manager.unblock_fingerprint(std::string(kClientFp));

    const auto reopened = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    const auto secret2 = raw_secret_from_setup_uri(reopened);
    const auto proof2 = DirectAuthManager::hmac_sha256_base64url(secret2, DirectAuthManager::enrollment_proof_input(
      reopened.enrollment_id, kHostFp, kClientFp));
    std::string second_pending_id;
    std::string error;
    EXPECT_TRUE(manager.submit_enrollment_request(
      reopened.enrollment_id, std::string(kClientFp), "A", "u", proof2,
      std::string(kClientFp), cert, "10.0.0.5", &second_pending_id, &error)) << error;
  }

  TEST_F(DirectAuthTest, RouteAuthorizationMatrix) {
    EXPECT_FALSE(route_requires_trusted_client("/direct/v1/status"));
    EXPECT_FALSE(route_requires_trusted_client("/direct/v1/enroll/request"));
    EXPECT_FALSE(route_requires_trusted_client("/direct/v1/enroll/status"));
    EXPECT_TRUE(route_requires_trusted_client("/direct/v1/probe"));
    EXPECT_TRUE(route_requires_trusted_client("/applist"));
    EXPECT_TRUE(route_requires_trusted_client("/appasset"));
    EXPECT_TRUE(route_requires_trusted_client("/launch"));
    EXPECT_TRUE(route_requires_trusted_client("/resume"));
    EXPECT_TRUE(route_requires_trusted_client("/cancel"));
    EXPECT_TRUE(route_requires_trusted_client("/clipboard"));
    EXPECT_TRUE(route_requires_trusted_client("/actions"));
    EXPECT_TRUE(route_requires_trusted_client("/bitrate"));
    EXPECT_TRUE(route_requires_trusted_client("/abr"));
    EXPECT_FALSE(route_requires_trusted_client("/pair"));
  }

  TEST_F(DirectAuthTest, NamedDeviceTrustUsesSpkiNotCertificateBytes) {
    auto named = std::make_shared<crypto::named_cert_t>();
    named->cert = std::string(kSpkiFixture);
    std::vector<crypto::p_named_cert_t> devices {named};
    const auto parsed = crypto::x509(kSpkiFixture);
    ASSERT_TRUE(parsed);
    const auto fingerprint = crypto::spki_sha256_fingerprint(parsed);
    EXPECT_TRUE(cert_matches_any_named_device(fingerprint, devices));
    EXPECT_FALSE(cert_matches_any_named_device(std::string(kOtherFp), devices));
  }

  TEST_F(DirectAuthTest, ReissuedCertificateWithSameKeyPreservesNamedDevicePermissions) {
    const auto creds = crypto::gen_creds("first-direct-auth-cert", 2048);
    const auto reissued = issue_cert_with_existing_key(creds.pkey, 4242, "reissued-direct-auth-cert");
    ASSERT_FALSE(reissued.empty());
    ASSERT_NE(reissued, creds.x509);

    const auto first_x509 = crypto::x509(creds.x509);
    const auto reissued_x509 = crypto::x509(reissued);
    ASSERT_TRUE(first_x509);
    ASSERT_TRUE(reissued_x509);
    const auto first_fp = crypto::spki_sha256_fingerprint(first_x509);
    const auto reissued_fp = crypto::spki_sha256_fingerprint(reissued_x509);
    ASSERT_EQ(first_fp, reissued_fp);

    auto named = std::make_shared<crypto::named_cert_t>();
    named->name = "Laptop";
    named->uuid = "same-key-device-uuid";
    named->cert = creds.x509;
    named->perm = static_cast<crypto::PERM>(
      static_cast<std::uint32_t>(crypto::PERM::launch) |
      static_cast<std::uint32_t>(crypto::PERM::_allow_view)
    );
    std::vector<crypto::p_named_cert_t> devices {named};

    const auto resolved = find_named_device_by_fingerprint(reissued_fp, devices);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(resolved->uuid, "same-key-device-uuid");
    EXPECT_EQ(resolved->name, "Laptop");
    EXPECT_EQ(resolved->perm, named->perm);

    DirectAuthManager manager;
    EXPECT_EQ(
      manager.classify(reissued_fp, reissued, [&](const std::string &fingerprint) {
        return cert_matches_any_named_device(fingerprint, devices);
      }),
      DeviceTrustState::Trusted
    );

    const auto other_creds = crypto::gen_creds("other-key", 2048);
    const auto other_x509 = crypto::x509(other_creds.x509);
    ASSERT_TRUE(other_x509);
    const auto other_fp = crypto::spki_sha256_fingerprint(other_x509);
    EXPECT_NE(other_fp, first_fp);
    EXPECT_FALSE(find_named_device_by_fingerprint(other_fp, devices));
    EXPECT_EQ(
      manager.classify(other_fp, other_creds.x509, [&](const std::string &fingerprint) {
        return cert_matches_any_named_device(fingerprint, devices);
      }),
      DeviceTrustState::Unknown
    );
  }

  TEST_F(DirectAuthTest, RevocationAppliesToSameKeyCertificateReissue) {
    const auto creds = crypto::gen_creds("revoked-first", 2048);
    const auto reissued = issue_cert_with_existing_key(creds.pkey, 777, "revoked-reissue");
    ASSERT_FALSE(reissued.empty());
    const auto first_x509 = crypto::x509(creds.x509);
    const auto reissued_x509 = crypto::x509(reissued);
    ASSERT_TRUE(first_x509);
    ASSERT_TRUE(reissued_x509);
    const auto fingerprint = crypto::spki_sha256_fingerprint(first_x509);
    ASSERT_EQ(fingerprint, crypto::spki_sha256_fingerprint(reissued_x509));

    auto named = std::make_shared<crypto::named_cert_t>();
    named->cert = creds.x509;
    std::vector<crypto::p_named_cert_t> devices {named};

    DirectAuthManager manager;
    manager.revoke_fingerprint(fingerprint);
    EXPECT_EQ(
      manager.classify(fingerprint, reissued, [&](const std::string &fp) {
        return cert_matches_any_named_device(fp, devices);
      }),
      DeviceTrustState::Revoked
    );
  }

  TEST_F(DirectAuthTest, RandomScannerAttemptsDoNotCreatePendingAndRateMapsStayBounded) {
    DirectAuthManager manager;
    const auto open = manager.open_enrollment("gaming-pc", 47984, std::string(kHostFp));
    ASSERT_EQ(open.state, EnrollmentState::Open);
    const std::string wrong_proof = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    for (int i = 0; i < 100; ++i) {
      std::string digest(32, '\0');
      digest[0] = static_cast<char>(i);
      const auto fingerprint = "sha256/" + DirectAuthManager::base64url_encode(digest);
      std::string pending_id;
      std::string error;
      EXPECT_FALSE(manager.submit_enrollment_request(
        open.enrollment_id, fingerprint, "scanner", "scanner-uuid", wrong_proof,
        fingerprint, sample_cert(), "10.23.0." + std::to_string(i + 1), &pending_id, &error));
      EXPECT_TRUE(pending_id.empty());
    }
    EXPECT_TRUE(manager.pending_candidates().empty());
    const auto stats = manager.rate_limit_stats();
    EXPECT_LE(stats.ip_buckets, 30u);
    EXPECT_LE(stats.fingerprint_buckets, 30u);
    EXPECT_LE(stats.global_timestamps, 30u);

    manager.prune_rate_limits(std::numeric_limits<std::int64_t>::max());
    const auto pruned = manager.rate_limit_stats();
    EXPECT_EQ(pruned.ip_buckets, 0u);
    EXPECT_EQ(pruned.fingerprint_buckets, 0u);
    EXPECT_EQ(pruned.global_timestamps, 0u);
  }

}  // namespace direct_auth
