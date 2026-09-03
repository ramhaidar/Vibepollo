/**
 * @file tests/unit/test_direct_auth.cpp
 * @brief Unit tests for the Vibe Direct Auth v1 host state machine.
 */
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "src/direct_auth.h"
#include "src/crypto.h"

namespace direct_auth {

  namespace {
    constexpr std::string_view kHostFp = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    constexpr std::string_view kClientFp = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    constexpr std::string_view kOtherFp = "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    std::string sample_cert() {
      const auto creds = crypto::gen_creds("direct-auth-test", 2048);
      return creds.x509;
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
    EXPECT_TRUE(DirectAuthManager::base64url_decode("", decoded));
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);

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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    const auto secret_pos2 = open_after.setup_uri.find("secret=");
    ASSERT_NE(secret_pos2, std::string::npos);
    const auto secret2 = open_after.setup_uri.substr(secret_pos2 + 7);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    EXPECT_EQ(manager.classify(std::string(kClientFp), cert, [&](const std::string &pem) { return pem == cert; }),
              DeviceTrustState::Trusted);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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
    const auto secret_pos = open.setup_uri.find("secret=");
    ASSERT_NE(secret_pos, std::string::npos);
    const auto secret = open.setup_uri.substr(secret_pos + 7);
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

}  // namespace direct_auth
