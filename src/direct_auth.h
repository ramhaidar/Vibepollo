/**
 * @file src/direct_auth.h
 * @brief Vibe Direct Auth v1 host-side trusted-device/enrollment state machine.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// local includes
#include "crypto.h"

namespace direct_auth {

  constexpr std::int64_t ENROLLMENT_TTL_MS = 120 * 1000;
  constexpr std::int64_t PENDING_TTL_MS = 5 * 60 * 1000;
  constexpr std::size_t MAX_PENDING_CANDIDATES = 8;
  constexpr std::size_t MAX_BODY_BYTES = 16 * 1024;
  constexpr std::size_t MAX_CLIENT_NAME_BYTES = 128;
  constexpr std::size_t MAX_CLIENT_UUID_BYTES = 128;

  enum class DeviceTrustState {
    Unknown,
    Trusted,
    Blocked,
    Revoked,
  };

  enum class EnrollmentState {
    Closed,
    Open,
    Consumed,
  };

  enum class PendingState {
    Pending,
    Accepted,
    Denied,
    Expired,
  };

  struct EnrollmentInfo {
    EnrollmentState state {EnrollmentState::Closed};
    std::string enrollment_id;
    std::string setup_uri;
    std::int64_t expires_at_unix_ms {0};
  };

  struct PendingInfo {
    std::string pending_id;
    std::string fingerprint;
    std::string name;
    std::string uuid;
    std::string source_ip;
    std::string cert_pem;
    PendingState state {PendingState::Pending};
    std::int64_t created_at_unix_ms {0};
    std::int64_t expires_at_unix_ms {0};
  };

  struct BlockedInfo {
    std::string fingerprint;
    std::string reason;
    std::string name;
    std::string uuid;
    std::int64_t created_at_unix_ms {0};
  };

  /**
   * @brief Pure Vibe Direct Auth v1 state manager.
   *
   * The manager deliberately does not know about HTTP servers, TLS sockets, or
   * nvhttp internals. Callers feed it an already-extracted peer fingerprint,
   * certificate PEM, source IP, and trusted-device lookup callback.
   *
   * Enrollment secrets and pending proofs are memory-only. Durable block/revoke
   * state is serialized through the admin API and restored by the host at
   * startup.
   */
  class DirectAuthManager {
  public:
    DirectAuthManager() = default;
    DirectAuthManager(DirectAuthManager &&) noexcept = default;
    DirectAuthManager &operator=(DirectAuthManager &&) noexcept = default;

    DirectAuthManager(const DirectAuthManager &) = delete;
    DirectAuthManager &operator=(const DirectAuthManager &) = delete;

    // ---- Trust classification -------------------------------------------

    /**
     * @brief Resolve trust for a peer fingerprint.
     *
     * The `is_trusted_cert_pem` callback is used to verify against the existing
     * named-device trust database so DirectAuthManager does not maintain a
     * second trusted-device database.
     */
    DeviceTrustState classify(
      const std::string &fingerprint,
      const std::string &cert_pem,
      const std::function<bool(const std::string &cert_pem)> &is_trusted_cert_pem
    ) const;

    // ---- Enrollment ------------------------------------------------------

    /**
     * @brief Open an enrollment window.
     *
     * Replaces any existing open/consumed session. The setup URI is constructed
     * from the caller-supplied endpoint values so the manager can be tested
     * without network assumptions.
     *
     * @return An info snapshot containing the enrollment ID and setup URI.
     */
    EnrollmentInfo open_enrollment(
      const std::string &host,
      std::uint16_t https_port,
      const std::string &host_fingerprint,
      std::int64_t ttl_ms = ENROLLMENT_TTL_MS
    );

    /**
     * @brief Close the current enrollment window.
     */
    void close_enrollment();

    EnrollmentInfo enrollment_status() const;

    /**
     * @brief Verify and consume an enrollment request.
     *
     * @return true if a pending approval was created. The caller must emit a UI
     * notification only when this returns true.
     */
    bool submit_enrollment_request(
      const std::string &enrollment_id,
      const std::string &body_fingerprint,
      const std::string &body_client_name,
      const std::string &body_client_uuid,
      const std::string &body_proof,
      const std::string &actual_fingerprint,
      const std::string &cert_pem,
      const std::string &source_ip,
      std::string *out_pending_id,
      std::string *out_error_code = nullptr
    );

    PendingInfo pending_status(const std::string &pending_id, const std::string &fingerprint);
    std::vector<PendingInfo> pending_candidates() const;

    // ---- Admin actions ----------------------------------------------------

    /**
     * @brief Accept a pending enrollment and persist it into the trusted registry.
     *
     * The `accept_trusted_cert` callback creates/updates a normal named device
     * and returns the generated fingerprint. The manager marks the pending
     * record accepted only after the callback succeeds.
     */
    bool accept_pending(
      const std::string &pending_id,
      const std::function<bool(const PendingInfo &)> &accept_trusted_cert
    );

    /**
     * @brief Deny a pending enrollment and block the fingerprint.
     *
     * `block_fingerprint` must persist the fingerprint in blocked state.
     */
    bool deny_pending(
      const std::string &pending_id,
      const std::function<void(const std::string &fingerprint)> &block_fingerprint
    );

    /**
     * @brief Persist a blocked fingerprint.
     */
    void block_fingerprint(const std::string &fingerprint, const std::string &reason = "denied", const std::string &name = {}, const std::string &uuid = {});

    /**
     * @brief Persist a revoked fingerprint. Revocation is durable and takes
     * precedence over trusted state.
     */
    void revoke_fingerprint(const std::string &fingerprint);

    /**
     * @brief Remove a blocked/revoked fingerprint. The device becomes unknown;
     * it is not trusted.
     */
    void unblock_fingerprint(const std::string &fingerprint);

    std::vector<BlockedInfo> blocked_revoked() const;
    bool is_blocked_or_revoked(const std::string &fingerprint) const;

    /**
     * @brief Expire stale in-memory enrollment/pending records.
     */
    void expire_stale();

    /**
     * @brief Reset enrollment and pending ephemeral state (host restart path).
     * Durable blocked/revoked records are retained.
     */
    void reset_ephemeral();

    // ---- Persistence ------------------------------------------------------

    /**
     * @brief Load durable blocked/revoked state from a JSON array.
     */
    void load_blocked(const std::vector<BlockedInfo> &blocked);

    /**
     * @brief Snapshot durable blocked/revoked state for serialization.
     */
    std::vector<BlockedInfo> snapshot_blocked() const;

    // ---- Rate limiting ----------------------------------------------------

    /**
     * @brief Rate limit failed enrollment attempts.
     *
     * Buckets: per source IP ~5/min, per fingerprint ~3/min, global ~30/min.
     * @return false when the attempt should be rejected as rate limited.
     */
    bool rate_limit_failed_attempt(const std::string &fingerprint, const std::string &source_ip);

    // ---- Crypto/format helpers (public for shared vectors/tests) ----------

    /**
     * @brief Base64url encode without padding.
     */
    static std::string base64url_encode(const std::string_view &bytes);

    /**
     * @brief Decode base64url (with or without padding). Returns false on
     * malformed input.
     */
    static bool base64url_decode(const std::string_view &input, std::string &out);

    /**
     * @brief HMAC-SHA256 and base64url no-padding.
     */
    static std::string hmac_sha256_base64url(const std::string_view &key, const std::string_view &data);

    /**
     * @brief Exact Vibe Direct Auth enrollment proof bytes.
     */
    static std::string enrollment_proof_input(
      const std::string_view &enrollment_id,
      const std::string_view &host_fingerprint,
      const std::string_view &client_fingerprint
    );

    /**
     * @brief Constant-time string comparison.
     */
    static bool constant_time_equal(const std::string_view &a, const std::string_view &b);

    static bool valid_fingerprint_format(const std::string_view &fp);
    static bool valid_enrollment_id_format(const std::string_view &id);

  private:
    struct EnrollmentSession {
      std::string enrollment_id;
      std::string secret;
      std::string host;
      std::uint16_t https_port {0};
      std::string host_fingerprint;
      std::chrono::system_clock::time_point expires_at;
      bool consumed {false};
    };

    struct PendingEnrollment {
      PendingInfo info;
      std::string proof;
    };

    mutable std::recursive_mutex mutex_;
    std::optional<EnrollmentSession> enrollment_;
    std::unordered_map<std::string, PendingEnrollment> pending_by_id_;
    std::unordered_map<std::string, PendingState> pending_by_fingerprint_;
    std::unordered_map<std::string, BlockedInfo> blocked_;
    std::unordered_map<std::string, std::vector<std::int64_t>> ip_failures_;
    std::unordered_map<std::string, std::vector<std::int64_t>> fingerprint_failures_;
    std::vector<std::int64_t> global_failures_;
  };

  /**
   * @brief Convenience wrapper for the nvhttp certificate trust callback.
   */
  bool cert_matches_any_named_device(
    const std::string &cert_pem,
    const std::vector<crypto::p_named_cert_t> &named_devices
  );

}  // namespace direct_auth
