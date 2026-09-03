/**
 * @file src/direct_auth.cpp
 * @brief Vibe Direct Auth v1 host-side trusted-device/enrollment state machine.
 */
// standard includes
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <functional>
#include <mutex>
#include <random>
#include <sstream>
#include <string_view>

// lib includes
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// local includes
#include "direct_auth.h"

namespace direct_auth {

  namespace {
    std::int64_t now_ms() {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
      ).count();
    }

    std::int64_t count_recent(const std::vector<std::int64_t> &timestamps, std::int64_t window_ms) {
      const auto cutoff = now_ms() - window_ms;
      return static_cast<std::int64_t>(std::count_if(timestamps.begin(), timestamps.end(), [cutoff](std::int64_t ts) {
        return ts >= cutoff;
      }));
    }

    void push_timestamp(std::vector<std::int64_t> &timestamps, std::int64_t window_ms) {
      const auto cutoff = now_ms() - window_ms;
      timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(), [cutoff](std::int64_t ts) { return ts < cutoff; }),
        timestamps.end()
      );
      timestamps.push_back(now_ms());
    }
  }  // namespace

  std::string DirectAuthManager::base64url_encode(const std::string_view &bytes) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
      const auto b0 = static_cast<unsigned char>(bytes[i]);
      const auto b1 = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0;
      const auto b2 = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0;
      out.push_back(alphabet[b0 >> 2]);
      out.push_back(alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]);
      if (i + 1 < bytes.size()) {
        out.push_back(alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)]);
      }
      if (i + 2 < bytes.size()) {
        out.push_back(alphabet[b2 & 0x3F]);
      }
    }
    return out;
  }

  bool DirectAuthManager::base64url_decode(const std::string_view &input, std::string &out) {
    out.clear();
    if (input.empty()) {
      return true;
    }

    auto valid_char = [](char c) -> int {
      if (c >= 'A' && c <= 'Z') return c - 'A';
      if (c >= 'a' && c <= 'z') return c - 'a' + 26;
      if (c >= '0' && c <= '9') return c - '0' + 52;
      if (c == '-') return 62;
      if (c == '_') return 63;
      return -1;
    };

    std::size_t padding = 0;
    if (input.back() == '=') {
      padding = 1;
      if (input.size() > 1 && input[input.size() - 2] == '=') {
        padding = 2;
      }
    }

    const std::size_t data_len = input.size() - padding;
    if (data_len % 4 == 1) {
      return false;
    }

    out.reserve((data_len / 4) * 3 + (data_len % 4 == 2 ? 1 : data_len % 4 == 3 ? 2 : 0));
    std::array<int, 4> buf {};
    std::size_t group = 0;
    for (std::size_t i = 0; i < data_len; ++i) {
      const auto value = valid_char(input[i]);
      if (value < 0) {
        out.clear();
        return false;
      }
      buf[group++] = value;
      if (group == 4) {
        out.push_back(static_cast<char>((buf[0] << 2) | (buf[1] >> 4)));
        out.push_back(static_cast<char>(((buf[1] & 0x0F) << 4) | (buf[2] >> 2)));
        out.push_back(static_cast<char>(((buf[2] & 0x03) << 6) | buf[3]));
        group = 0;
      }
    }
    if (group == 2) {
      out.push_back(static_cast<char>((buf[0] << 2) | (buf[1] >> 4)));
    } else if (group == 3) {
      out.push_back(static_cast<char>((buf[0] << 2) | (buf[1] >> 4)));
      out.push_back(static_cast<char>(((buf[1] & 0x0F) << 4) | (buf[2] >> 2)));
    } else if (group != 0) {
      out.clear();
      return false;
    }
    return true;
  }

  std::string DirectAuthManager::hmac_sha256_base64url(const std::string_view &key, const std::string_view &data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char *>(data.data()), data.size(),
              digest, &digest_len)) {
      return {};
    }
    return base64url_encode(std::string_view {reinterpret_cast<const char *>(digest), digest_len});
  }

  std::string DirectAuthManager::enrollment_proof_input(
    const std::string_view &enrollment_id,
    const std::string_view &host_fingerprint,
    const std::string_view &client_fingerprint
  ) {
    std::string input;
    input.reserve(32 + enrollment_id.size() + host_fingerprint.size() + client_fingerprint.size() + 3);
    input += "vibe-direct-enroll-v1\n";
    input += enrollment_id;
    input += '\n';
    input += host_fingerprint;
    input += '\n';
    input += client_fingerprint;
    return input;
  }

  bool DirectAuthManager::constant_time_equal(const std::string_view &a, const std::string_view &b) {
    if (a.size() != b.size()) {
      return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
      diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
  }

  bool DirectAuthManager::valid_fingerprint_format(const std::string_view &fp) {
    if (fp.size() <= 8 || fp.substr(0, 7) != "sha256/") {
      return false;
    }
    for (std::size_t i = 7; i < fp.size(); ++i) {
      const char c = fp[i];
      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
        return false;
      }
    }
    // SHA-256 base64url no padding is exactly 43 characters.
    return fp.size() == 7 + 43;
  }

  bool DirectAuthManager::valid_enrollment_id_format(const std::string_view &id) {
    if (id.empty() || id.size() > 256) {
      return false;
    }
    for (const char c : id) {
      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
        return false;
      }
    }
    return true;
  }

  DeviceTrustState DirectAuthManager::classify(
    const std::string &fingerprint,
    const std::string &cert_pem,
    const std::function<bool(const std::string &cert_pem)> &is_trusted_cert_pem
  ) const {
    if (fingerprint.empty()) {
      return DeviceTrustState::Unknown;
    }

    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      const auto it = blocked_.find(fingerprint);
      if (it != blocked_.end()) {
        return it->second.reason == "revoked" ? DeviceTrustState::Revoked : DeviceTrustState::Blocked;
      }
    }

    if (is_trusted_cert_pem && is_trusted_cert_pem(cert_pem)) {
      return DeviceTrustState::Trusted;
    }
    return DeviceTrustState::Unknown;
  }

  EnrollmentInfo DirectAuthManager::open_enrollment(
    const std::string &host,
    std::uint16_t https_port,
    const std::string &host_fingerprint,
    std::int64_t ttl_ms
  ) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Enrollment IDs must be >=128 bits of CSPRNG randomness.
    std::string enrollment_id_bytes = crypto::rand(16);
    std::string secret_bytes = crypto::rand(32);

    EnrollmentSession session;
    session.enrollment_id = base64url_encode(enrollment_id_bytes);
    session.secret = base64url_encode(secret_bytes);
    session.host = host;
    session.https_port = https_port;
    session.host_fingerprint = host_fingerprint;
    session.expires_at = std::chrono::system_clock::now() + std::chrono::milliseconds(ttl_ms);
    session.consumed = false;

    enrollment_ = std::move(session);

    EnrollmentInfo info;
    info.state = EnrollmentState::Open;
    info.enrollment_id = enrollment_->enrollment_id;
    info.expires_at_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(enrollment_->expires_at.time_since_epoch()).count();

    const auto &enroll = *enrollment_;
    info.setup_uri = "vibedirect://enroll?v=1&host=" + enroll.host +
                     "&https_port=" + std::to_string(enroll.https_port) +
                     "&hostfp=" + enroll.host_fingerprint +
                     "&eid=" + enroll.enrollment_id +
                     "&secret=" + enroll.secret;
    return info;
  }

  void DirectAuthManager::close_enrollment() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    enrollment_.reset();
  }

  EnrollmentInfo DirectAuthManager::enrollment_status() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    EnrollmentInfo info;
    if (!enrollment_) {
      info.state = EnrollmentState::Closed;
      return info;
    }

    const auto now = std::chrono::system_clock::now();
    if (enrollment_->expires_at <= now) {
      info.state = EnrollmentState::Closed;
      return info;
    }

    if (enrollment_->consumed) {
      info.state = EnrollmentState::Consumed;
      return info;
    }

    info.state = EnrollmentState::Open;
    info.enrollment_id = enrollment_->enrollment_id;
    info.expires_at_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(enrollment_->expires_at.time_since_epoch()).count();
    info.setup_uri = "vibedirect://enroll?v=1&host=" + enrollment_->host +
                     "&https_port=" + std::to_string(enrollment_->https_port) +
                     "&hostfp=" + enrollment_->host_fingerprint +
                     "&eid=" + enrollment_->enrollment_id +
                     "&secret=" + enrollment_->secret;
    return info;
  }

  bool DirectAuthManager::submit_enrollment_request(
    const std::string &enrollment_id,
    const std::string &body_fingerprint,
    const std::string &body_client_name,
    const std::string &body_client_uuid,
    const std::string &body_proof,
    const std::string &actual_fingerprint,
    const std::string &cert_pem,
    const std::string &source_ip,
    std::string *out_pending_id,
    std::string *out_error_code
  ) {
    if (!valid_enrollment_id_format(enrollment_id) || !valid_fingerprint_format(body_fingerprint) || body_proof.empty()) {
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
      return false;
    }
    if (body_client_name.size() > MAX_CLIENT_NAME_BYTES || body_client_uuid.size() > MAX_CLIENT_UUID_BYTES) {
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
      return false;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (!enrollment_ || enrollment_->consumed || enrollment_->expires_at <= std::chrono::system_clock::now()) {
      if (out_error_code) *out_error_code = "ENROLLMENT_CLOSED";
      return false;
    }

    if (!constant_time_equal(enrollment_id, enrollment_->enrollment_id)) {
      if (!rate_limit_failed_attempt(actual_fingerprint, source_ip)) {
        if (out_error_code) *out_error_code = "RATE_LIMITED";
        return false;
      }
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
      return false;
    }

    // Actual TLS peer certificate fingerprint must match the body fingerprint.
    if (!constant_time_equal(body_fingerprint, actual_fingerprint)) {
      if (!rate_limit_failed_attempt(actual_fingerprint, source_ip)) {
        if (out_error_code) *out_error_code = "RATE_LIMITED";
        return false;
      }
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
      return false;
    }

    const auto proof_input = enrollment_proof_input(enrollment_id, enrollment_->host_fingerprint, actual_fingerprint);
    const auto expected_proof = hmac_sha256_base64url(enrollment_->secret, proof_input);
    if (expected_proof.empty() || !constant_time_equal(body_proof, expected_proof)) {
      if (!rate_limit_failed_attempt(actual_fingerprint, source_ip)) {
        if (out_error_code) *out_error_code = "RATE_LIMITED";
        return false;
      }
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
      return false;
    }

    // Consume the enrollment session atomically.
    enrollment_->consumed = true;

    // A previously blocked/revoked fingerprint stays blocked even with a valid
    // fresh token until an admin explicitly unblocks it.
    const auto blocked_it = blocked_.find(actual_fingerprint);
    if (blocked_it != blocked_.end()) {
      if (out_error_code) *out_error_code = "DEVICE_BLOCKED";
      return false;
    }

    if (pending_by_fingerprint_.contains(actual_fingerprint)) {
      if (out_error_code) *out_error_code = "ENROLLMENT_PENDING";
      return false;
    }

    if (pending_by_id_.size() >= MAX_PENDING_CANDIDATES) {
      if (out_error_code) *out_error_code = "RATE_LIMITED";
      return false;
    }

    const auto pending_id_bytes = crypto::rand(16);
    PendingEnrollment pending;
    pending.info.pending_id = base64url_encode(pending_id_bytes);
    pending.info.fingerprint = actual_fingerprint;
    pending.info.name = body_client_name;
    pending.info.uuid = body_client_uuid;
    pending.info.source_ip = source_ip;
    pending.info.cert_pem = cert_pem;
    pending.info.state = PendingState::Pending;
    pending.info.created_at_unix_ms = now_ms();
    pending.info.expires_at_unix_ms = pending.info.created_at_unix_ms + PENDING_TTL_MS;
    pending.proof = body_proof;

    const auto pending_id = pending.info.pending_id;
    pending_by_id_.emplace(pending_id, std::move(pending));
    pending_by_fingerprint_.emplace(actual_fingerprint, PendingState::Pending);

    if (out_pending_id) {
      *out_pending_id = pending_id;
    }
    return true;
  }

  PendingInfo DirectAuthManager::pending_status(const std::string &pending_id, const std::string &fingerprint) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto it = pending_by_id_.find(pending_id);
    if (it == pending_by_id_.end()) {
      PendingInfo info;
      info.state = PendingState::Expired;
      return info;
    }
    if (it->second.info.fingerprint != fingerprint) {
      PendingInfo info;
      info.state = PendingState::Expired;
      return info;
    }
    if (it->second.info.expires_at_unix_ms <= now_ms() && it->second.info.state == PendingState::Pending) {
      it->second.info.state = PendingState::Expired;
      pending_by_fingerprint_[fingerprint] = PendingState::Expired;
    }
    return it->second.info;
  }

  std::vector<PendingInfo> DirectAuthManager::pending_candidates() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<PendingInfo> out;
    out.reserve(pending_by_id_.size());
    for (const auto &[_, pending] : pending_by_id_) {
      if (pending.info.state == PendingState::Pending) {
        out.push_back(pending.info);
      }
    }
    std::sort(out.begin(), out.end(), [](const PendingInfo &a, const PendingInfo &b) {
      return a.created_at_unix_ms < b.created_at_unix_ms;
    });
    return out;
  }

  bool DirectAuthManager::accept_pending(
    const std::string &pending_id,
    const std::function<bool(const PendingInfo &)> &accept_trusted_cert
  ) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto it = pending_by_id_.find(pending_id);
    if (it == pending_by_id_.end() || it->second.info.state != PendingState::Pending) {
      return false;
    }
    if (it->second.info.expires_at_unix_ms <= now_ms()) {
      it->second.info.state = PendingState::Expired;
      pending_by_fingerprint_[it->second.info.fingerprint] = PendingState::Expired;
      return false;
    }

    if (!accept_trusted_cert(it->second.info)) {
      return false;
    }

    it->second.info.state = PendingState::Accepted;
    pending_by_fingerprint_[it->second.info.fingerprint] = PendingState::Accepted;
    return true;
  }

  bool DirectAuthManager::deny_pending(
    const std::string &pending_id,
    const std::function<void(const std::string &fingerprint)> &block_fingerprint
  ) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto it = pending_by_id_.find(pending_id);
    if (it == pending_by_id_.end() || it->second.info.state != PendingState::Pending) {
      return false;
    }

    const auto fingerprint = it->second.info.fingerprint;
    it->second.info.state = PendingState::Denied;
    pending_by_fingerprint_[fingerprint] = PendingState::Denied;

    if (block_fingerprint) {
      block_fingerprint(fingerprint);
    } else {
      this->block_fingerprint(fingerprint, "denied");
    }
    return true;
  }

  void DirectAuthManager::block_fingerprint(
    const std::string &fingerprint,
    const std::string &reason,
    const std::string &name,
    const std::string &uuid
  ) {
    if (fingerprint.empty()) {
      return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    BlockedInfo info;
    info.fingerprint = fingerprint;
    info.reason = reason.empty() ? "denied" : reason;
    info.name = name;
    info.uuid = uuid;
    info.created_at_unix_ms = now_ms();
    blocked_[fingerprint] = std::move(info);
  }

  void DirectAuthManager::revoke_fingerprint(const std::string &fingerprint) {
    block_fingerprint(fingerprint, "revoked");
  }

  void DirectAuthManager::unblock_fingerprint(const std::string &fingerprint) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    blocked_.erase(fingerprint);
  }

  std::vector<BlockedInfo> DirectAuthManager::blocked_revoked() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BlockedInfo> out;
    out.reserve(blocked_.size());
    for (const auto &[_, info] : blocked_) {
      out.push_back(info);
    }
    std::sort(out.begin(), out.end(), [](const BlockedInfo &a, const BlockedInfo &b) {
      return a.created_at_unix_ms < b.created_at_unix_ms;
    });
    return out;
  }

  bool DirectAuthManager::is_blocked_or_revoked(const std::string &fingerprint) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return blocked_.contains(fingerprint);
  }

  void DirectAuthManager::expire_stale() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto now = now_ms();
    if (enrollment_ && enrollment_->expires_at <= std::chrono::system_clock::now()) {
      enrollment_.reset();
    }

    std::erase_if(pending_by_id_, [&](const auto &entry) {
      if (entry.second.info.expires_at_unix_ms <= now && entry.second.info.state == PendingState::Pending) {
        pending_by_fingerprint_.erase(entry.second.info.fingerprint);
        return true;
      }
      return false;
    });
  }

  void DirectAuthManager::reset_ephemeral() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    enrollment_.reset();
    pending_by_id_.clear();
    pending_by_fingerprint_.clear();
    ip_failures_.clear();
    fingerprint_failures_.clear();
    global_failures_.clear();
  }

  void DirectAuthManager::load_blocked(const std::vector<BlockedInfo> &blocked) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    blocked_.clear();
    for (const auto &info : blocked) {
      if (!info.fingerprint.empty()) {
        blocked_[info.fingerprint] = info;
      }
    }
  }

  std::vector<BlockedInfo> DirectAuthManager::snapshot_blocked() const {
    return blocked_revoked();
  }

  bool DirectAuthManager::rate_limit_failed_attempt(const std::string &fingerprint, const std::string &source_ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    constexpr std::int64_t kWindowMs = 60 * 1000;
    constexpr std::int64_t kMaxIp = 5;
    constexpr std::int64_t kMaxFingerprint = 3;
    constexpr std::int64_t kMaxGlobal = 30;

    const auto ip_count = count_recent(ip_failures_[source_ip], kWindowMs);
    const auto fp_count = fingerprint.empty() ? 0 : count_recent(fingerprint_failures_[fingerprint], kWindowMs);
    const auto global_count = count_recent(global_failures_, kWindowMs);

    const bool allowed = ip_count < kMaxIp && fp_count < kMaxFingerprint && global_count < kMaxGlobal;
    if (allowed) {
      push_timestamp(ip_failures_[source_ip], kWindowMs);
      if (!fingerprint.empty()) {
        push_timestamp(fingerprint_failures_[fingerprint], kWindowMs);
      }
      push_timestamp(global_failures_, kWindowMs);
    }
    return allowed;
  }

  bool cert_matches_any_named_device(
    const std::string &cert_pem,
    const std::vector<crypto::p_named_cert_t> &named_devices
  ) {
    if (cert_pem.empty()) {
      return false;
    }
    return std::any_of(named_devices.begin(), named_devices.end(), [&](const crypto::p_named_cert_t &named_cert) {
      return named_cert && named_cert->cert == cert_pem;
    });
  }

}  // namespace direct_auth
