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
#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>
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

  DirectAuthManager::DirectAuthManager():
      DirectAuthManager([](const std::size_t bytes, std::string &out) {
        return crypto::secure_random_bytes(bytes, out);
      }) {
  }

  DirectAuthManager::DirectAuthManager(RandomBytesProvider random_bytes_provider):
      random_bytes_provider_(std::move(random_bytes_provider)) {
    if (!random_bytes_provider_) {
      random_bytes_provider_ = [](const std::size_t bytes, std::string &out) {
        return crypto::secure_random_bytes(bytes, out);
      };
    }
  }

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

    if (input.find('=') != std::string_view::npos ||
        input.find('+') != std::string_view::npos ||
        input.find('/') != std::string_view::npos ||
        input.size() % 4 == 1) {
      return false;
    }

    auto valid_char = [](char c) -> int {
      if (c >= 'A' && c <= 'Z') return c - 'A';
      if (c >= 'a' && c <= 'z') return c - 'a' + 26;
      if (c >= '0' && c <= '9') return c - '0' + 52;
      if (c == '-') return 62;
      if (c == '_') return 63;
      return -1;
    };

    const std::size_t data_len = input.size();

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
    if (base64url_encode(out) != input) {
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
    if (fp.size() != 7 + 43 || fp.substr(0, 7) != "sha256/") {
      return false;
    }
    std::string digest;
    return base64url_decode(fp.substr(7), digest) && digest.size() == 32;
  }

  bool DirectAuthManager::valid_enrollment_id_format(const std::string_view &id) {
    if (id.empty() || id.size() > 256) {
      return false;
    }
    std::string decoded;
    return base64url_decode(id, decoded) && decoded.size() >= 16;
  }

  bool DirectAuthManager::valid_pending_id_format(const std::string_view &id) {
    if (id.empty() || id.size() > 64) {
      return false;
    }
    std::string decoded;
    return base64url_decode(id, decoded) && decoded.size() == 16;
  }

  bool DirectAuthManager::valid_proof_format(const std::string_view &proof) {
    std::string decoded;
    return base64url_decode(proof, decoded) && decoded.size() == 32;
  }

  bool parse_enrollment_request_body(
    const std::string_view raw_body,
    EnrollmentRequestFields &fields,
    std::string &error_code
  ) {
    fields = {};
    error_code.clear();
    if (raw_body.size() > MAX_BODY_BYTES) {
      error_code = "BODY_TOO_LARGE";
      return false;
    }

    try {
      const auto body = nlohmann::json::parse(raw_body.begin(), raw_body.end());
      if (!body.is_object()) {
        error_code = "MALFORMED";
        return false;
      }

      const auto protocol_it = body.find("protocol");
      if (protocol_it == body.end() ||
          !(protocol_it->is_number_integer() || protocol_it->is_number_unsigned())) {
        error_code = "MALFORMED";
        return false;
      }
      const bool protocol_one = protocol_it->is_number_unsigned() ?
                                  protocol_it->get<std::uint64_t>() == 1u :
                                  protocol_it->get<std::int64_t>() == 1;
      if (!protocol_one) {
        error_code = "UNSUPPORTED_VERSION";
        return false;
      }

      const auto read_required_string = [&](const char *key, std::string &out) {
        const auto it = body.find(key);
        if (it == body.end() || !it->is_string()) {
          return false;
        }
        out = it->get<std::string>();
        return true;
      };

      if (!read_required_string("enrollment_id", fields.enrollment_id) ||
          !read_required_string("client_fingerprint", fields.client_fingerprint) ||
          !read_required_string("client_name", fields.client_name) ||
          !read_required_string("client_uuid", fields.client_uuid) ||
          !read_required_string("proof", fields.proof)) {
        fields = {};
        error_code = "MALFORMED";
        return false;
      }
      return true;
    } catch (...) {
      fields = {};
      error_code = "MALFORMED";
      return false;
    }
  }

  bool parse_pending_id_query_values(
    const std::vector<std::string> &values,
    std::string &pending_id
  ) {
    pending_id.clear();
    if (values.size() != 1 || !DirectAuthManager::valid_pending_id_format(values.front())) {
      return false;
    }
    pending_id = values.front();
    return true;
  }

  bool valid_setup_host(const std::string_view host) {
    if (host.empty() || host.size() > 255) {
      return false;
    }
    for (const auto ch : host) {
      const auto c = static_cast<unsigned char>(ch);
      if (c <= 0x20 || c >= 0x7f) {
        return false;
      }
    }
    if (host.find_first_of("/?#[]@") != std::string_view::npos) {
      return false;
    }

    const auto colon_count = static_cast<std::size_t>(std::count(host.begin(), host.end(), ':'));
    if (colon_count == 1) {
      return false;
    }

    boost::system::error_code ec;
    (void) boost::asio::ip::make_address(std::string(host), ec);
    if (!ec) {
      return true;
    }

    // A colon that was not accepted as an IP literal is an embedded port or
    // otherwise malformed address, not a DNS hostname.
    if (host.find(':') != std::string_view::npos || host.size() > 253) {
      return false;
    }
    const bool numeric_dotted = std::all_of(host.begin(), host.end(), [](const char ch) {
      return (ch >= '0' && ch <= '9') || ch == '.';
    });
    if (numeric_dotted) {
      return false;
    }

    std::size_t label_start = 0;
    while (label_start < host.size()) {
      const auto label_end = host.find('.', label_start);
      const auto end = label_end == std::string_view::npos ? host.size() : label_end;
      const auto label = host.substr(label_start, end - label_start);
      if (label.empty() || label.size() > 63) {
        return false;
      }
      const auto is_alnum = [](const char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
      };
      if (!is_alnum(label.front()) || !is_alnum(label.back()) ||
          !std::all_of(label.begin(), label.end(), [&](const char ch) { return is_alnum(ch) || ch == '-'; })) {
        return false;
      }
      if (label_end == std::string_view::npos) {
        break;
      }
      label_start = label_end + 1;
    }
    return true;
  }

  std::string generate_unique_named_device_uuid(
    const std::vector<crypto::p_named_cert_t> &named_devices,
    const std::function<std::string()> &generate_uuid
  ) {
    if (!generate_uuid) {
      return {};
    }

    std::unordered_set<std::string> existing_uuids;
    existing_uuids.reserve(named_devices.size());
    for (const auto &device : named_devices) {
      if (device && !device->uuid.empty()) {
        existing_uuids.insert(device->uuid);
      }
    }

    // UUID collisions are practically impossible with the production
    // generator, but enforce the data-model invariant rather than assuming it.
    for (std::size_t attempt = 0; attempt < 128; ++attempt) {
      auto candidate = generate_uuid();
      if (!candidate.empty() && !existing_uuids.contains(candidate)) {
        return candidate;
      }
    }
    return {};
  }

  std::vector<std::string> remove_named_devices_by_fingerprint(
    const std::string &fingerprint,
    std::vector<crypto::p_named_cert_t> &named_devices
  ) {
    std::vector<std::string> removed_uuids;
    if (!DirectAuthManager::valid_fingerprint_format(fingerprint)) {
      return removed_uuids;
    }

    for (auto it = named_devices.begin(); it != named_devices.end();) {
      const auto &named_cert = *it;
      if (!named_cert) {
        ++it;
        continue;
      }
      const auto cert = crypto::x509(named_cert->cert);
      const auto stored_fingerprint = cert ? crypto::spki_sha256_fingerprint(cert) : std::string();
      if (!stored_fingerprint.empty() && stored_fingerprint == fingerprint) {
        if (!named_cert->uuid.empty()) {
          removed_uuids.push_back(named_cert->uuid);
        }
        it = named_devices.erase(it);
      } else {
        ++it;
      }
    }
    return removed_uuids;
  }

  std::string DirectAuthManager::percent_encode_query_value(const std::string_view &value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
      const bool unreserved =
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
      if (unreserved) {
        out.push_back(static_cast<char>(c));
      } else {
        out.push_back('%');
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0F]);
      }
    }
    return out;
  }

  DeviceTrustState DirectAuthManager::classify(
    const std::string &fingerprint,
    const std::string &cert_pem,
    const std::function<bool(const std::string &fingerprint)> &is_trusted_fingerprint
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

    (void) cert_pem;
    if (is_trusted_fingerprint && is_trusted_fingerprint(fingerprint)) {
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

    // Enrollment IDs and secrets fail closed if OpenSSL cannot supply CSPRNG
    // material. Tests inject the same checked provider contract.
    std::string enrollment_id_bytes;
    std::string secret_bytes;
    if (!random_bytes_provider_ ||
        !random_bytes_provider_(16, enrollment_id_bytes) || enrollment_id_bytes.size() != 16 ||
        !random_bytes_provider_(32, secret_bytes) || secret_bytes.size() != 32) {
      enrollment_.reset();
      return {};
    }

    EnrollmentSession session;
    session.enrollment_id = base64url_encode(enrollment_id_bytes);
    std::copy(secret_bytes.begin(), secret_bytes.end(), session.secret.begin());
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
    const auto secret_text = base64url_encode(std::string_view {
      reinterpret_cast<const char *>(enroll.secret.data()), enroll.secret.size()
    });
    info.setup_uri = "vibedirect://enroll?v=1&host=" + percent_encode_query_value(enroll.host) +
                     "&https_port=" + std::to_string(enroll.https_port) +
                     "&hostfp=" + percent_encode_query_value(enroll.host_fingerprint) +
                     "&eid=" + percent_encode_query_value(enroll.enrollment_id) +
                     "&secret=" + percent_encode_query_value(secret_text);
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
    const auto secret_text = base64url_encode(std::string_view {
      reinterpret_cast<const char *>(enrollment_->secret.data()), enrollment_->secret.size()
    });
    info.setup_uri = "vibedirect://enroll?v=1&host=" + percent_encode_query_value(enrollment_->host) +
                     "&https_port=" + std::to_string(enrollment_->https_port) +
                     "&hostfp=" + percent_encode_query_value(enrollment_->host_fingerprint) +
                     "&eid=" + percent_encode_query_value(enrollment_->enrollment_id) +
                     "&secret=" + percent_encode_query_value(secret_text);
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
    if (out_pending_id) {
      out_pending_id->clear();
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

    if (!valid_enrollment_id_format(enrollment_id) || !valid_fingerprint_format(body_fingerprint) || !valid_proof_format(body_proof)) {
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
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
    const std::string_view raw_secret {
      reinterpret_cast<const char *>(enrollment_->secret.data()), enrollment_->secret.size()
    };
    const auto expected_proof = hmac_sha256_base64url(raw_secret, proof_input);
    std::string supplied_proof_bytes;
    std::string expected_proof_bytes;
    const bool proof_decoded = base64url_decode(body_proof, supplied_proof_bytes) && supplied_proof_bytes.size() == 32;
    const bool expected_decoded = base64url_decode(expected_proof, expected_proof_bytes) && expected_proof_bytes.size() == 32;
    if (!proof_decoded || !expected_decoded || !constant_time_equal(supplied_proof_bytes, expected_proof_bytes)) {
      if (!rate_limit_failed_attempt(actual_fingerprint, source_ip)) {
        if (out_error_code) *out_error_code = "RATE_LIMITED";
        return false;
      }
      if (out_error_code) *out_error_code = "ENROLLMENT_INVALID_PROOF";
      return false;
    }

    // A previously blocked/revoked fingerprint stays blocked even with a valid
    // fresh token until an admin explicitly unblocks it.
    const auto blocked_it = blocked_.find(actual_fingerprint);
    if (blocked_it != blocked_.end()) {
      if (out_error_code) {
        *out_error_code = blocked_it->second.reason == "revoked" ? "DEVICE_REVOKED" : "DEVICE_BLOCKED";
      }
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

    // Generate a checked pending ID before consuming the one-time enrollment.
    // RNG failure therefore cannot burn a valid token without creating state.
    std::string pending_id_bytes;
    if (!random_bytes_provider_ || !random_bytes_provider_(16, pending_id_bytes) || pending_id_bytes.size() != 16) {
      if (out_error_code) *out_error_code = "INTERNAL_ERROR";
      return false;
    }
    const auto pending_id = base64url_encode(pending_id_bytes);
    if (!valid_pending_id_format(pending_id) || pending_by_id_.contains(pending_id)) {
      if (out_error_code) *out_error_code = "INTERNAL_ERROR";
      return false;
    }

    // Consume only after every proof/security-state/bounds/RNG check succeeds.
    enrollment_->consumed = true;

    PendingEnrollment pending;
    pending.info.pending_id = pending_id;
    pending.info.fingerprint = actual_fingerprint;
    pending.info.name = body_client_name;
    pending.info.uuid = body_client_uuid;
    pending.info.source_ip = source_ip;
    pending.info.cert_pem = cert_pem;
    pending.info.state = PendingState::Pending;
    pending.info.created_at_unix_ms = now_ms();
    pending.info.expires_at_unix_ms = pending.info.created_at_unix_ms + PENDING_TTL_MS;
    pending.proof = body_proof;

    pending_by_id_.emplace(pending_id, std::move(pending));
    pending_by_fingerprint_.emplace(actual_fingerprint, PendingState::Pending);

    if (out_pending_id) {
      *out_pending_id = pending_id;
    }
    return true;
  }

  PendingInfo DirectAuthManager::pending_status(
    const std::string &pending_id,
    const std::string &fingerprint,
    const std::int64_t now_override_ms
  ) {
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
    const auto now = now_override_ms != 0 ? now_override_ms : now_ms();
    if (it->second.info.expires_at_unix_ms <= now && it->second.info.state != PendingState::Accepting) {
      pending_by_fingerprint_.erase(it->second.info.fingerprint);
      pending_by_id_.erase(it);
      PendingInfo info;
      info.state = PendingState::Expired;
      return info;
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
    PendingInfo candidate;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      const auto it = pending_by_id_.find(pending_id);
      if (it == pending_by_id_.end() || it->second.info.state != PendingState::Pending) {
        return false;
      }
      if (it->second.info.expires_at_unix_ms <= now_ms()) {
        pending_by_fingerprint_.erase(it->second.info.fingerprint);
        pending_by_id_.erase(it);
        return false;
      }
      it->second.info.state = PendingState::Accepting;
      pending_by_fingerprint_[it->second.info.fingerprint] = PendingState::Accepting;
      candidate = it->second.info;
    }

    bool accepted = false;
    try {
      accepted = accept_trusted_cert && accept_trusted_cert(candidate);
    } catch (...) {
      accepted = false;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto it = pending_by_id_.find(pending_id);
    if (it == pending_by_id_.end() || it->second.info.state != PendingState::Accepting ||
        it->second.info.fingerprint != candidate.fingerprint) {
      return false;
    }
    if (blocked_.contains(candidate.fingerprint)) {
      it->second.info.state = PendingState::Denied;
      it->second.info.expires_at_unix_ms = now_ms() + TERMINAL_PENDING_GRACE_MS;
      it->second.expired_while_accepting = false;
      pending_by_fingerprint_[candidate.fingerprint] = PendingState::Denied;
      return false;
    }
    if (!accepted) {
      if (it->second.expired_while_accepting || it->second.info.expires_at_unix_ms <= now_ms()) {
        pending_by_fingerprint_.erase(candidate.fingerprint);
        pending_by_id_.erase(it);
        return false;
      }
      it->second.info.state = PendingState::Pending;
      pending_by_fingerprint_[candidate.fingerprint] = PendingState::Pending;
      return false;
    }
    it->second.info.state = PendingState::Accepted;
    it->second.info.expires_at_unix_ms = now_ms() + TERMINAL_PENDING_GRACE_MS;
    it->second.expired_while_accepting = false;
    pending_by_fingerprint_[candidate.fingerprint] = PendingState::Accepted;
    return true;
  }

  bool DirectAuthManager::deny_pending(
    const std::string &pending_id,
    const std::function<void(const std::string &fingerprint)> &block_fingerprint
  ) {
    std::string fingerprint;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      const auto it = pending_by_id_.find(pending_id);
      if (it == pending_by_id_.end() || it->second.info.state != PendingState::Pending) {
        return false;
      }
      fingerprint = it->second.info.fingerprint;
      it->second.info.state = PendingState::Denied;
      it->second.info.expires_at_unix_ms = now_ms() + TERMINAL_PENDING_GRACE_MS;
      pending_by_fingerprint_[fingerprint] = PendingState::Denied;
    }

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

    // Explicit blocking wins over pending/accepting approval state. The host
    // serializes trusted-device side effects with the same policy.
    for (auto &[_, pending] : pending_by_id_) {
      if (pending.info.fingerprint == fingerprint &&
          (pending.info.state == PendingState::Pending || pending.info.state == PendingState::Accepting)) {
        pending.info.state = PendingState::Denied;
        pending.info.expires_at_unix_ms = now_ms() + TERMINAL_PENDING_GRACE_MS;
        pending.expired_while_accepting = false;
        pending_by_fingerprint_[fingerprint] = PendingState::Denied;
      }
    }
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

  void DirectAuthManager::expire_stale(std::int64_t now_override_ms) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto now = now_override_ms != 0 ? now_override_ms : now_ms();
    if (enrollment_ && std::chrono::duration_cast<std::chrono::milliseconds>(enrollment_->expires_at.time_since_epoch()).count() <= now) {
      enrollment_.reset();
    }

    for (auto it = pending_by_id_.begin(); it != pending_by_id_.end();) {
      if (it->second.info.expires_at_unix_ms > now) {
        ++it;
        continue;
      }
      if (it->second.info.state == PendingState::Accepting) {
        it->second.expired_while_accepting = true;
        ++it;
        continue;
      }
      pending_by_fingerprint_.erase(it->second.info.fingerprint);
      it = pending_by_id_.erase(it);
    }
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

    const auto now = now_ms();
    const auto cutoff = now - kWindowMs;
    const auto prune_map = [cutoff](auto &map) {
      std::erase_if(map, [cutoff](auto &entry) {
        auto &timestamps = entry.second;
        std::erase_if(timestamps, [cutoff](std::int64_t ts) { return ts < cutoff; });
        return timestamps.empty();
      });
    };
    prune_map(ip_failures_);
    prune_map(fingerprint_failures_);
    std::erase_if(global_failures_, [cutoff](std::int64_t ts) { return ts < cutoff; });

    const auto bucket_count = [now, kWindowMs](const auto &map, const std::string &key) -> std::int64_t {
      if (key.empty()) return 0;
      const auto it = map.find(key);
      if (it == map.end()) return 0;
      const auto cutoff = now - kWindowMs;
      return static_cast<std::int64_t>(std::count_if(it->second.begin(), it->second.end(), [cutoff](std::int64_t ts) {
        return ts >= cutoff;
      }));
    };
    const auto ip_count = bucket_count(ip_failures_, source_ip);
    const auto fp_count = bucket_count(fingerprint_failures_, fingerprint);
    const auto global_count = count_recent(global_failures_, kWindowMs);

    const bool allowed = ip_count < kMaxIp && fp_count < kMaxFingerprint && global_count < kMaxGlobal;
    if (allowed) {
      if (!source_ip.empty()) {
        push_timestamp(ip_failures_[source_ip], kWindowMs);
      }
      if (!fingerprint.empty()) {
        push_timestamp(fingerprint_failures_[fingerprint], kWindowMs);
      }
      push_timestamp(global_failures_, kWindowMs);
    }
    return allowed;
  }

  RateLimitStats DirectAuthManager::rate_limit_stats() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return {
      .ip_buckets = ip_failures_.size(),
      .fingerprint_buckets = fingerprint_failures_.size(),
      .global_timestamps = global_failures_.size(),
    };
  }

  void DirectAuthManager::prune_rate_limits(std::int64_t now_override_ms) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    constexpr std::int64_t kWindowMs = 60 * 1000;
    const auto now = now_override_ms != 0 ? now_override_ms : now_ms();
    const auto cutoff = now - kWindowMs;
    const auto prune_map = [cutoff](auto &map) {
      std::erase_if(map, [cutoff](auto &entry) {
        auto &timestamps = entry.second;
        std::erase_if(timestamps, [cutoff](std::int64_t ts) { return ts < cutoff; });
        return timestamps.empty();
      });
    };
    prune_map(ip_failures_);
    prune_map(fingerprint_failures_);
    std::erase_if(global_failures_, [cutoff](std::int64_t ts) { return ts < cutoff; });
  }

  bool cert_matches_any_named_device(
    const std::string &fingerprint,
    const std::vector<crypto::p_named_cert_t> &named_devices
  ) {
    return find_named_device_by_fingerprint(fingerprint, named_devices) != nullptr;
  }

  crypto::p_named_cert_t find_named_device_by_fingerprint(
    const std::string &fingerprint,
    const std::vector<crypto::p_named_cert_t> &named_devices
  ) {
    if (!DirectAuthManager::valid_fingerprint_format(fingerprint)) {
      return {};
    }
    const auto it = std::find_if(named_devices.begin(), named_devices.end(), [&](const crypto::p_named_cert_t &named_cert) {
      if (!named_cert) {
        return false;
      }
      const auto cert = crypto::x509(named_cert->cert);
      if (!cert) {
        return false;
      }
      // The certificate-derived value is authoritative. A persisted field is
      // only a cache/migration aid and must never override conflicting cert data.
      return crypto::spki_sha256_fingerprint(cert) == fingerprint;
    });
    return it == named_devices.end() ? crypto::p_named_cert_t {} : *it;
  }

  bool is_public_direct_auth_path(std::string_view path) {
    return path == "/direct/v1/status" ||
           path == "/direct/v1/enroll/request" ||
           path == "/direct/v1/enroll/status";
  }

  bool route_requires_trusted_client(std::string_view path) {
    if (path == "/serverinfo" || path == "/pair" || path == "/unpair") {
      return false;
    }
    return !is_public_direct_auth_path(path);
  }

}  // namespace direct_auth
