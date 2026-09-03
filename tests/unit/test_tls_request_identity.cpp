/**
 * @file tests/unit/test_tls_request_identity.cpp
 * @brief Regression tests for TLS peer identity binding to the actual HTTP connection.
 */
#include <gtest/gtest.h>

#include <future>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <Simple-Web-Server/server_http.hpp>

#include "src/crypto.h"
#include "src/direct_auth.h"

namespace {

  struct TestPeerAuthContext {
    std::string fingerprint;
    bool trusted {};
  };

  class RequestBindingHarness: public SimpleWeb::ServerBase<SimpleWeb::HTTP> {
    using base_t = SimpleWeb::ServerBase<SimpleWeb::HTTP>;

  public:
    using request_t = std::shared_ptr<typename base_t::Request>;

    struct connection_requests_t {
      std::shared_ptr<void> connection_keepalive;
      request_t first;
      request_t second;
    };

    RequestBindingHarness():
        base_t(0) {
    }

    connection_requests_t make_connection() {
      auto connection = this->create_connection(io_context_);
      auto first_session = std::make_shared<typename base_t::Session>(
        this->config.max_request_streambuf_size,
        connection
      );
      auto second_session = std::make_shared<typename base_t::Session>(
        this->config.max_request_streambuf_size,
        connection
      );
      return {
        std::static_pointer_cast<void>(connection),
        first_session->request,
        second_session->request,
      };
    }

  protected:
    void accept() override {
    }

  private:
    SimpleWeb::io_context io_context_;
  };

  std::shared_ptr<const TestPeerAuthContext> peer_auth(const RequestBindingHarness::request_t &request) {
    return std::static_pointer_cast<const TestPeerAuthContext>(request->connection_user_data());
  }

  void bind_peer_auth(
    const RequestBindingHarness::request_t &request,
    std::shared_ptr<const TestPeerAuthContext> context
  ) {
    ASSERT_TRUE(request->set_connection_user_data(std::move(context)));
  }

  std::string raw_secret_from_setup_uri(const direct_auth::EnrollmentInfo &info) {
    const auto secret_pos = info.setup_uri.find("secret=");
    if (secret_pos == std::string::npos) {
      return {};
    }
    const auto start = secret_pos + 7;
    const auto end = info.setup_uri.find('&', start);
    const auto encoded = info.setup_uri.substr(start, end == std::string::npos ? std::string::npos : end - start);
    std::string decoded;
    if (!direct_auth::DirectAuthManager::base64url_decode(encoded, decoded)) {
      return {};
    }
    return decoded;
  }

  TEST(TlsRequestIdentityBinding, KeepAliveRequestsShareTheSameConnectionContext) {
    RequestBindingHarness harness;
    auto connection = harness.make_connection();
    auto context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/A", true}
    );

    bind_peer_auth(connection.first, context);

    ASSERT_EQ(peer_auth(connection.first), context);
    ASSERT_EQ(peer_auth(connection.second), context);
  }

  TEST(TlsRequestIdentityBinding, InterleavedConnectionsNeverOverwriteEachOther) {
    RequestBindingHarness harness;
    auto trusted_a = harness.make_connection();
    auto unknown_b = harness.make_connection();
    auto a_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/A", true}
    );
    auto b_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/B", false}
    );

    bind_peer_auth(trusted_a.first, a_context);
    bind_peer_auth(unknown_b.first, b_context);

    ASSERT_EQ(peer_auth(trusted_a.second), a_context);
    ASSERT_TRUE(peer_auth(trusted_a.second)->trusted);
    ASSERT_EQ(peer_auth(unknown_b.second), b_context);
    ASSERT_FALSE(peer_auth(unknown_b.second)->trusted);
  }

  TEST(TlsRequestIdentityBinding, UnknownARequestNeverInheritsTrustedBHandshake) {
    RequestBindingHarness harness;
    auto unknown_a = harness.make_connection();
    auto trusted_b = harness.make_connection();
    auto a_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/A", false}
    );
    auto b_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/B", true}
    );

    bind_peer_auth(unknown_a.first, a_context);
    bind_peer_auth(trusted_b.first, b_context);

    ASSERT_EQ(peer_auth(unknown_a.second), a_context);
    ASSERT_FALSE(peer_auth(unknown_a.second)->trusted);
    ASSERT_EQ(peer_auth(trusted_b.second), b_context);
  }

  TEST(TlsRequestIdentityBinding, StatusFingerprintIsPerConnection) {
    RequestBindingHarness harness;
    auto connection_a = harness.make_connection();
    auto connection_b = harness.make_connection();
    auto a_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/A", false}
    );
    auto b_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/B", false}
    );

    bind_peer_auth(connection_a.first, a_context);
    bind_peer_auth(connection_b.first, b_context);

    EXPECT_EQ(peer_auth(connection_a.second)->fingerprint, "sha256/A");
    EXPECT_EQ(peer_auth(connection_b.second)->fingerprint, "sha256/B");
  }

  TEST(TlsRequestIdentityBinding, EnrollmentPendingOwnershipCannotCrossConnections) {
    RequestBindingHarness harness;
    auto connection_a = harness.make_connection();
    auto connection_b = harness.make_connection();
    const auto creds_a = crypto::gen_creds("tls-binding-a", 2048);
    const auto creds_b = crypto::gen_creds("tls-binding-b", 2048);
    auto cert_a = crypto::x509(creds_a.x509);
    auto cert_b = crypto::x509(creds_b.x509);
    ASSERT_TRUE(cert_a);
    ASSERT_TRUE(cert_b);
    const auto fingerprint_a = crypto::spki_sha256_fingerprint(cert_a);
    const auto fingerprint_b = crypto::spki_sha256_fingerprint(cert_b);
    ASSERT_NE(fingerprint_a, fingerprint_b);

    bind_peer_auth(connection_a.first, std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {fingerprint_a, false}
    ));
    bind_peer_auth(connection_b.first, std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {fingerprint_b, false}
    ));

    direct_auth::DirectAuthManager manager;
    const std::string host_fingerprint = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const auto open = manager.open_enrollment("127.0.0.1", 47984, host_fingerprint);
    const auto secret = raw_secret_from_setup_uri(open);
    ASSERT_EQ(secret.size(), 32u);
    const auto owner_fingerprint = peer_auth(connection_a.second)->fingerprint;
    const auto proof = direct_auth::DirectAuthManager::hmac_sha256_base64url(
      secret,
      direct_auth::DirectAuthManager::enrollment_proof_input(open.enrollment_id, host_fingerprint, owner_fingerprint)
    );
    std::string pending_id;
    std::string error;
    ASSERT_TRUE(manager.submit_enrollment_request(
      open.enrollment_id,
      owner_fingerprint,
      "Client A",
      "client-a",
      proof,
      owner_fingerprint,
      creds_a.x509,
      "127.0.0.1",
      &pending_id,
      &error
    )) << error;

    EXPECT_EQ(manager.pending_status(pending_id, peer_auth(connection_a.second)->fingerprint).state,
              direct_auth::PendingState::Pending);
    EXPECT_EQ(manager.pending_status(pending_id, peer_auth(connection_b.second)->fingerprint).state,
              direct_auth::PendingState::Expired);
    EXPECT_EQ(peer_auth(connection_b.second)->fingerprint, fingerprint_b);
  }

  TEST(TlsRequestIdentityBinding, WorkerThreadReadsOriginatingConnectionContext) {
    RequestBindingHarness harness;
    auto trusted_a = harness.make_connection();
    auto unknown_b = harness.make_connection();
    auto a_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/A", true}
    );
    auto b_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/B", false}
    );

    bind_peer_auth(trusted_a.first, a_context);
    bind_peer_auth(unknown_b.first, b_context);

    auto worker = std::async(std::launch::async, [request = trusted_a.second] {
      return peer_auth(request);
    });

    ASSERT_EQ(worker.get(), a_context);
  }

  TEST(TlsRequestIdentityBinding, ConnectionDestructionReleasesAuthContext) {
    RequestBindingHarness harness;
    auto connection = harness.make_connection();
    auto context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/A", true}
    );
    std::weak_ptr<const TestPeerAuthContext> weak_context = context;

    bind_peer_auth(connection.first, context);
    context.reset();
    ASSERT_FALSE(weak_context.expired());

    connection.connection_keepalive.reset();

    ASSERT_TRUE(weak_context.expired());
    ASSERT_EQ(peer_auth(connection.first), nullptr);
    ASSERT_EQ(peer_auth(connection.second), nullptr);
  }

  TEST(TlsRequestIdentityBinding, ConnectionChurnReleasesAllAuthContexts) {
    RequestBindingHarness harness;
    std::vector<std::weak_ptr<const TestPeerAuthContext>> weak_contexts;
    weak_contexts.reserve(512);

    for (int i = 0; i < 512; ++i) {
      auto connection = harness.make_connection();
      auto context = std::make_shared<const TestPeerAuthContext>(TestPeerAuthContext {
        "sha256/churn-" + std::to_string(i),
        (i % 2) == 0,
      });
      weak_contexts.emplace_back(context);
      bind_peer_auth(connection.first, context);
      context.reset();
      connection.connection_keepalive.reset();
      ASSERT_EQ(peer_auth(connection.first), nullptr);
    }

    for (const auto &weak_context : weak_contexts) {
      EXPECT_TRUE(weak_context.expired());
    }
  }

  TEST(TlsRequestIdentityBinding, IdenticalTransportMetadataDoesNotShareIdentity) {
    RequestBindingHarness harness;
    auto old_connection = harness.make_connection();
    auto new_connection = harness.make_connection();
    auto old_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/OLD", true}
    );
    auto new_context = std::make_shared<const TestPeerAuthContext>(
      TestPeerAuthContext {"sha256/NEW", false}
    );

    // Both sockets are deliberately unconnected, so their exposed transport
    // endpoints are identical/default. Identity must still be connection-owned.
    ASSERT_EQ(old_connection.first->remote_endpoint(), new_connection.first->remote_endpoint());

    bind_peer_auth(old_connection.first, old_context);
    bind_peer_auth(new_connection.first, new_context);

    ASSERT_EQ(peer_auth(old_connection.second), old_context);
    ASSERT_EQ(peer_auth(new_connection.second), new_context);
  }

  TEST(TlsRequestIdentityBinding, NvhttpHasOneConnectionBoundPeerIdentityPath) {
    std::ifstream source_file(std::string(SUNSHINE_SOURCE_DIR) + "/src/nvhttp.cpp");
    ASSERT_TRUE(source_file.is_open());
    std::ostringstream source_stream;
    source_stream << source_file.rdbuf();
    const auto source = source_stream.str();

    EXPECT_EQ(source.find("tl_peer_auth_context"), std::string::npos);
    EXPECT_EQ(source.find("tl_peer_certificate"), std::string::npos);
    EXPECT_EQ(source.find("tls_client_identity_by_endpoint"), std::string::npos);
    EXPECT_EQ(source.find("endpoint_key("), std::string::npos);
    EXPECT_EQ(source.find("remember_tls_client_identity("), std::string::npos);
    EXPECT_EQ(source.find("get_remembered_tls_client_identity("), std::string::npos);
    EXPECT_EQ(source.find("classify_current_peer("), std::string::npos);
    EXPECT_EQ(source.find("current_peer_fingerprint("), std::string::npos);
    EXPECT_EQ(source.find("current_peer_cert_pem("), std::string::npos);
    EXPECT_NE(source.find("connection_user_data()"), std::string::npos);
    EXPECT_NE(source.find("set_connection_user_data("), std::string::npos);
  }

  TEST(TlsRequestIdentityBinding, NvhttpUsesTypeSafeDirectAuthProtocolParsing) {
    std::ifstream source_file(std::string(SUNSHINE_SOURCE_DIR) + "/src/nvhttp.cpp");
    ASSERT_TRUE(source_file.is_open());
    std::ostringstream source_stream;
    source_stream << source_file.rdbuf();
    const auto source = source_stream.str();

    EXPECT_EQ(source.find("body.value(\"protocol\""), std::string::npos);
    EXPECT_EQ(source.find("body.value(\"enrollment_id\""), std::string::npos);
    EXPECT_EQ(source.find("body.value(\"client_fingerprint\""), std::string::npos);
    EXPECT_EQ(source.find("body.value(\"client_name\""), std::string::npos);
    EXPECT_EQ(source.find("body.value(\"client_uuid\""), std::string::npos);
    EXPECT_EQ(source.find("body.value(\"proof\""), std::string::npos);
    EXPECT_NE(source.find("parse_enrollment_request_body("), std::string::npos);
    EXPECT_NE(source.find("parse_pending_id_query_values("), std::string::npos);
  }

  TEST(TlsRequestIdentityBinding, NvhttpNeverTrustsClientUuidAsInternalDeviceUuid) {
    std::ifstream source_file(std::string(SUNSHINE_SOURCE_DIR) + "/src/nvhttp.cpp");
    ASSERT_TRUE(source_file.is_open());
    std::ostringstream source_stream;
    source_stream << source_file.rdbuf();
    const auto source = source_stream.str();

    EXPECT_EQ(source.find("info.uuid.empty() ? uuid_util::uuid_t::generate().string() : info.uuid"), std::string::npos);
    EXPECT_EQ(source.find("named_cert_p->uuid = info.uuid"), std::string::npos);
    EXPECT_NE(source.find("generate_unique_named_device_uuid("), std::string::npos);
  }

  TEST(TlsRequestIdentityBinding, DirectAuthSecurityTokensUseCheckedCSPRNG) {
    std::ifstream direct_auth_file(std::string(SUNSHINE_SOURCE_DIR) + "/src/direct_auth.cpp");
    ASSERT_TRUE(direct_auth_file.is_open());
    std::ostringstream direct_auth_stream;
    direct_auth_stream << direct_auth_file.rdbuf();
    const auto direct_auth_source = direct_auth_stream.str();

    std::ifstream crypto_file(std::string(SUNSHINE_SOURCE_DIR) + "/src/crypto.cpp");
    ASSERT_TRUE(crypto_file.is_open());
    std::ostringstream crypto_stream;
    crypto_stream << crypto_file.rdbuf();
    const auto crypto_source = crypto_stream.str();

    EXPECT_EQ(direct_auth_source.find("crypto::rand("), std::string::npos);
    EXPECT_NE(direct_auth_source.find("crypto::secure_random_bytes"), std::string::npos);
    EXPECT_NE(crypto_source.find("RAND_bytes"), std::string::npos);
    EXPECT_NE(crypto_source.find("!= 1"), std::string::npos);
  }

  TEST(TlsRequestIdentityBinding, NvhttpBlockIsTrustDestructiveAndSetupHostIsValidated) {
    std::ifstream source_file(std::string(SUNSHINE_SOURCE_DIR) + "/src/nvhttp.cpp");
    ASSERT_TRUE(source_file.is_open());
    std::ostringstream source_stream;
    source_stream << source_file.rdbuf();
    const auto source = source_stream.str();

    EXPECT_NE(source.find("block_or_revoke_direct_auth_fingerprint("), std::string::npos);
    EXPECT_NE(source.find("remove_named_devices_by_fingerprint("), std::string::npos);
    EXPECT_NE(source.find("disconnect_client("), std::string::npos);
    EXPECT_NE(source.find("direct_auth_trust_transition_mutex"), std::string::npos);
    EXPECT_NE(source.find("valid_setup_host(host)"), std::string::npos);
  }

  TEST(TlsRequestIdentityBinding, CompileCommandsPlacePeerContextOverlayFirstForProductionAndTest) {
    std::ifstream compile_commands_file(std::string(SUNSHINE_BUILD_DIR) + "/compile_commands.json");
    ASSERT_TRUE(compile_commands_file.is_open());
    nlohmann::json compile_commands;
    ASSERT_NO_THROW(compile_commands = nlohmann::json::parse(compile_commands_file));
    ASSERT_TRUE(compile_commands.is_array());

    std::string production_command;
    std::string test_command;
    for (const auto &entry : compile_commands) {
      if (!entry.is_object() || !entry.contains("file") || !entry.contains("command") ||
          !entry["file"].is_string() || !entry["command"].is_string()) {
        continue;
      }
      auto file = entry["file"].get<std::string>();
      std::replace(file.begin(), file.end(), '\\', '/');
      if (file.ends_with("/src/nvhttp.cpp")) {
        production_command = entry["command"].get<std::string>();
      }
      else if (file.ends_with("/tests/unit/test_tls_request_identity.cpp")) {
        test_command = entry["command"].get<std::string>();
      }
    }

    ASSERT_FALSE(production_command.empty());
    ASSERT_FALSE(test_command.empty());
    for (const auto &command : {production_command, test_command}) {
      const auto overlay_pos = command.find("simple-web-server-peer-context");
      const auto original_third_party_pos = command.find("/third-party");
      ASSERT_NE(overlay_pos, std::string::npos);
      ASSERT_NE(original_third_party_pos, std::string::npos);
      EXPECT_LT(overlay_pos, original_third_party_pos);
    }
  }

}  // namespace
