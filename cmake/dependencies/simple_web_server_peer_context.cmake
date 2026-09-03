function(sunshine_prepare_simple_web_server_peer_context repository_root binary_root output_variable)
    set(_source_dir "${repository_root}/third-party/Simple-Web-Server")
    set(_overlay_root "${binary_root}/simple-web-server-peer-context")
    set(_overlay_dir "${_overlay_root}/Simple-Web-Server")

    file(REMOVE_RECURSE "${_overlay_dir}")
    file(MAKE_DIRECTORY "${_overlay_dir}")
    file(COPY "${_source_dir}/"
        DESTINATION "${_overlay_dir}"
        FILES_MATCHING PATTERN "*.hpp")

    set(_server_http "${_overlay_dir}/server_http.hpp")
    file(READ "${_server_http}" _http_source)

    set(_connection_marker
"      std::unique_ptr<socket_type> socket; // Socket must be unique_ptr since asio::ssl::stream<asio::ip::tcp::socket> is not movable

      /**")
    set(_connection_replacement
"      std::unique_ptr<socket_type> socket; // Socket must be unique_ptr since asio::ssl::stream<asio::ip::tcp::socket> is not movable

      // Vibepollo connection-owned immutable authentication state. The host
      // binds this once after the TLS handshake and every keep-alive Request
      // on this Connection observes the same shared state.
      std::shared_ptr<const void> user_data;

      /**")
    string(REPLACE "${_connection_marker}" "${_connection_replacement}" _patched_http "${_http_source}")
    if(_patched_http STREQUAL _http_source)
        message(FATAL_ERROR "Simple-Web-Server Connection layout changed; peer-context overlay needs review")
    endif()
    set(_http_source "${_patched_http}")

    set(_request_marker
"      /// Returns query keys with percent-decoded values.
      CaseInsensitiveMultimap parse_query_string() const noexcept {")
    set(_request_replacement
"      /// Returns immutable user state owned by this Request's exact Connection.
      std::shared_ptr<const void> connection_user_data() const noexcept {
        try {
          if(auto connection = this->connection.lock())
            return connection->user_data;
        }
        catch(...) {
        }
        return {};
      }

      /// Binds immutable user state to this Request's exact Connection.
      /// Returns false if the connection is gone or state was already bound.
      bool set_connection_user_data(std::shared_ptr<const void> data) noexcept {
        try {
          if(auto connection = this->connection.lock()) {
            if(connection->user_data)
              return false;
            connection->user_data = std::move(data);
            return true;
          }
        }
        catch(...) {
        }
        return false;
      }

      /// Returns query keys with percent-decoded values.
      CaseInsensitiveMultimap parse_query_string() const noexcept {")
    string(REPLACE "${_request_marker}" "${_request_replacement}" _patched_http "${_http_source}")
    if(_patched_http STREQUAL _http_source)
        message(FATAL_ERROR "Simple-Web-Server Request layout changed; peer-context overlay needs review")
    endif()

    file(WRITE "${_server_http}" "${_patched_http}")
    set(${output_variable} "${_overlay_root}" PARENT_SCOPE)
endfunction()
