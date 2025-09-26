#include "client.hpp"

#include <stdexcept>

#include "server.hpp"

extern Server *global_server;

Client::Client()
{
    m_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!m_ctx) {
        throw std::runtime_error("SSL_CTX_new");
    }
    if (SSL_CTX_use_certificate_chain_file(m_ctx, "cert") <= 0) {
        throw std::runtime_error("SSL_CTX_use_certificate_chain_file");
    }
    if (SSL_CTX_use_PrivateKey_file(m_ctx, "key", SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("SSL_CTX_use_PrivateKey_file");
    }
    if (SSL_CTX_check_private_key(m_ctx) != 1) {
        throw std::runtime_error("SSL_CTX_check_private_key");
    }
    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) throw std::runtime_error("SSL_new");
    SSL_set_connect_state(m_ssl);  // TODO: maybe remove
    BIO *internal_bio;
    if (BIO_new_bio_dgram_pair(&internal_bio, 0, &m_net_bio, 0) <= 0)
        throw std::runtime_error("BIO_new_bio_dgram_pair");
    SSL_set_bio(m_ssl, internal_bio, internal_bio);
    static const uint8_t alpn[3] = {2, 'h', '3'};
    if (SSL_set_alpn_protos(m_ssl, alpn, sizeof(alpn)))
        throw std::runtime_error("SSL_set_alpn_protos");
    if (!SSL_set_default_stream_mode(m_ssl, SSL_DEFAULT_STREAM_MODE_NONE))
        throw std::runtime_error("SSL_set_default_stream_mode");
}
void Client::Start() { Flush(); }
void Client::Cycle()
{
    // fprintf(stderr, "[CLIENT] Cycle\n");

    for (const auto &d : m_rx_queue) {
        if (BIO_write(m_net_bio, d.data(), d.size()) < (int)d.size()) {
            throw std::runtime_error("BIO_write short write");
        }
        Flush();
    }
    m_rx_queue.clear();
}
void Client::FromServer(std::span<std::byte> data)
{
    // fprintf(stderr, "Server -> Client %4ld\n", data.size());
    std::vector<std::byte> d{data.begin(), data.end()};
    m_rx_queue.emplace_back(std::move(d));
}
void Client::Flush()
{
    if (!m_connected) {
        const auto ret = SSL_do_handshake(m_ssl);
        if (ret == 0)
            throw std::runtime_error("SSL_do_handshake");
        else if (ret == 1) {
            m_connected = true;
            fprintf(stderr, "[CLIENT] Connected\n");
        } else {
            // handhsake still in progress
        }
    }
    if (SSL_handle_events(m_ssl) != 1) {
        throw std::runtime_error("SSL_handle_events");
    }
    while (BIO_pending(m_net_bio)) {
        const auto n = BIO_read(m_net_bio, m_buffer.data(), m_buffer.size());
        if (n <= 0) {
            throw;
        }
        global_server->FromClient({m_buffer.data(), (unsigned)n});
    }
    if (auto new_stream = SSL_accept_stream(m_ssl, SSL_ACCEPT_STREAM_NO_BLOCK); new_stream) {
        fprintf(stderr, "[CLIENT] New stream\n");
        if (m_stream) throw;
        m_stream = new_stream;
    }
    if (m_stream) {
        auto ret = SSL_read(m_stream, m_buffer.data(), m_buffer.size());
        if (ret > 0) {
            fprintf(stderr, "[CLIENT] rx: %d\n", ret);
        }
    }
}
