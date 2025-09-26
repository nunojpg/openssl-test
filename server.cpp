#include "server.hpp"

#include <stdexcept>

#include <netinet/ip.h>

#include "client.hpp"

extern Client *global_client;
int verify_cb(int, X509_STORE_CTX *) { return 1; }
static const uint8_t alpn[] = {'h', '3'};
static int select_alpn(SSL *, const uint8_t **out, uint8_t *out_len, const uint8_t *, unsigned int,
                       void *)
{
    *out = alpn;
    *out_len = sizeof(alpn);
    return SSL_TLSEXT_ERR_OK;
}

Server::Server()
{
    m_bio_msg_recv.data = m_buf_tx.data();
    m_bio_msg_recv.local = BIO_ADDR_new();
    m_bio_msg_recv.flags = 0;
    m_bio_msg_recv.peer = nullptr;

    m_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
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
    SSL_CTX_set_verify(m_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_cb);
    SSL_CTX_set_alpn_select_cb(m_ctx, select_alpn, nullptr);

    m_server = SSL_new_listener(m_ctx, 0);
    if (!m_server) {
        throw std::runtime_error("SSL_new_listener");
    }
    BIO *bio_internal;
    if (BIO_new_bio_dgram_pair(&m_bio, 0, &bio_internal, 0) != 1) {
        throw std::runtime_error("BIO_new_bio_dgram_pair");
    }

    BIO_dgram_set_caps(bio_internal,
                       BIO_DGRAM_CAP_HANDLES_SRC_ADDR | BIO_DGRAM_CAP_PROVIDES_DST_ADDR);
    BIO_dgram_set_caps(m_bio, BIO_DGRAM_CAP_HANDLES_DST_ADDR);
    BIO_dgram_set_local_addr_enable(m_bio, true);

    SSL_set_bio(m_server, bio_internal, bio_internal);
    if (SSL_set_blocking_mode(m_server, 0) != 1) {
        throw std::runtime_error("SSL_set_blocking_mode");
    }
}
void Server::Cycle()
{
    // fprintf(stderr, "[SERVER] Cycle\n");

    for (auto &d : m_rx_queue) {
        BIO_MSG msg{
            .data = d.data(),
            .data_len = d.size(),
            .peer = nullptr,
            .local = BIO_ADDR_new(),  // this is free'd by BIO_sendmmsg
            .flags = 0,
        };
        struct in_addr ina = {0};
        ina.s_addr = htonl(0x7f000001UL);
        BIO_ADDR_rawmake(msg.local, AF_INET, &ina, sizeof(ina), 0);
        size_t msgs_processed;
        BIO_sendmmsg(m_bio, &msg, sizeof(BIO_MSG), 1, 0, &msgs_processed);
        auto conn = SSL_accept_connection(m_server, 0);  // also performs as SSL_handle_events
        if (conn) {
            m_conn = conn;
            fprintf(stderr, "[SERVER] connection accepted\n");
        }
        if (m_conn) {
            // if (SSL_is_init_finished(m_conn)) {
            //     fprintf(stderr, "[SERVER] connection init finished\n");
            // }
        }
        TxAll();
    }
    m_rx_queue.clear();
    SSL_handle_events(m_server);
    if (m_conn) SSL_handle_events(m_conn);
    if (m_stream) SSL_handle_events(m_stream);

    TxAll();
}
void Server::StartStream()
{
    m_stream = SSL_new_stream(m_conn, 0);
    uint8_t buf = 0;
    SSL_write(m_stream, &buf, 1);
}
void Server::Write()
{
    const char *str = "dasdasds";
    SSL_write(m_stream, str, 2);
    // SSL_write(m_stream, str, 1);
}
void Server::FromClient(const std::span<std::byte> data)
{
    // fprintf(stderr, "Client -> Server %4ld\n", data.size());
    std::vector<std::byte> d{data.begin(), data.end()};
    m_rx_queue.emplace_back(std::move(d));
}
void Server::TxAll()
{
    while (BIO_pending(m_bio)) {
        size_t n;
        m_bio_msg_recv.data_len = m_buf_tx.size();
        if (BIO_recvmmsg(m_bio, &m_bio_msg_recv, sizeof(BIO_MSG), 1, 0, &n) != 1 || n != 1) {
            throw std::runtime_error("error");
        }
        global_client->FromServer({(std ::byte *)m_bio_msg_recv.data, m_bio_msg_recv.data_len});
    }
}