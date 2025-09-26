#pragma once

#include <array>
#include <span>
#include <vector>

#include <openssl/ssl.h>

class Server {
public:
    Server();
    void StartStream();
    void Write();
    void Cycle();
    void FromClient(std::span<std::byte>);

private:
    void TxAll();

    SSL_CTX *m_ctx;
    SSL *m_server;
    SSL *m_conn = nullptr;
    SSL *m_stream = nullptr;
    BIO *m_bio;
    BIO_MSG m_bio_msg_recv;

    std::array<std::byte, 1500> m_buf_tx;

    std::vector<std::vector<std::byte>> m_rx_queue;
};
