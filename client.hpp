#pragma once

#include <span>
#include <vector>

#include <openssl/ssl.h>

class Client {
public:
    Client();
    void Start();
    void Cycle();
    void FromServer(std::span<std::byte>);
    bool Connected() const { return m_connected; }

private:
    void Flush();

    SSL_CTX *m_ctx;
    SSL *m_ssl;
    SSL *m_stream{nullptr};
    BIO *m_net_bio;

    std::array<std::byte, 1500> m_buffer;
    bool m_connected{false};

    std::vector<std::vector<std::byte>> m_rx_queue;
};
