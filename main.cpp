#include <chrono>
#include <thread>

#include "client.hpp"
#include "server.hpp"

/*
Create certs:
openssl req -batch -newkey rsa:2048 -nodes -keyout key -x509 -days 365 -out cert
*/


Server *global_server;
Client *global_client;

int main()
{
    Server server;
    Client client;

    global_server = &server;
    global_client = &client;

    client.Start();

    for (int i = 0; i < 200; ++i) {
        /*
        with 250ms sleep always succeeds
        with 100ms sleep it fails most times
        */
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        client.Cycle();
        server.Cycle();
        if (client.Connected()) break;
    }
    return !client.Connected();
}
