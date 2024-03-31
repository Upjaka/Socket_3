#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

int main() {
    SSL_CTX* ctx;
    SSL* ssl;
    const SSL_METHOD* method;
    char hostname[] = "smtp.gmail.com";
    int port = 465;
    const char* user = "alesant999@gmail.com";
    char password[] = "injbuskewpmlrzwi";
    char msg[] = "\r\n Я люблю компьютерные сети!";
    char endmsg[] = "\r\n.\r\n";
    char buffer[100];

    memset(buffer, 0, sizeof(buffer));

    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    int serverAddrSize = sizeof(serverAddr);

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    // Create a TCP socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        std::cerr << "Error creating socket" << std::endl;
        WSACleanup();
        return 1;
    }

    // Resolve IP address and port
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, std::to_string(port).c_str(), &hints, &result);

    // Connect to server
    connect(clientSocket, result->ai_addr, result->ai_addrlen);

    // Initialize SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    // Create SSL structure
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSocket);

    // Perform SSL handshake
    SSL_connect(ssl);

    // Receive initial response from server
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to connection establishment: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send HELO command
    char heloCommand[] = "HELO Alice\r\n";
    SSL_write(ssl, heloCommand, strlen(heloCommand));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to HELO command: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send AUTH LOGIN command
    char loginCommand[] = "AUTH LOGIN\r\n";
    SSL_write(ssl, loginCommand, strlen(loginCommand));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to AUTH LOGIN command: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send base64 encoded username
    char base64_username[] = "YWxlc2FudDk5OUBnbWFpbC5jb20=\r\n";
    SSL_write(ssl, base64_username, strlen(base64_username));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to login: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send base64 encoded password
    char base64_password[] = "aW5qYnVza2V3cG1scnp3aQ==\r\n";
    SSL_write(ssl, base64_password, strlen(base64_password));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to password: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send MAIL FROM command
    char mailFromCommand[] = "MAIL FROM: <alesant999@gmail.com>\r\n";
    SSL_write(ssl, mailFromCommand, strlen(mailFromCommand));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to MAIL FROM command: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send RCPT TO command
    char rcptToCommand[] = "RCPT TO: <alesant-l-99@mail.ru>\r\n";
    SSL_write(ssl, rcptToCommand, strlen(rcptToCommand));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to RCPT TO command: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send DATA command
    char dataCommand[] = "DATA\r\n";
    SSL_write(ssl, dataCommand, strlen(dataCommand));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to DATA command: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send message data
    SSL_write(ssl, msg, strlen(msg));

    // Send message end
    SSL_write(ssl, endmsg, strlen(endmsg));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to message text: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Send QUIT command
    char quitCommand[] = "QUIT\r\n";
    SSL_write(ssl, quitCommand, strlen(quitCommand));
    SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Response to QUIT command: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Close SSL connection and free resources
    SSL_shutdown(ssl);
    closesocket(clientSocket);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}
