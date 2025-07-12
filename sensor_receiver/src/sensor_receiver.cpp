#include <iostream>
#include <sys/dispatch.h>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>      // socket(), connect(), send()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <sstream>
#include <chrono>
#include <thread>

#define SERVER_NAME "SENSOR_CHANNEL"   // QNX channel name for IPC
#define TCP_SERVER_IP "192.168.56.1"  // WINDOWS host IP
#define TCP_SERVER_PORT 9000 		   // TCP port used for TLS

struct SensorData {
    int temperature;
    int speed;
    float gps_lat;
    float gps_lon;
};

// Initialize OpenSSL and create SSL context
SSL_CTX* initialize_ssl_context() {
    SSL_library_init();               // Legacy OpenSSL init
    SSL_load_error_strings();		  // Load human-readable error strings
    OpenSSL_add_all_algorithms();	  // Enable all ciphers, digests
    const SSL_METHOD* method = TLS_client_method();  // TLS client mode
    SSL_CTX* ctx = SSL_CTX_new(method);				// Create SSL context for TLS
    return ctx;
}

bool aes_encrypt(const unsigned char* plaintext, int plaintext_len,
                 const unsigned char* key, const unsigned char* iv,
                 unsigned char* ciphertext, int& ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool generate_cmac(const unsigned char* data, size_t data_len,
                   const unsigned char* key, unsigned char* mac, size_t& mac_len) {
    CMAC_CTX* ctx = CMAC_CTX_new();
    if (!ctx) return false;

    if (1 != CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) {
        CMAC_CTX_free(ctx);
        return false;
    }

    if (1 != CMAC_Update(ctx, data, data_len)) {
        CMAC_CTX_free(ctx);
        return false;
    }

    if (1 != CMAC_Final(ctx, mac, &mac_len)) {
        CMAC_CTX_free(ctx);
        return false;
    }

    CMAC_CTX_free(ctx);
    return true;
}



// -- Function declarations
bool setup_ssl_connection(SSL_CTX* ctx, int& sockfd, SSL*& ssl);
// -- Function implementation
bool setup_ssl_connection(SSL_CTX* ctx, int& sockfd, SSL*& ssl) {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TCP_SERVER_PORT);
    inet_pton(AF_INET, TCP_SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP connect failed");
        close(sockfd);
        return false;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return false;
    }

    std::cout << "[INFO] Secure TLS connection established.\n";
    return true;
}

// Constants
const int MAX_RETRIES = 5;
const int RETRY_DELAY_SEC = 3;

int main() {
    SSL_CTX* ctx = initialize_ssl_context();
    if (!ctx) {
        std::cerr << "Failed to initialize SSL context\n";
        return 1;
    }

    name_attach_t* attach = name_attach(NULL, SERVER_NAME, 0);
    if (attach == NULL) {
        perror("name_attach failed");
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "Receiver is ready and waiting for messages...\n";

    int sockfd = -1;
    SSL* ssl = nullptr;

    if (!setup_ssl_connection(ctx, sockfd, ssl)) {
        std::cerr << "Initial connection to server failed.\n";
        bool reconnected = false;
                      for (int attempt = 1; attempt <= MAX_RETRIES; ++attempt) {
                          std::cout << "[INFO] Reconnecting... attempt " << attempt << "\n";
                          if (setup_ssl_connection(ctx, sockfd, ssl)) {
                              std::cout << "[INFO] Reconnection successful.\n";
                              reconnected = true;
                              break;
                          }
                          std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                      }

                      if (!reconnected) {
                          std::cerr << "[FATAL] Could not reconnect to server after retries.\n";
                          name_detach(attach, 0);
                                 SSL_CTX_free(ctx);
                                 return 1;

                      }

    }

    while (true) {
        SensorData data;
        int rcvid = MsgReceive(attach->chid, &data, sizeof(data), NULL);
        if (rcvid == -1) {
            perror("MsgReceive failed");
            continue;
        }

        MsgReply(rcvid, 0, NULL, 0);

        // AES Key + IV (128-bit = 16 bytes)
               const unsigned char aes_key[16] = {
                   '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
               };

               const unsigned char aes_iv[16] = {
                   '1','2','3','4','5','6','7','8','9','0','A','B','C','D','E','F'
               };

        std::ostringstream oss;
        oss << "Temp=" << data.temperature
            << ", Speed=" << data.speed
            << ", GPS=(" << data.gps_lat << "," << data.gps_lon << ")";
        std::string msg = oss.str();

        unsigned char ciphertext[128];
        int ciphertext_len = 0;
        if (!aes_encrypt(reinterpret_cast<const unsigned char*>(msg.c_str()), msg.size(),
                         aes_key, aes_iv, ciphertext, ciphertext_len)) {
            std::cerr << "AES encryption failed.\n";
            continue;
        }

        unsigned char cmac_tag[16];
        size_t cmac_len = 0;
        if (!generate_cmac(ciphertext, ciphertext_len, aes_key, cmac_tag, cmac_len)) {
            std::cerr << "CMAC generation failed.\n";
            continue;
        }

        unsigned char final_payload[128 + 16];
        memcpy(final_payload, ciphertext, ciphertext_len);
       // cmac_tag[0] ^= 0xFF; //to_corrupt CMAC
        memcpy(final_payload + ciphertext_len, cmac_tag, cmac_len);
        int total_len = ciphertext_len + cmac_len;

        int sent = SSL_write(ssl, final_payload, total_len);
        int attempts = 0;

        while (sent <= 0 && attempts < MAX_RETRIES) {
            std::cerr << "[WARNING] SSL write failed (attempt " << (attempts + 1) << "). Reconnecting...\n";
            ERR_print_errors_fp(stderr);

            // Clean up previous connection
            if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
            }
            if (sockfd >= 0) {
                close(sockfd);
                sockfd = -1;
            }

            std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
            attempts++;

            if (setup_ssl_connection(ctx, sockfd, ssl)) {
                std::cout << "[INFO] Reconnection successful on attempt " << attempts << "\n";
                // Retry sending the same message after reconnect
                sent = SSL_write(ssl, final_payload, total_len);
            }
        }

        if (sent <= 0) {
            std::cerr << "[FATAL] Could not send data after " << MAX_RETRIES << " retries.\n";
            break;
        }


        std::cout << "[SENT] Temp=" << data.temperature
                  << ", Speed=" << data.speed
                  << ", GPS=(" << data.gps_lat << "," << data.gps_lon << ")\n";
    }

    name_detach(attach, 0);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sockfd >= 0)
        close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
