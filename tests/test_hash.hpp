#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#ifdef USE_CLI_HASH
#include <unistd.h>
#endif

#ifdef USE_LIBCRYPTO
#include <openssl/evp.h>
#endif

namespace test_hash {

#ifdef USE_LIBCRYPTO

inline std::string sha256_hex(std::span<const uint8_t> data) {
    std::array<uint8_t, 32> digest{};
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
    EVP_MD_CTX_free(ctx);

    std::string hex;
    hex.reserve(2 * digest_len);
    for (unsigned int i = 0; i < digest_len; i++) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", digest[i]);
        hex += buf;
    }
    return hex;
}

inline std::string sha1_hex(std::span<const uint8_t> data) {
    std::array<uint8_t, 20> digest{};
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
    EVP_MD_CTX_free(ctx);

    std::string hex;
    hex.reserve(2 * digest_len);
    for (unsigned int i = 0; i < digest_len; i++) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", digest[i]);
        hex += buf;
    }
    return hex;
}

inline std::string sha512_hex(std::span<const uint8_t> data) {
    std::array<uint8_t, 64> digest{};
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
    EVP_MD_CTX_free(ctx);

    std::string hex;
    hex.reserve(2 * digest_len);
    for (unsigned int i = 0; i < digest_len; i++) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", digest[i]);
        hex += buf;
    }
    return hex;
}

#elif defined(USE_CLI_HASH)

namespace {

inline std::string run_hash_cli(const char* tool, const std::string& tool_path,
                                 std::span<const uint8_t> data) {
    std::string tmpfile = "/tmp/pefile_hash_XXXXXX";
    int fd = mkstemps(tmpfile.data(), 0);
    if (fd < 0) return "";

    std::ofstream ofs(tmpfile, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    ofs.close();
    close(fd);

    std::string cmd = tool_path + " < " + tmpfile + " 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        std::remove(tmpfile.c_str());
        return "";
    }

    char buffer[256];
    std::string output;
    while (std::fgets(buffer, sizeof(buffer), fp)) {
        output += buffer;
    }
    pclose(fp);
    std::remove(tmpfile.c_str());

    auto space_pos = output.find(' ');
    if (space_pos != std::string::npos) {
        return output.substr(0, space_pos);
    }
    auto nl_pos = output.find('\n');
    if (nl_pos != std::string::npos) {
        return output.substr(0, nl_pos);
    }
    return output;
}

} // namespace

#ifdef SHA256SUM_EXECUTABLE
inline std::string sha256_hex(std::span<const uint8_t> data) {
    return run_hash_cli("sha256sum", SHA256SUM_EXECUTABLE, data);
}
#endif

#ifdef SHA1SUM_EXECUTABLE
inline std::string sha1_hex(std::span<const uint8_t> data) {
    return run_hash_cli("sha1sum", SHA1SUM_EXECUTABLE, data);
}
#endif

#ifdef SHA512SUM_EXECUTABLE
inline std::string sha512_hex(std::span<const uint8_t> data) {
    return run_hash_cli("sha512sum", SHA512SUM_EXECUTABLE, data);
}
#endif

#else
#error "No hashing backend available: define USE_LIBCRYPTO or USE_CLI_HASH"
#endif

inline std::string sha256_hex(const std::string& s) {
    return sha256_hex(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

inline std::string sha1_hex(const std::string& s) {
    return sha1_hex(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

inline std::string sha512_hex(const std::string& s) {
    return sha512_hex(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

} // namespace test_hash
