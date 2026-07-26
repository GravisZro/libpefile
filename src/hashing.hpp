#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#ifdef USE_LIBCRYPTO
#include <openssl/evp.h>
#endif

#ifdef USE_CLI_HASH
#include <unistd.h>
#endif

namespace pefile
{
  namespace hash_helpers
  {

#ifdef USE_LIBCRYPTO

    inline std::string hash_hex(const char* algo_name,
                                 std::span<const std::uint8_t> data,
                                 unsigned int digest_byte_len)
    {
      auto* algo = EVP_get_digestbyname(algo_name);
      if (!algo) return "";

      std::vector<std::uint8_t> digest(digest_byte_len, 0);
      unsigned int outl = 0;

      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, algo, nullptr);
      EVP_DigestUpdate(ctx, data.data(), data.size());
      EVP_DigestFinal_ex(ctx, digest.data(), &outl);
      EVP_MD_CTX_free(ctx);

      std::string hex;
      hex.reserve(2 * outl);
      for (unsigned int i = 0; i < outl; i++)
      {
        hex += std::format("{:02x}", digest[i]);
      }
      return hex;
    }

    inline std::string md5_hex(std::span<const std::uint8_t> data)
    {
      return hash_hex("MD5", data, 16);
    }

    inline std::string sha1_hex(std::span<const std::uint8_t> data)
    {
      return hash_hex("SHA1", data, 20);
    }

    inline std::string sha256_hex(std::span<const std::uint8_t> data)
    {
      return hash_hex("SHA256", data, 32);
    }

    inline std::string sha512_hex(std::span<const std::uint8_t> data)
    {
      return hash_hex("SHA512", data, 64);
    }

#elif defined(USE_CLI_HASH)

    namespace
    {

      inline std::string run_hash_cli(const char* tool_path,
                                       std::span<const std::uint8_t> data)
      {
        if (!tool_path || tool_path[0] == '\0') return "";

        std::string tmpfile = "/tmp/pefile_hash_XXXXXX";
        int fd = mkstemps(tmpfile.data(), 0);
        if (fd < 0) return "";

        std::ofstream ofs(tmpfile, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        ofs.close();
        close(fd);

        std::string cmd = std::string(tool_path) + " < " + tmpfile + " 2>/dev/null";
        FILE* fp = popen(cmd.c_str(), "r");
        if (!fp)
        {
          std::remove(tmpfile.c_str());
          return "";
        }

        char buffer[256];
        std::string output;
        while (std::fgets(buffer, sizeof(buffer), fp)) output += buffer;
        pclose(fp);
        std::remove(tmpfile.c_str());

        auto space_pos = output.find(' ');
        if (space_pos != std::string::npos) return output.substr(0, space_pos);
        auto nl_pos = output.find('\n');
        if (nl_pos != std::string::npos) return output.substr(0, nl_pos);
        return output;
      }

    } // anonymous namespace

#ifdef MD5SUM_EXECUTABLE
    inline std::string md5_hex(std::span<const std::uint8_t> data)
    {
      return run_hash_cli(MD5SUM_EXECUTABLE, data);
    }
#endif

#ifdef SHA1SUM_EXECUTABLE
    inline std::string sha1_hex(std::span<const std::uint8_t> data)
    {
      return run_hash_cli(SHA1SUM_EXECUTABLE, data);
    }
#endif

#ifdef SHA256SUM_EXECUTABLE
    inline std::string sha256_hex(std::span<const std::uint8_t> data)
    {
      return run_hash_cli(SHA256SUM_EXECUTABLE, data);
    }
#endif

#ifdef SHA512SUM_EXECUTABLE
    inline std::string sha512_hex(std::span<const std::uint8_t> data)
    {
      return run_hash_cli(SHA512SUM_EXECUTABLE, data);
    }
#endif

#else
#error "No hashing backend available: define USE_LIBCRYPTO or USE_CLI_HASH"
#endif

    inline std::string md5_hex(const std::string& s)
    {
      return md5_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
    }

    inline std::string sha1_hex(const std::string& s)
    {
      return sha1_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
    }

    inline std::string sha256_hex(const std::string& s)
    {
      return sha256_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
    }

    inline std::string sha512_hex(const std::string& s)
    {
      return sha512_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
    }

  } // namespace hash_helpers
} // namespace pefile
