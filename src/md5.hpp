#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <span>

namespace pefile {

class MD5 {
public:
    MD5() { init(); }

    void update(std::span<const std::uint8_t> data) {
        for (auto byte : data) {
            buffer_[byte_count_ / 4 % 16] |=
                static_cast<std::uint32_t>(byte) << ((byte_count_ % 4) * 8);
            byte_count_++;
            if (byte_count_ % 64 == 0) {
                transform();
                std::memset(buffer_, 0, sizeof(buffer_));
            }
        }
    }

    void update(const std::string& s) {
        update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
    }

    std::array<std::uint8_t, 16> digest() {
        std::uint32_t bits[2] = {
            static_cast<std::uint32_t>(byte_count_ * 8),
            static_cast<std::uint32_t>(byte_count_ >> 29)
        };

        auto padding = std::uint8_t(0x80);
        std::size_t pad_len = (55 - byte_count_ % 64 + 64) % 64 + 1;
        std::vector<std::uint8_t> pad_data(pad_len, 0);
        pad_data[0] = padding;
        update(pad_data);

        std::memcpy(buffer_, bits, 8);
        transform();

        std::array<std::uint8_t, 16> result;
        for (int i = 0; i < 4; i++) {
            result[i * 4 + 0] = static_cast<std::uint8_t>((state_[i]) & 0xFF);
            result[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
            result[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
            result[i * 4 + 3] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
        }
        return result;
    }

    std::string hexdigest() {
        auto d = digest();
        char hex[33] = {};
        for (int i = 0; i < 16; i++) {
            std::snprintf(hex + i * 2, 3, "%02x", d[i]);
        }
        return std::string(hex);
    }

private:
    void init() {
        state_ = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
        byte_count_ = 0;
        std::memset(buffer_, 0, sizeof(buffer_));
    }

    static std::uint32_t leftrotate(std::uint32_t x, std::uint32_t c) {
        return (x << c) | (x >> (32 - c));
    }

    void transform() {
        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];

        for (int i = 0; i < 64; i++) {
            std::uint32_t f, g;
            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }

            std::uint32_t temp = d;
            d = c;
            c = b;
            b += leftrotate(a + f + k_[i] + buffer_[g], s_[i]);
            a = temp;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }

    std::array<std::uint32_t, 4> state_;
    std::uint32_t buffer_[16];
    std::uint64_t byte_count_;

    static constexpr std::uint32_t k_[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };

    static constexpr std::uint32_t s_[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };
};

} // namespace pefile
