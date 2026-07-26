#pragma once

#include <string>
#include <span>
#include <cstdint>

#include "hashing.hpp"

namespace test_hash {

using pefile::hash_helpers::md5_hex;
using pefile::hash_helpers::sha1_hex;
using pefile::hash_helpers::sha256_hex;
using pefile::hash_helpers::sha512_hex;

} // namespace test_hash
