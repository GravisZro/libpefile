#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace pefile::ordlookup {

using OrdinalMap = std::unordered_map<std::uint16_t, std::string>;

const OrdinalMap& get_ordinals(std::string_view dll_name);
const OrdinalMap& get_imphash_ordinals(std::string_view dll_name);

std::string ordinal_lookup(std::string_view dll_name, std::uint16_t ordinal, bool make_name = true);
std::string imphash_ordinal_lookup(std::string_view dll_name, std::uint16_t ordinal, bool make_name = true);

} // namespace pefile::ordlookup
