#include "pe_utils.hpp"
#include "pefile.hpp"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <format>
#include <fstream>
#include <regex>
#include <sstream>

namespace pefile {

SignatureDatabase::SignatureDatabase(const std::string& filename) {
    load(filename);
}

SignatureDatabase::SignatureDatabase(std::span<const uint8_t> data) {
    load(data);
}

void SignatureDatabase::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    load_internal(content);
}

void SignatureDatabase::load(std::span<const uint8_t> data) {
    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    load_internal(content);
}

void SignatureDatabase::load_internal(std::string_view data) {
    static const std::regex sig_regex(
        R"(\[(.*?)\]\s+?signature\s*=\s*(.*?)(\s+\?\?)*\s*ep_only\s*=\s*(\w+)(?:\s*section_start_only\s*=\s*(\w+)|))",
        std::regex::ECMAScript);

    std::string content(data);
    auto begin = std::sregex_iterator(content.begin(), content.end(), sig_regex);
    auto end = std::sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        auto& match = *it;
        std::string name = match[1].str();
        std::string signature = match[2].str();
        bool ep_only = match[4].str() == "True" || match[4].str() == "true";
        bool section_start_only = match.size() > 5 &&
            (match[5].str() == "True" || match[5].str() == "true");

        // Remove spaces from signature
        signature.erase(std::remove(signature.begin(), signature.end(), ' '), signature.end());

        auto& target_tree = section_start_only ? m_signature_tree_section_start :
            (ep_only ? m_signature_tree_ep_only_true : m_signature_tree_ep_only_false);

        if (!target_tree) {
            target_tree = std::make_shared<TrieNode>();
        }

        auto current = target_tree;
        for (size_t i = 0; i + 1 < signature.size(); i += 2) {
            std::string byte_str = signature.substr(i, 2);
            if (byte_str == "??") {
                // Wildcard: use a special child
                if (!current->children.count(0xFF)) {
                    auto child = std::make_shared<TrieNode>();
                    child->is_wildcard_child = true;
                    current->children[0xFF] = child;
                }
                current = current->children[0xFF];
            } else {
                uint8_t byte_val = 0;
                auto [ptr, ec] = std::from_chars(byte_str.data(),
                    byte_str.data() + 2, byte_val, 16);
                if (ec != std::errc()) continue;
                if (!current->children.count(byte_val)) {
                    current->children[byte_val] = std::make_shared<TrieNode>();
                }
                current = current->children[byte_val];
            }
        }
        current->packer_names.push_back(name);
    }
}

std::string SignatureDatabase::match(const PE& pe, bool ep_only, bool section_start_only) const {
    auto results = match_all(pe, ep_only, section_start_only);
    if (results.empty()) return "";
    return results[0].second;
}

std::vector<std::pair<uint32_t, std::string>> SignatureDatabase::match_all(
    const PE& pe, bool ep_only, bool section_start_only) const {

    std::vector<std::pair<uint32_t, std::string>> results;

    auto overlay_offset = pe.get_overlay_data_start_offset();
    auto max_offset = overlay_offset.value_or(static_cast<uint32_t>(
        pe.dos_header().e_lfanew + 4 + pe.file_header().SizeOfOptionalHeader));

    const TrieTree* tree = &m_signature_tree_ep_only_true;
    if (section_start_only) {
        tree = &m_signature_tree_section_start;
    } else if (!ep_only) {
        tree = &m_signature_tree_ep_only_false;
    }

    if (!*tree) return results;

    auto ep_offset = pe.get_offset_from_rva(
        pe.is_pe32_plus() ? pe.optional_header_64().AddressOfEntryPoint :
                           pe.optional_header_32().AddressOfEntryPoint);

    if (ep_only) {
        auto data = pe.get_data(ep_offset);
        auto matches = match_signature_tree(*tree, data, 0);
        for (auto& m : matches) {
            if (!m.empty()) {
                results.emplace_back(ep_offset, m[0]);
            }
        }
    } else if (section_start_only) {
        for (auto& section : pe.sections()) {
            if (section.PointerToRawData == 0) continue;
            auto data = pe.get_data(section.PointerToRawData);
            auto matches = match_signature_tree(*tree, data, 0);
            for (auto& m : matches) {
                if (!m.empty()) {
                    results.emplace_back(section.PointerToRawData, m[0]);
                }
            }
        }
    } else {
        for (uint32_t offset = 0x200; offset < max_offset; offset++) {
            auto data = pe.get_data(offset, std::min(max_offset - offset, 256u));
            auto matches = match_signature_tree(*tree, data, 0);
            for (auto& m : matches) {
                if (!m.empty()) {
                    results.emplace_back(offset, m[0]);
                }
            }
        }
    }

    return results;
}

std::string SignatureDatabase::match_data(std::span<const uint8_t> code_data,
                                           bool ep_only, bool /*section_start_only*/) const {
    const TrieTree* tree = ep_only ? &m_signature_tree_ep_only_true : &m_signature_tree_ep_only_false;
    if (!*tree) return "";

    auto matches = match_signature_tree(*tree, code_data, 0);
    if (!matches.empty() && !matches[0].empty()) {
        return matches[0][0];
    }
    return "";
}

std::vector<std::vector<std::string>> SignatureDatabase::match_signature_tree(
    const TrieTree& tree, std::span<const uint8_t> data, size_t depth) const {

    std::vector<std::vector<std::string>> results;

    if (!tree) return results;

    if (!tree->packer_names.empty()) {
        results.push_back(tree->packer_names);
    }

    if (depth >= data.size()) return results;

    // Try regular byte match
    auto it = tree->children.find(data[depth]);
    if (it != tree->children.end()) {
        auto sub = match_signature_tree(it->second, data, depth + 1);
        results.insert(results.end(), sub.begin(), sub.end());
    }

    // Try wildcard match
    auto wc = tree->children.find(0xFF);
    if (wc != tree->children.end() && wc->second->is_wildcard_child) {
        auto sub = match_signature_tree(wc->second, data, depth + 1);
        results.insert(results.end(), sub.begin(), sub.end());
    }

    return results;
}

std::string SignatureDatabase::generate_ep_signature(const PE& pe, const std::string& name,
                                                      size_t sig_length) const {
    auto ep = pe.get_offset_from_rva(
        pe.is_pe32_plus() ? pe.optional_header_64().AddressOfEntryPoint :
                           pe.optional_header_32().AddressOfEntryPoint);

    auto data = pe.get_data(ep, sig_length);
    std::ostringstream ss;
    ss << "[" << name << "]\n";
    ss << "signature = ";
    for (size_t i = 0; i < data.size(); i++) {
        if (i > 0) ss << " ";
        ss << std::format("{:02X}", data[i]);
    }
    ss << "\n";
    ss << "ep_only = True\n";
    return ss.str();
}

std::vector<std::string> SignatureDatabase::generate_section_signatures(
    const PE& pe, const std::string& name, size_t sig_length) const {

    std::vector<std::string> results;
    for (auto& section : pe.sections()) {
        if (section.PointerToRawData == 0) continue;
        auto data = pe.get_data(section.PointerToRawData, sig_length);
        std::ostringstream ss;
        ss << "[" << name << "_" << section.name() << "]\n";
        ss << "signature = ";
        for (size_t i = 0; i < data.size(); i++) {
            if (i > 0) ss << " ";
            ss << std::format("{:02X}", data[i]);
        }
        ss << "\n";
        ss << "ep_only = False\n";
        results.push_back(ss.str());
    }
    return results;
}

bool is_probably_packed(const PE& pe, double section_entropy, double packed_threshold) {
    uint64_t total_size = 0;
    uint64_t high_entropy_size = 0;

    for (auto& section : pe.sections()) {
        auto size = static_cast<uint64_t>(section.SizeOfRawData);
        total_size += size;

        if (section.SizeOfRawData == 0) continue;

        auto data = pe.get_data(section.VirtualAddress, section.SizeOfRawData);
        size_t freq[256] = {};

        for (auto byte : data) {
            freq[byte]++;
        }

        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] == 0) continue;
            double p = static_cast<double>(freq[i]) / data.size();
            entropy -= p * std::log2(p);
        }

        if (entropy >= section_entropy) {
            high_entropy_size += size;
        }
    }

    if (total_size == 0) return false;
    return static_cast<double>(high_entropy_size) / total_size > packed_threshold;
}

} // namespace pefile
