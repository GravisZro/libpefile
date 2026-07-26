#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace pefile
{

  class PE;

  class SignatureDatabase
  {
  public:
    SignatureDatabase() = default;
    explicit SignatureDatabase(const std::string& filename);
    explicit SignatureDatabase(std::span<const uint8_t> data);

    void load(const std::string& filename);
    void load(std::span<const uint8_t> data);

    std::string match(const PE& pe, bool ep_only = true, bool section_start_only = false) const;
    std::vector<std::pair<uint32_t, std::string> > match_all(const PE& pe,
                                                                  bool ep_only = true,
                                                                  bool section_start_only = false) const;

    std::string match_data(std::span<const uint8_t> code_data,
                           bool ep_only = true,
                           bool section_start_only = false) const;

    std::string generate_ep_signature(const PE& pe, const std::string& name, size_t sig_length) const;
    std::vector<std::string> generate_section_signatures(const PE& pe,
                                                         const std::string& name,
                                                         size_t sig_length) const;

  private:
    struct TrieNode
    {
      std::unordered_map<uint8_t, std::shared_ptr<TrieNode> > children;
      std::vector<std::string> packer_names;
      bool is_wildcard_child = false;
    };

    using TrieTree = std::shared_ptr<TrieNode>;

    TrieTree m_signature_tree_ep_only_true;
    TrieTree m_signature_tree_ep_only_false;
    TrieTree m_signature_tree_section_start;

    void load_internal(std::string_view data);
    std::vector<std::vector<std::string> > match_signature_tree(const TrieTree& tree,
                                                                std::span<const uint8_t> data,
                                                                size_t depth) const;
  };

  bool is_probably_packed(const PE& pe, double section_entropy = 7.4, double packed_threshold = 0.2);

} // namespace pefile
