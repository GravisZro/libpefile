#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace pefile
{
  using std::int64_t;
  using std::uint8_t;
  using std::uint16_t;
  using std::uint32_t;
  using std::uint64_t;
  using std::size_t;

  struct StructureField
  {
    std::string name;
    std::string format;
    size_t size = 0;
    bool is_union = false;
    std::vector<std::string> union_names;
  };

  class Structure
  {
  public:
    Structure() = default;

    explicit Structure(const std::string& name,
                       std::vector<StructureField> fields,
                       size_t file_offset = 0)
        : m_name(name), m_fields(std::move(fields)), m_file_offset(file_offset)
    {
      compute_offsets();
    }

    void unpack(std::span<const uint8_t> data);
    std::vector<uint8_t> pack() const;

    const std::string& name() const { return m_name; }
    size_t sizeof_structure() const { return m_format_length; }
    size_t file_offset() const { return m_file_offset; }
    void set_file_offset(size_t offset) { m_file_offset = offset; }

    size_t get_field_absolute_offset(const std::string& field_name) const;
    size_t get_field_relative_offset(const std::string& field_name) const;

    int64_t get(const std::string& field_name) const;
    void set(const std::string& field_name, int64_t value);
    std::string get_string(const std::string& field_name) const;
    void set_string(const std::string& field_name, const std::string& value);

    bool all_zeroes() const;
    std::vector<std::string> dump(int indentation = 0) const;
    std::unordered_map<std::string, int64_t> dump_dict() const;

    const std::vector<StructureField>& fields() const { return m_fields; }

  private:
    void compute_offsets();
    size_t parse_format_size(const std::string& fmt) const;

    std::string m_name;
    std::vector<StructureField> m_fields;
    size_t m_file_offset = 0;
    size_t m_format_length = 0;
    std::unordered_map<std::string, size_t> m_field_offsets;
    std::vector<uint8_t> m_data;
  };

  class StructureWithBitfields : public Structure
  {
  public:
    using Structure::Structure;

    void unpack(std::span<const uint8_t> data);
    std::vector<uint8_t> pack() const;

  private:
    void unpack_bitfield_attributes();
    void pack_bitfield_attributes();

    std::unordered_map<std::string, size_t> m_extended_keys;
    std::vector<std::pair<std::string, std::vector<std::string> > > m_compound_fields;
  };

} // namespace pefile
