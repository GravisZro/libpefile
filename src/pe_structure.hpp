#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <span>
#include <unordered_map>
#include <functional>
#include <variant>

namespace pefile {

struct StructureField {
    std::string name;
    std::string format;
    std::size_t size = 0;
    bool is_union = false;
    std::vector<std::string> union_names;
};

class Structure {
public:
    Structure() = default;

    explicit Structure(const std::string& name,
                       std::vector<StructureField> fields,
                       std::size_t file_offset = 0)
        : name_(name), fields_(std::move(fields)), file_offset_(file_offset) {
        compute_offsets();
    }

    void unpack(std::span<const std::uint8_t> data);
    std::vector<std::uint8_t> pack() const;

    const std::string& name() const { return name_; }
    std::size_t sizeof_structure() const { return format_length_; }
    std::size_t file_offset() const { return file_offset_; }
    void set_file_offset(std::size_t offset) { file_offset_ = offset; }

    std::size_t get_field_absolute_offset(const std::string& field_name) const;
    std::size_t get_field_relative_offset(const std::string& field_name) const;

    std::int64_t get(const std::string& field_name) const;
    void set(const std::string& field_name, std::int64_t value);
    std::string get_string(const std::string& field_name) const;
    void set_string(const std::string& field_name, const std::string& value);

    bool all_zeroes() const;
    std::vector<std::string> dump(int indentation = 0) const;
    std::unordered_map<std::string, std::int64_t> dump_dict() const;

    const std::vector<StructureField>& fields() const { return fields_; }

private:
    void compute_offsets();
    std::size_t parse_format_size(const std::string& fmt) const;

    std::string name_;
    std::vector<StructureField> fields_;
    std::size_t file_offset_ = 0;
    std::size_t format_length_ = 0;
    std::unordered_map<std::string, std::size_t> field_offsets_;
    std::vector<std::uint8_t> data_;
};

class StructureWithBitfields : public Structure {
public:
    using Structure::Structure;

    void unpack(std::span<const std::uint8_t> data);
    std::vector<std::uint8_t> pack() const;

private:
    void unpack_bitfield_attributes();
    void pack_bitfield_attributes();

    std::unordered_map<std::string, std::size_t> extended_keys_;
    std::vector<std::pair<std::string, std::vector<std::string>>> compound_fields_;
};

} // namespace pefile
