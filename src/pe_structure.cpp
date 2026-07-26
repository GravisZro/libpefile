#include "pe_structure.hpp"
#include <cstring>
#include <stdexcept>

namespace pefile {

namespace {

std::size_t parse_format_char_size(char c) {
    switch (c) {
        case 'x': case 'c': case 'b': case 'B': case 's': return 1;
        case 'h': case 'H': return 2;
        case 'i': case 'I': case 'l': case 'L': case 'f': return 4;
        case 'q': case 'Q': case 'd': return 8;
        default: return 0;
    }
}

std::int64_t read_value(std::span<const std::uint8_t> data, std::size_t offset, std::size_t size, bool is_signed) {
    if (offset + size > data.size()) return 0;
    std::int64_t result = 0;
    std::memcpy(&result, data.data() + offset, size);
    if (is_signed) {
        switch (size) {
            case 1: result = static_cast<std::int8_t>(result); break;
            case 2: result = static_cast<std::int16_t>(result); break;
            case 4: result = static_cast<std::int32_t>(result); break;
        }
    } else {
        switch (size) {
            case 1: result = static_cast<std::uint8_t>(result); break;
            case 2: result = static_cast<std::uint16_t>(result); break;
            case 4: result = static_cast<std::uint32_t>(result); break;
        }
    }
    return result;
}

void write_value(std::vector<std::uint8_t>& data, std::size_t offset, std::int64_t value, std::size_t size) {
    if (offset + size > data.size()) {
        data.resize(offset + size, 0);
    }
    std::memcpy(data.data() + offset, &value, size);
}

} // anonymous namespace

void Structure::compute_offsets() {
    format_length_ = 0;
    field_offsets_.clear();

    for (const auto& field : fields_) {
        if (field.is_union) {
            std::size_t max_size = 0;
            for (const auto& uname : field.union_names) {
                auto it = field_offsets_.find(uname);
                if (it != field_offsets_.end()) {
                    auto fit = std::find_if(fields_.begin(), fields_.end(),
                        [&](const StructureField& f) { return f.name == uname; });
                    if (fit != fields_.end()) {
                        max_size = std::max(max_size, parse_format_size(fit->format));
                    }
                }
            }
            field_offsets_[field.name] = format_length_;
            format_length_ += max_size > 0 ? max_size : parse_format_size(field.format);
        } else {
            field_offsets_[field.name] = format_length_;
            format_length_ += parse_format_size(field.format);
        }
    }
}

std::size_t Structure::parse_format_size(const std::string& fmt) const {
    if (fmt.empty()) return 0;
    std::size_t i = 0;
    std::size_t count = 0;

    while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i]))) {
        count = count * 10 + (fmt[i] - '0');
        i++;
    }

    if (i >= fmt.size()) return 0;

    std::size_t elem_size = parse_format_char_size(fmt[i]);
    if (elem_size == 0) return 0;

    return (count > 0 ? count : 1) * elem_size;
}

std::size_t Structure::get_field_absolute_offset(const std::string& field_name) const {
    auto it = field_offsets_.find(field_name);
    if (it == field_offsets_.end()) return 0;
    return file_offset_ + it->second;
}

std::size_t Structure::get_field_relative_offset(const std::string& field_name) const {
    auto it = field_offsets_.find(field_name);
    if (it == field_offsets_.end()) return 0;
    return it->second;
}

void Structure::unpack(std::span<const std::uint8_t> data) {
    data_.assign(data.begin(), data.end());
}

std::vector<std::uint8_t> Structure::pack() const {
    return data_;
}

std::int64_t Structure::get(const std::string& field_name) const {
    auto it = field_offsets_.find(field_name);
    if (it == field_offsets_.end()) return 0;

    auto fit = std::find_if(fields_.begin(), fields_.end(),
        [&](const StructureField& f) { return f.name == field_name; });
    if (fit == fields_.end()) return 0;

    std::size_t size = parse_format_size(fit->format);
    bool is_signed = (fit->format.back() == 'b' || fit->format.back() == 'h' ||
                      fit->format.back() == 'i' || fit->format.back() == 'l');
    return read_value(data_, it->second, size, is_signed);
}

void Structure::set(const std::string& field_name, std::int64_t value) {
    auto it = field_offsets_.find(field_name);
    if (it == field_offsets_.end()) return;

    auto fit = std::find_if(fields_.begin(), fields_.end(),
        [&](const StructureField& f) { return f.name == field_name; });
    if (fit == fields_.end()) return;

    std::size_t size = parse_format_size(fit->format);
    write_value(data_, it->second, value, size);
}

std::string Structure::get_string(const std::string& field_name) const {
    auto it = field_offsets_.find(field_name);
    if (it == field_offsets_.end()) return "";

    auto fit = std::find_if(fields_.begin(), fields_.end(),
        [&](const StructureField& f) { return f.name == field_name; });
    if (fit == fields_.end()) return "";

    std::size_t size = parse_format_size(fit->format);
    if (it->second + size > data_.size()) return "";
    return std::string(reinterpret_cast<const char*>(data_.data() + it->second), size);
}

void Structure::set_string(const std::string& field_name, const std::string& value) {
    auto it = field_offsets_.find(field_name);
    if (it == field_offsets_.end()) return;

    auto fit = std::find_if(fields_.begin(), fields_.end(),
        [&](const StructureField& f) { return f.name == field_name; });
    if (fit == fields_.end()) return;

    std::size_t size = parse_format_size(fit->format);
    if (it->second + size > data_.size()) {
        data_.resize(it->second + size, 0);
    }
    std::size_t copy_len = std::min(value.size(), size);
    std::memcpy(data_.data() + it->second, value.data(), copy_len);
    if (copy_len < size) {
        std::memset(data_.data() + it->second + copy_len, 0, size - copy_len);
    }
}

bool Structure::all_zeroes() const {
    return std::all_of(data_.begin(), data_.end(), [](std::uint8_t b) { return b == 0; });
}

std::vector<std::string> Structure::dump(int indentation) const {
    std::vector<std::string> result;
    std::string indent(indentation * 2, ' ');

    for (const auto& field : fields_) {
        auto it = field_offsets_.find(field.name);
        if (it == field_offsets_.end()) continue;

        auto fit = std::find_if(fields_.begin(), fields_.end(),
            [&](const StructureField& f) { return f.name == field.name; });
        if (fit == fields_.end()) continue;

        std::size_t size = parse_format_size(fit->format);
        std::int64_t value = 0;
        if (size <= 8) {
            value = read_value(data_, it->second, size,
                fit->format.back() == 'b' || fit->format.back() == 'h' ||
                fit->format.back() == 'i' || fit->format.back() == 'l');
        }

        char buf[256];
        if (fit->format.back() == 's') {
            std::string str(reinterpret_cast<const char*>(data_.data() + it->second),
                           std::min(size, data_.size() - it->second));
            std::snprintf(buf, sizeof(buf), "%s%-30s : (String) %s",
                         indent.c_str(), field.name.c_str(), str.c_str());
        } else if (fit->format == "x") {
            std::snprintf(buf, sizeof(buf), "%s%-30s : (Padding) 0x%X",
                         indent.c_str(), field.name.c_str(), static_cast<unsigned>(value));
        } else {
            std::snprintf(buf, sizeof(buf), "%s%-30s : 0x%llX (%lld)",
                         indent.c_str(), field.name.c_str(),
                         static_cast<unsigned long long>(value),
                         static_cast<long long>(value));
        }
        result.push_back(buf);
    }
    return result;
}

std::unordered_map<std::string, std::int64_t> Structure::dump_dict() const {
    std::unordered_map<std::string, std::int64_t> result;
    for (const auto& field : fields_) {
        result[field.name] = get(field.name);
    }
    return result;
}

void StructureWithBitfields::unpack(std::span<const std::uint8_t> data) {
    Structure::unpack(data);
}

std::vector<std::uint8_t> StructureWithBitfields::pack() {
    pack_bitfield_attributes();
    return Structure::pack();
}

void StructureWithBitfields::unpack_bitfield_attributes() {
}

void StructureWithBitfields::pack_bitfield_attributes() {
}

} // namespace pefile
