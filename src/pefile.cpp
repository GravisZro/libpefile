#include "pefile.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <numeric>
#include <set>
#include <sstream>
#include <functional>

#include "ordlookup.hpp"
#include "md5.hpp"

namespace pefile {

namespace {
constexpr std::size_t MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69;
constexpr int MAX_SIMULTANEOUS_ERRORS = 3;
constexpr std::size_t MAX_ALLOWED_RESOURCE_ENTRIES = 4096;
constexpr std::size_t MAX_REPEATED_ADDRESSES = 15;
constexpr std::size_t MAX_ADDRESS_SPREAD = 128 * 1024 * 1024;
constexpr std::uint64_t ADDR_4GB = 0x100000000ULL;
}

// UnwindInfo parse (variable-size struct)
UnwindInfo UnwindInfo::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    UnwindInfo h{};
    if (data.size() - offset < 4) return h;
    auto p = data.data() + offset;
    h.Version = *p++;
    h.Flags = *p++;
    h.SizeOfProlog = *p++;
    h.CountOfCodes = *p++;
    if (data.size() - offset >= 6) {
        h.FrameRegister = *p++;
        h.FrameOffset = *p++;
    }
    for (int i = 0; i < h.CountOfCodes && (p - data.data()) < static_cast<long long>(data.size()); i++) {
        std::uint16_t code;
        std::memcpy(&code, p, 2); p += 2;
        h.UnwindCodes.push_back(code);
    }
    if (h.chained() && (p - data.data()) + 4 <= static_cast<long long>(data.size())) {
        p += 4;
    }
    return h;
}


// ============================================================================
// PE class implementation
// ============================================================================

PE::PE(const std::string& filename, bool fast_load) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw PEFormatError("Unable to open file: " + filename);
    }
    auto size = file.tellg();
    file.seekg(0);
    data_.resize(static_cast<std::size_t>(size));
    file.read(reinterpret_cast<char*>(data_.data()), size);
    data_size_ = data_.size();
    parse();
    if (!fast_load) {
        full_load();
    }
}

PE::PE(std::span<const std::uint8_t> data, bool fast_load) {
    data_.assign(data.begin(), data.end());
    data_size_ = data_.size();
    parse();
    if (!fast_load) {
        full_load();
    }
}

PE::~PE() = default;
PE::PE(PE&&) noexcept = default;
PE& PE::operator=(PE&&) noexcept = default;

void PE::parse() {
    if (data_size_ < 64) {
        throw PEFormatError("File too small for DOS header");
    }

    dos_header_ = DosHeader::parse(data_, 0);
    if (dos_header_.e_magic != IMAGE_DOS_SIGNATURE) {
        throw PEFormatError("Invalid DOS signature");
    }

    auto nt_headers_offset = static_cast<std::size_t>(dos_header_.e_lfanew);
    if (nt_headers_offset + 4 > data_size_) {
        throw PEFormatError("Invalid NT headers offset");
    }

    std::uint32_t signature = read_packed<std::uint32_t>(data_, nt_headers_offset);

    if ((0xFFFF & signature) == IMAGE_NE_SIGNATURE)
        throw PEFormatError("Invalid NT Headers signature. Probably a NE file");
    if ((0xFFFF & signature) == IMAGE_LE_SIGNATURE)
        throw PEFormatError("Invalid NT Headers signature. Probably a LE file");
    if ((0xFFFF & signature) == IMAGE_LX_SIGNATURE)
        throw PEFormatError("Invalid NT Headers signature. Probably a LX file");
    if ((0xFFFF & signature) == IMAGE_TE_SIGNATURE)
        throw PEFormatError("Invalid NT Headers signature. Probably a TE file");
    if (signature != IMAGE_NT_SIGNATURE)
        throw PEFormatError("Invalid NT Headers signature.");

    file_header_ = FileHeader::parse(data_, nt_headers_offset + 4);

    auto optional_header_offset = nt_headers_offset + 4 + 20;
    auto sections_offset = optional_header_offset + file_header_.SizeOfOptionalHeader;

    if (sections_offset > data_size_) {
        throw PEFormatError("Sections offset beyond file");
    }

    if (optional_header_offset + 256 <= data_size_) {
        auto oh_data = std::span<const std::uint8_t>(
            data_.data() + optional_header_offset,
            std::min<std::size_t>(256, data_size_ - optional_header_offset));
        optional_header_32_ = OptionalHeader32::parse(oh_data, 0);
    }

    if (optional_header_32_.Magic == OPTIONAL_HEADER_MAGIC_PE) {
        pe_type_ = OPTIONAL_HEADER_MAGIC_PE;
    } else if (optional_header_32_.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS) {
        pe_type_ = OPTIONAL_HEADER_MAGIC_PE_PLUS;
        optional_header_64_ = read_packed<OptionalHeader64>(data_, optional_header_offset);
    } else {
        add_warning("Invalid type in Optional Header: 0x" +
            std::to_string(optional_header_32_.Magic));
    }

    if (pe_type_ == 0) {
        throw PEFormatError("No Optional Header found, invalid PE32 or PE32+ file.");
    }

    std::size_t dir_offset = optional_header_offset + (is_pe32_plus() ? 112 : 96);
    std::uint32_t num_dirs = is_pe32_plus() ?
        optional_header_64_.NumberOfRvaAndSizes :
        optional_header_32_.NumberOfRvaAndSizes;

    if (num_dirs > 0x10) {
        add_warning("Suspicious NumberOfRvaAndSizes: 0x" +
            std::to_string(num_dirs));
    }

    std::uint32_t dir_count = std::min(num_dirs, static_cast<std::uint32_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
    for (std::uint32_t i = 0; i < dir_count; i++) {
        if (dir_offset + 8 > data_size_) break;
        auto dd = DataDirectory::parse(data_, dir_offset);
        dd.name = std::string(directory_entry_name(static_cast<DirectoryEntry>(i)));
        data_directories_.push_back(dd);
        dir_offset += 8;
    }

    parse_sections(sections_offset);

    rich_header_ = parse_rich_header();

    if (pe_type_ == OPTIONAL_HEADER_MAGIC_PE) {
        auto ep = optional_header_32_.AddressOfEntryPoint;
        if (ep != 0 && get_section_by_rva(ep).has_value()) {
            auto ep_offset = get_offset_from_rva(ep);
            if (ep_offset > data_size_) {
                add_warning("AddressOfEntryPoint lies outside the file");
            }
        }
    } else {
        auto ep = optional_header_64_.AddressOfEntryPoint;
        if (ep != 0 && get_section_by_rva(ep).has_value()) {
            auto ep_offset = get_offset_from_rva(ep);
            if (ep_offset > data_size_) {
                add_warning("AddressOfEntryPoint lies outside the file");
            }
        }
    }
}

void PE::full_load() {
    parse_data_directories();
}

void PE::parse_sections(std::size_t offset, std::size_t max_offset) {
    sections_.clear();

    for (std::uint16_t i = 0; i < file_header_.NumberOfSections; i++) {
        if (i >= MAX_SECTIONS) {
            add_warning("Too many sections");
            break;
        }

        auto section_offset = offset + 40 * i;
        if (section_offset + 40 > data_size_) break;

        auto section_data = std::span<const std::uint8_t>(
            data_.data() + section_offset,
            std::min<std::size_t>(40, data_size_ - section_offset));

        if (count_zeroes(section_data) == 40) {
            add_warning("Invalid section " + std::to_string(i) + ". Contents are null-bytes.");
            break;
        }

        auto section = SectionHeader::parse(section_data, 0);

        auto section_alignment = is_pe32_plus() ?
            optional_header_64_.SectionAlignment : optional_header_32_.SectionAlignment;
        auto file_alignment = is_pe32_plus() ?
            optional_header_64_.FileAlignment : optional_header_32_.FileAlignment;

        if (section.SizeOfRawData + section.PointerToRawData > data_size_) {
            add_warning("Error parsing section " + std::to_string(i) + ". SizeOfRawData is larger than file.");
        }

        if (section.VirtualSize > max_offset) {
            add_warning("Suspicious value found parsing section " + std::to_string(i) + ". VirtualSize is extremely large.");
        }

        if (adjust_section_alignment(section.VirtualAddress, section_alignment, file_alignment) > max_offset) {
            add_warning("Suspicious value found parsing section " + std::to_string(i) + ". VirtualAddress is beyond limit.");
        }

        section.VirtualSize = section.Misc;
        sections_.push_back(section);
    }

    std::sort(sections_.begin(), sections_.end(),
        [](const SectionHeader& a, const SectionHeader& b) {
            return a.VirtualAddress < b.VirtualAddress;
        });

    for (auto& section : sections_) {
        if ((section.Characteristics & static_cast<std::uint32_t>(SectionCharacteristic::MEM_WRITE)) &&
            (section.Characteristics & static_cast<std::uint32_t>(SectionCharacteristic::MEM_EXECUTE))) {
            std::string name(section.Name, strnlen(section.Name, 8));
            if (name == "PAGE" && is_driver()) {
                continue;
            }
            add_warning("Suspicious flags set for section with write+execute.");
        }
    }
}

const SectionHeader* PE::find_section_for_rva(std::uint32_t rva) const {
    for (auto& s : sections_) {
        if (s.VirtualAddress <= rva &&
            rva < s.VirtualAddress + std::max(s.SizeOfRawData, s.VirtualSize)) {
            return &s;
        }
    }
    return nullptr;
}

const SectionHeader* PE::find_section_for_offset(std::uint32_t offset) const {
    for (auto& s : sections_) {
        if (s.PointerToRawData <= offset &&
            offset < s.PointerToRawData + s.SizeOfRawData) {
            return &s;
        }
    }
    return nullptr;
}

std::uint32_t PE::get_offset_from_rva(std::uint32_t rva) const {
    auto section_alignment = is_pe32_plus() ?
        optional_header_64_.SectionAlignment : optional_header_32_.SectionAlignment;
    auto file_alignment = is_pe32_plus() ?
        optional_header_64_.FileAlignment : optional_header_32_.FileAlignment;

    for (auto& s : sections_) {
        auto adj_va = adjust_section_alignment(s.VirtualAddress, section_alignment, file_alignment);
        auto adj_ptr = s.PointerToRawData & ~0x1FFu;

        if (adj_va <= rva && rva < adj_va + s.SizeOfRawData) {
            return adj_ptr + (rva - adj_va);
        }
    }
    return rva;
}

std::uint32_t PE::get_rva_from_offset(std::uint32_t offset) const {
    for (auto& s : sections_) {
        if (s.PointerToRawData <= offset && offset < s.PointerToRawData + s.SizeOfRawData) {
            return s.VirtualAddress + (offset - s.PointerToRawData);
        }
    }
    return offset;
}

std::span<const std::uint8_t> PE::get_data_span(std::uint32_t rva, std::uint32_t length) const {
    if (rva + length > data_size_ || rva + length < rva) {
        throw PEFormatError("RVA out of bounds");
    }
    return std::span<const std::uint8_t>(data_.data() + rva, length);
}

std::span<const std::uint8_t> PE::get_data(std::uint32_t rva, std::optional<std::uint32_t> length) const {
    auto section = find_section_for_rva(rva);
    if (!section && rva != 0) {
        if (!length) {
            length = 1;
        }
        return get_data_span(rva, *length);
    }
    if (!section) {
        throw PEFormatError("No section for RVA");
    }

    auto file_offset = get_offset_from_rva(rva);
    auto section_end = section->PointerToRawData + section->SizeOfRawData;

    if (length) {
        auto end = file_offset + *length;
        if (end > data_size_) end = data_size_;
        if (file_offset >= data_size_) throw PEFormatError("Offset out of bounds");
        return std::span<const std::uint8_t>(data_.data() + file_offset, end - file_offset);
    }

    auto max_len = std::min(static_cast<std::uint32_t>(data_size_), section_end) - file_offset;
    if (file_offset >= data_size_ || max_len > data_size_) throw PEFormatError("Offset out of bounds");
    return std::span<const std::uint8_t>(data_.data() + file_offset, max_len);
}

std::vector<std::uint8_t> PE::get_data_copy(std::uint32_t rva, std::optional<std::uint32_t> length) const {
    auto span = get_data(rva, length);
    return {span.begin(), span.end()};
}

std::optional<std::reference_wrapper<const SectionHeader>> PE::get_section_by_rva(std::uint32_t rva) const {
    auto section = find_section_for_rva(rva);
    if (!section) return std::nullopt;
    return std::cref(*section);
}

std::optional<std::reference_wrapper<const SectionHeader>> PE::get_section_by_offset(std::uint32_t offset) const {
    auto section = find_section_for_offset(offset);
    if (!section) return std::nullopt;
    return std::cref(*section);
}

std::string PE::get_string_at_rva(std::uint32_t rva, std::size_t max_length) const {
    std::string result;
    for (std::size_t i = 0; i < max_length; i++) {
        auto offset = get_offset_from_rva(rva + static_cast<std::uint32_t>(i));
        if (offset >= data_size_) break;
        char c = static_cast<char>(data_[offset]);
        if (c == '\0') break;
        result += c;
    }
    return result;
}

std::string PE::get_string_u_at_rva(std::uint32_t rva, std::size_t max_length) const {
    std::string result;
    auto offset = get_offset_from_rva(rva);
    for (std::size_t i = 0; i < max_length * 2 && offset + i + 1 < data_size_; i += 2) {
        char c1 = static_cast<char>(data_[offset + i]);
        char c2 = static_cast<char>(data_[offset + i + 1]);
        if (c1 == '\0' && c2 == '\0') break;
        if (c2 == '\0') {
            result += c1;
            break;
        }
        result += c1;
    }
    return result;
}

std::vector<std::uint8_t> PE::get_memory_mapped_image(std::uint32_t max_virtual_address) const {
    auto size_of_image = is_pe32_plus() ?
        optional_header_64_.SizeOfImage : optional_header_32_.SizeOfImage;
    auto image_size = std::min(size_of_image, max_virtual_address);
    std::vector<std::uint8_t> mapped(image_size, 0);

    auto headers_size = is_pe32_plus() ?
        optional_header_64_.SizeOfHeaders : optional_header_32_.SizeOfHeaders;
    auto copy_size = std::min(static_cast<std::size_t>(headers_size), data_size_);
    std::memcpy(mapped.data(), data_.data(), copy_size);

    for (auto& section : sections_) {
        if (section.VirtualAddress >= max_virtual_address) continue;
        if (section.VirtualAddress + section.SizeOfRawData > max_virtual_address) continue;
        if (section.PointerToRawData + section.SizeOfRawData > data_size_) continue;
        if (section.VirtualAddress + section.SizeOfRawData > image_size) continue;
        std::memcpy(mapped.data() + section.VirtualAddress,
                    data_.data() + section.PointerToRawData,
                    section.SizeOfRawData);
    }

    return mapped;
}

std::span<const std::uint8_t> PE::get_overlay() const {
    if (sections_.empty()) return {};
    std::uint32_t max_end = 0;
    for (auto& s : sections_) {
        auto end = s.PointerToRawData + s.SizeOfRawData;
        if (end > max_end) max_end = end;
    }
    if (max_end >= data_size_) return {};
    return std::span<const std::uint8_t>(data_.data() + max_end, data_size_ - max_end);
}

std::optional<std::uint32_t> PE::get_overlay_data_start_offset() const {
    if (sections_.empty()) return std::nullopt;
    std::uint32_t max_end = 0;
    for (auto& s : sections_) {
        auto end = s.PointerToRawData + s.SizeOfRawData;
        if (end > max_end) max_end = end;
    }
    if (max_end >= data_size_) return std::nullopt;
    return max_end;
}

std::vector<std::uint8_t> PE::trim() const {
    if (sections_.empty()) {
        return {data_.begin(), data_.end()};
    }
    std::uint32_t max_end = 0;
    for (auto& s : sections_) {
        auto end = s.PointerToRawData + s.SizeOfRawData;
        if (end > max_end) max_end = end;
    }
    return {data_.begin(), data_.begin() + std::min(max_end, static_cast<std::uint32_t>(data_size_))};
}

bool PE::is_exe() const {
    return (file_header_.Characteristics & static_cast<std::uint16_t>(ImageCharacteristic::EXECUTABLE_IMAGE)) != 0 &&
           (file_header_.Characteristics & static_cast<std::uint16_t>(ImageCharacteristic::DLL)) == 0;
}

bool PE::is_dll() const {
    return (file_header_.Characteristics & static_cast<std::uint16_t>(ImageCharacteristic::DLL)) != 0;
}

bool PE::is_driver() const {
    auto sub = is_pe32_plus() ? optional_header_64_.Subsystem : optional_header_32_.Subsystem;
    if (sub == 1) return true;
    if (sub == 10 || sub == 11 || sub == 12 || sub == 13) return true;
    return false;
}

bool PE::has_relocs() const {
    return !relocations_.empty();
}

bool PE::has_dynamic_relocs() const {
    if (load_config_data_ && load_config_data_->dynamic_value_reloc_table != 0) {
        return true;
    }
    return false;
}

bool PE::verify_checksum() const {
    return generate_checksum() == (is_pe32_plus() ?
        optional_header_64_.CheckSum : optional_header_32_.CheckSum);
}

std::uint32_t PE::generate_checksum() const {
    std::uint64_t checksum = 0;
    std::size_t size = data_size_;
    auto ptr = data_.data();

    for (std::size_t i = 0; i < size / 4; i++) {
        std::uint32_t dword_val;
        std::memcpy(&dword_val, ptr + i * 4, 4);
        checksum += dword_val;
        if (checksum > 0xFFFFFFFF) {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
    }

    ptr += (size / 4) * 4;
    std::size_t remaining = size % 4;
    if (remaining > 0) {
        std::uint32_t dword_val = 0;
        std::memcpy(&dword_val, ptr, remaining);
        checksum += dword_val;
        if (checksum > 0xFFFFFFFF) {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
    }

    checksum = static_cast<std::uint32_t>((checksum & 0xFFFF) + (checksum >> 16));
    checksum = static_cast<std::uint32_t>(checksum + (checksum >> 16));
    checksum &= 0xFFFF;
    checksum += size;

    return static_cast<std::uint32_t>(checksum);
}

std::uint8_t PE::get_byte_at_rva(std::uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset >= data_size_) return 0;
    return data_[offset];
}

std::uint16_t PE::get_word_at_rva(std::uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset + 2 > data_size_) return 0;
    std::uint16_t val;
    std::memcpy(&val, data_.data() + offset, 2);
    return val;
}

std::uint32_t PE::get_dword_at_rva(std::uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset + 4 > data_size_) return 0;
    std::uint32_t val;
    std::memcpy(&val, data_.data() + offset, 4);
    return val;
}

std::uint64_t PE::get_qword_at_rva(std::uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset + 8 > data_size_) return 0;
    std::uint64_t val;
    std::memcpy(&val, data_.data() + offset, 8);
    return val;
}

std::uint8_t PE::get_byte_at_offset(std::uint32_t offset) const {
    if (offset >= data_size_) return 0;
    return data_[offset];
}

std::uint16_t PE::get_word_at_offset(std::uint32_t offset) const {
    if (offset + 2 > data_size_) return 0;
    std::uint16_t val;
    std::memcpy(&val, data_.data() + offset, 2);
    return val;
}

std::uint32_t PE::get_dword_at_offset(std::uint32_t offset) const {
    if (offset + 4 > data_size_) return 0;
    std::uint32_t val;
    std::memcpy(&val, data_.data() + offset, 4);
    return val;
}

std::uint64_t PE::get_qword_at_offset(std::uint32_t offset) const {
    if (offset + 8 > data_size_) return 0;
    std::uint64_t val;
    std::memcpy(&val, data_.data() + offset, 8);
    return val;
}

bool PE::set_bytes_at_rva(std::uint32_t rva, std::span<const std::uint8_t> data) {
    auto offset = get_offset_from_rva(rva);
    if (offset + data.size() > data_size_) return false;
    std::memcpy(data_.data() + offset, data.data(), data.size());
    return true;
}

bool PE::set_bytes_at_offset(std::uint32_t offset, std::span<const std::uint8_t> data) {
    if (offset + data.size() > data_size_) return false;
    std::memcpy(data_.data() + offset, data.data(), data.size());
    return true;
}

bool PE::set_word_at_rva(std::uint32_t rva, std::uint16_t word) {
    return set_bytes_at_rva(rva, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&word), 2));
}

bool PE::set_dword_at_rva(std::uint32_t rva, std::uint32_t dword) {
    return set_bytes_at_rva(rva, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&dword), 4));
}

bool PE::set_qword_at_rva(std::uint32_t rva, std::uint64_t qword) {
    return set_bytes_at_rva(rva, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&qword), 8));
}

bool PE::set_word_at_offset(std::uint32_t offset, std::uint16_t word) {
    return set_bytes_at_offset(offset, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&word), 2));
}

bool PE::set_dword_at_offset(std::uint32_t offset, std::uint32_t dword) {
    return set_bytes_at_offset(offset, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&dword), 4));
}

bool PE::set_qword_at_offset(std::uint32_t offset, std::uint64_t qword) {
    return set_bytes_at_offset(offset, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(&qword), 8));
}

std::vector<std::uint8_t> PE::write() const {
    return data_;
}

bool PE::write(const std::string& filename) const {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(data_.data()), data_size_);
    return file.good();
}

// ============================================================================
// Directory Parsers
// ============================================================================

void PE::parse_data_directories() {
    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::EXPORT) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::EXPORT)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::EXPORT)];
        exports_ = parse_export_directory(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::IMPORT) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::IMPORT)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::IMPORT)];
        imports_ = parse_import_directory(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::BASERELOC) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::BASERELOC)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::BASERELOC)];
        relocations_ = parse_relocations_directory(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::DEBUG) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::DEBUG)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::DEBUG)];
        debug_data_ = parse_debug_directory(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::TLS) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::TLS)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::TLS)];
        tls_data_ = parse_directory_tls(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::EXCEPTION) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::EXCEPTION)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::EXCEPTION)];
        exceptions_ = parse_exceptions_directory(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::LOAD_CONFIG) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::LOAD_CONFIG)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::LOAD_CONFIG)];
        load_config_data_ = parse_directory_load_config(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::BOUND_IMPORT) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::BOUND_IMPORT)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::BOUND_IMPORT)];
        bound_imports_ = parse_directory_bound_imports(dir.VirtualAddress, dir.Size);
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::RESOURCE) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::RESOURCE)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::RESOURCE)];
        auto result = parse_resources_directory(dir.VirtualAddress, dir.Size);
        if (result) {
            resources_.push_back(*result);
        }
    }

    if (data_directories_.size() > static_cast<std::size_t>(DirectoryEntry::DELAY_IMPORT) &&
        data_directories_[static_cast<std::size_t>(DirectoryEntry::DELAY_IMPORT)].VirtualAddress) {
        auto& dir = data_directories_[static_cast<std::size_t>(DirectoryEntry::DELAY_IMPORT)];
        delay_imports_ = parse_delay_import_directory(dir.VirtualAddress, dir.Size);
    }
}

std::vector<ImportDescData> PE::parse_import_directory(std::uint32_t rva, std::uint32_t size) {
    std::vector<ImportDescData> import_descs;
    std::size_t desc_size = 20;

    while (true) {
        if (rva + desc_size > data_size_) break;

        auto import_desc = ImageImportDescriptor::parse(data_, rva);
        if (import_desc.OriginalFirstThunk == 0 && import_desc.FirstThunk == 0 &&
            import_desc.Name == 0) {
            break;
        }

        rva += desc_size;

        auto file_offset = get_offset_from_rva(rva);
        std::uint32_t max_len = static_cast<std::uint32_t>(data_size_) - file_offset;
        if (rva > import_desc.OriginalFirstThunk || rva > import_desc.FirstThunk) {
            max_len = std::max(
                rva - import_desc.OriginalFirstThunk,
                rva - import_desc.FirstThunk);
        }

        std::vector<ImportData> import_data;
        try {
            import_data = parse_imports(
                import_desc.OriginalFirstThunk,
                import_desc.FirstThunk,
                import_desc.ForwarderChain,
                max_len);
        } catch (const PEFormatError& e) {
            add_warning("Error parsing import directory: " + std::string(e.what()));
        }

        std::string dll = get_string_at_rva(import_desc.Name, MAX_DLL_LENGTH);
        if (!is_valid_dos_filename(dll)) dll = "*invalid*";

        if (!dll.empty()) {
            for (auto& symbol : import_data) {
                if (symbol.name.empty()) {
                    auto funcname = ordlookup::ordinal_lookup(dll, symbol.ordinal);
                    if (!funcname.empty()) {
                        symbol.name = funcname;
                        symbol.name_from_ordinal = true;
                    }
                }
            }
            import_descs.push_back({dll, import_data, static_cast<std::uint32_t>(rva - desc_size)});
        }
    }

    return import_descs;
}

std::vector<ImportData> PE::parse_imports(
    std::uint32_t original_first_thunk,
    std::uint32_t first_thunk,
    std::uint32_t forwarder_chain,
    std::uint32_t max_length) {

    std::vector<ImportData> imported_symbols;

    std::uint64_t ordinal_flag;
    std::size_t entry_size;
    if (pe_type_ == OPTIONAL_HEADER_MAGIC_PE) {
        ordinal_flag = IMAGE_ORDINAL_FLAG;
        entry_size = 4;
    } else {
        ordinal_flag = IMAGE_ORDINAL_FLAG64;
        entry_size = 8;
    }

    std::uint32_t ilt_rva = original_first_thunk;
    std::uint32_t iat_rva = first_thunk;

    std::uint32_t start_rva = ilt_rva;
    std::size_t num_invalid = 0;

    while (ilt_rva != 0 || iat_rva != 0) {
        std::uint32_t current_rva = ilt_rva ? ilt_rva : iat_rva;

        if (max_length > 0 && current_rva >= start_rva + max_length) break;

        if (current_rva + entry_size > data_size_) break;

        std::uint64_t address_of_data = 0;
        auto offset = get_offset_from_rva(current_rva);
        if (entry_size == 4) {
            std::uint32_t val;
            std::memcpy(&val, data_.data() + offset, 4);
            address_of_data = val;
        } else {
            std::memcpy(&address_of_data, data_.data() + offset, 8);
        }

        if (address_of_data == 0) break;

        std::uint16_t imp_ord = 0;
        std::uint16_t imp_hint = 0;
        std::string imp_name;
        bool import_by_ordinal = false;
        std::uint32_t name_offset = 0;

        if (address_of_data & ordinal_flag) {
            import_by_ordinal = true;
            imp_ord = static_cast<std::uint16_t>(address_of_data & 0xFFFF);
        } else {
            if (address_of_data + 2 < data_size_) {
                auto name_rva = static_cast<std::uint32_t>(address_of_data);
                auto hint_offset = get_offset_from_rva(name_rva);
                if (hint_offset + 2 <= data_size_) {
                    std::memcpy(&imp_hint, data_.data() + hint_offset, 2);
                }
                imp_name = get_string_at_rva(name_rva + 2, MAX_IMPORT_NAME_LENGTH);
                name_offset = get_offset_from_rva(name_rva + 2);
            }
        }

        if (imp_ord == 0 && imp_name.empty()) {
            num_invalid++;
            if (num_invalid > 1000) break;
            if (ilt_rva) ilt_rva += entry_size;
            if (iat_rva) iat_rva += entry_size;
            continue;
        }

        auto thunk_offset = static_cast<std::uint32_t>(get_offset_from_rva(current_rva));
        auto thunk_rva = current_rva;

        std::uint64_t imp_address = first_thunk +
            (is_pe32_plus() ? optional_header_64_.ImageBase : optional_header_32_.ImageBase);

        ImportData imp;
        imp.ordinal = imp_ord;
        imp.import_by_ordinal = import_by_ordinal;
        imp.hint = imp_hint;
        imp.name = imp_name;
        imp.name_offset = name_offset;
        imp.name_from_ordinal = false;
        imp.address = imp_address;
        imp.hint_name_table_rva = address_of_data;
        imp.thunk_offset = thunk_offset;
        imp.thunk_rva = thunk_rva;
        imported_symbols.push_back(imp);

        if (ilt_rva) ilt_rva += entry_size;
        if (iat_rva) iat_rva += entry_size;
    }

    return imported_symbols;
}

std::optional<ExportDirData> PE::parse_export_directory(std::uint32_t rva, std::uint32_t size) {
    if (rva + 40 > data_size_) return std::nullopt;

    auto export_dir = ImageExportDirectory::parse(data_, rva);
    if (export_dir.NumberOfFunctions == 0 && export_dir.NumberOfNames == 0) {
        return std::nullopt;
    }

    auto length_until_eof = [this](std::uint32_t r) -> std::uint32_t {
        auto off = get_offset_from_rva(r);
        return static_cast<std::uint32_t>(data_size_) - off;
    };

    auto addr_of_names = get_offset_from_rva(export_dir.AddressOfNames);
    auto addr_of_name_ordinals = get_offset_from_rva(export_dir.AddressOfNameOrdinals);
    auto addr_of_functions = get_offset_from_rva(export_dir.AddressOfFunctions);

    std::vector<ExportData> exports;

    for (std::uint32_t i = 0; i < std::min(export_dir.NumberOfNames,
            length_until_eof(export_dir.AddressOfNames) / 4); i++) {
        if (addr_of_name_ordinals + i * 2 + 2 > data_size_) break;
        std::uint16_t symbol_ordinal;
        std::memcpy(&symbol_ordinal, data_.data() + addr_of_name_ordinals + i * 2, 2);

        std::uint32_t symbol_address = 0;
        if (addr_of_functions + symbol_ordinal * 4 + 4 <= data_size_) {
            std::memcpy(&symbol_address, data_.data() + addr_of_functions + symbol_ordinal * 4, 4);
        }

        if (symbol_address == 0) continue;

        std::string forwarder;
        if (rva <= symbol_address && symbol_address < rva + size) {
            forwarder = get_string_at_rva(symbol_address);
        }

        std::uint32_t symbol_name_rva = 0;
        if (addr_of_names + i * 4 + 4 <= data_size_) {
            std::memcpy(&symbol_name_rva, data_.data() + addr_of_names + i * 4, 4);
        }

        std::string symbol_name;
        if (symbol_name_rva) {
            symbol_name = get_string_at_rva(symbol_name_rva, MAX_SYMBOL_NAME_LENGTH);
        }

        ExportData exp;
        exp.ordinal = export_dir.Base + symbol_ordinal;
        exp.address = symbol_address;
        exp.name = symbol_name;
        exp.forwarder = forwarder;
        exp.is_forwarder = !forwarder.empty();
        exports.push_back(exp);
    }

    if (exports.empty()) return std::nullopt;

    return ExportDirData{0, exports, get_string_at_rva(export_dir.Name)};
}

std::vector<DebugData> PE::parse_debug_directory(std::uint32_t rva, std::uint32_t size) {
    std::vector<DebugData> debug;
    std::size_t dbg_size = 28;
    std::uint32_t count = static_cast<std::uint32_t>(size / dbg_size);

    for (std::uint32_t idx = 0; idx < count; idx++) {
        auto dbg_rva = rva + dbg_size * idx;
        if (dbg_rva + dbg_size > data_size_) break;

        auto dbg = ImageDebugDirectory::parse(data_, dbg_rva);

        DebugData data;
        data.type = dbg.Type;
        data.size_of_data = dbg.SizeOfData;
        data.address_of_raw_data = dbg.AddressOfRawData;
        data.pointer_to_raw_data = dbg.PointerToRawData;
        debug.push_back(data);
    }

    return debug;
}

std::vector<BaseRelocationData> PE::parse_relocations_directory(std::uint32_t rva, std::uint32_t size) {
    std::vector<BaseRelocationData> relocations;
    std::uint32_t end = rva + size;

    while (rva < end) {
        if (rva + 8 > data_size_) break;

        auto rlc = ImageBaseRelocation::parse(data_, rva);
        if (rlc.VirtualAddress == 0 && rlc.SizeOfBlock == 0) break;
        if (rlc.SizeOfBlock < 8 || rlc.SizeOfBlock > data_size_) break;

        std::uint32_t base_rva = rlc.VirtualAddress;
        std::uint32_t entries_size = rlc.SizeOfBlock - 8;
        std::uint32_t entry_rva = rva + 8;

        BaseRelocationData base_reloc;
        base_reloc.struct_offset = rva;

        std::set<std::pair<std::uint32_t, std::uint32_t>> seen;
        for (std::uint32_t i = 0; i < entries_size / 2; i++) {
            auto entry_offset = get_offset_from_rva(entry_rva + i * 2);
            if (entry_offset + 2 > data_size_) break;

            std::uint16_t word;
            std::memcpy(&word, data_.data() + entry_offset, 2);

            std::uint32_t reloc_type = word >> 12;
            std::uint32_t reloc_offset = word & 0x0FFF;

            auto key = std::make_pair(reloc_offset, reloc_type);
            if (seen.count(key)) break;
            seen.insert(key);

            RelocationData reloc;
            reloc.type = reloc_type;
            reloc.base_rva = base_rva;
            reloc.rva = reloc_offset + base_rva;
            base_reloc.entries.push_back(reloc);
        }

        relocations.push_back(base_reloc);

        if (rlc.SizeOfBlock == 0) break;
        rva += rlc.SizeOfBlock;
    }

    return relocations;
}

std::optional<TlsData> PE::parse_directory_tls(std::uint32_t rva, std::uint32_t size) {
    TlsData tls;
    tls.struct_offset = rva;

    if (is_pe32_plus()) {
        if (rva + 40 > data_size_) return std::nullopt;
        auto dir = ImageTlsDirectory64::parse(data_, rva);
        tls.start_address_of_raw_data = dir.StartAddressOfRawData;
        tls.end_address_of_raw_data = dir.EndAddressOfRawData;
        tls.address_of_index = dir.AddressOfIndex;
        tls.address_of_callbacks = dir.AddressOfCallBacks;
    } else {
        if (rva + 24 > data_size_) return std::nullopt;
        auto dir = ImageTlsDirectory32::parse(data_, rva);
        tls.start_address_of_raw_data = dir.StartAddressOfRawData;
        tls.end_address_of_raw_data = dir.EndAddressOfRawData;
        tls.address_of_index = dir.AddressOfIndex;
        tls.address_of_callbacks = dir.AddressOfCallBacks;
    }

    return tls;
}

std::vector<ExceptionsDirEntryData> PE::parse_exceptions_directory(std::uint32_t rva, std::uint32_t size) {
    std::vector<ExceptionsDirEntryData> result;

    if (file_header_.Machine != static_cast<std::uint16_t>(MachineType::AMD64) &&
        file_header_.Machine != static_cast<std::uint16_t>(MachineType::IA64)) {
        return result;
    }

    std::size_t rf_size = 12;
    std::uint32_t end = rva + size;

    while (rva + rf_size <= end && rva + rf_size <= data_size_) {
        auto rf = RuntimeFunction::parse(data_, rva);

        ExceptionsDirEntryData entry;
        entry.struct_offset = rva;
        entry.begin_address = rf.BeginAddress;
        entry.end_address = rf.EndAddress;
        entry.unwind_data = rf.UnwindData;
        result.push_back(entry);

        rva += rf_size;
    }

    return result;
}

std::optional<LoadConfigData> PE::parse_directory_load_config(std::uint32_t rva, std::uint32_t size) {
    if (rva + 4 > data_size_) return std::nullopt;

    LoadConfigData lc;
    lc.struct_offset = rva;

    std::uint32_t lc_size = get_dword_at_rva(rva);
    lc.size = lc_size;

    auto offset = get_offset_from_rva(rva);
    if (offset + lc_size > data_size_) return lc;

    if (is_pe32_plus()) {
        if (lc_size >= 40) {
            lc.time_date_stamp = get_dword_at_rva(rva + 4);
            lc.major_version = get_word_at_rva(rva + 8);
            lc.minor_version = get_word_at_rva(rva + 10);
            lc.global_flags_clear = get_dword_at_rva(rva + 12);
            lc.global_flags_set = get_dword_at_rva(rva + 16);
            lc.critical_section_default_timeout = get_dword_at_rva(rva + 20);
            lc.de_commit_free_block_threshold = get_qword_at_rva(rva + 24);
            lc.de_commit_total_free_threshold = get_qword_at_rva(rva + 32);
        }
        if (lc_size >= 68) {
            lc.lock_prefix_table = get_qword_at_rva(rva + 40);
            lc.maximum_allocation_size = get_qword_at_rva(rva + 48);
            lc.virtual_memory_threshold = get_qword_at_rva(rva + 56);
            lc.process_affinity_mask = get_qword_at_rva(rva + 64);
        }
        if (lc_size >= 72) {
            lc.process_heap_flags = get_dword_at_rva(rva + 72);
        }
        if (lc_size >= 76) {
            lc.csd_version = get_word_at_rva(rva + 76);
            lc.dependent_load_flags = get_word_at_rva(rva + 78);
        }
        if (lc_size >= 88) {
            lc.edit_list = get_qword_at_rva(rva + 80);
            lc.security_cookie = get_qword_at_rva(rva + 88);
        }
        if (lc_size >= 104) {
            lc.se_handler_table = get_qword_at_rva(rva + 96);
            lc.se_handler_count = get_qword_at_rva(rva + 104);
        }
        if (lc_size >= 120) {
            lc.guard_cf_check_function_pointer = get_qword_at_rva(rva + 112);
            lc.guard_cf_dispatch_function_pointer = get_qword_at_rva(rva + 120);
        }
        if (lc_size >= 136) {
            lc.guard_cf_function_table = get_qword_at_rva(rva + 128);
            lc.guard_cf_function_count = get_qword_at_rva(rva + 136);
        }
        if (lc_size >= 140) {
            lc.guard_flags = get_dword_at_rva(rva + 140);
        }
        if (lc_size >= 152) {
            lc.code_integrity_flags = get_word_at_rva(rva + 144);
            lc.code_integrity_catalog = get_word_at_rva(rva + 146);
            lc.code_integrity_catalog_offset = get_dword_at_rva(rva + 148);
            lc.code_integrity_reserved = get_dword_at_rva(rva + 152);
        }
        if (lc_size >= 168) {
            lc.guard_address_taken_iat_entry_table = get_qword_at_rva(rva + 156);
            lc.guard_address_taken_iat_entry_count = get_qword_at_rva(rva + 164);
        }
        if (lc_size >= 184) {
            lc.guard_long_jump_target_table = get_qword_at_rva(rva + 172);
            lc.guard_long_jump_target_count = get_qword_at_rva(rva + 180);
        }
        if (lc_size >= 200) {
            lc.dynamic_value_reloc_table = get_qword_at_rva(rva + 188);
            lc.chpe_metadata_pointer = get_qword_at_rva(rva + 196);
        }
        if (lc_size >= 216) {
            lc.guard_rf_failure_routine = get_qword_at_rva(rva + 204);
            lc.guard_rf_failure_routine_function_pointer = get_qword_at_rva(rva + 212);
        }
        if (lc_size >= 224) {
            lc.dynamic_value_reloc_table_offset = get_dword_at_rva(rva + 220);
            lc.dynamic_value_reloc_table_section = get_word_at_rva(rva + 224);
            lc.reserved2 = get_word_at_rva(rva + 226);
        }
        if (lc_size >= 240) {
            lc.guard_rf_verify_stack_pointer_function_pointer = get_qword_at_rva(rva + 228);
            lc.hot_patch_table_offset = get_dword_at_rva(rva + 236);
        }
        if (lc_size >= 248) {
            lc.reserved3 = get_dword_at_rva(rva + 240);
        }
        if (lc_size >= 264) {
            lc.enclave_configuration_pointer = get_qword_at_rva(rva + 248);
            lc.volatile_metadata_pointer = get_qword_at_rva(rva + 256);
        }
        if (lc_size >= 280) {
            lc.guard_eh_continuation_table = get_qword_at_rva(rva + 264);
            lc.guard_eh_continuation_count = get_qword_at_rva(rva + 272);
        }
        if (lc_size >= 296) {
            lc.guard_xfg_check_function_pointer = get_qword_at_rva(rva + 280);
            lc.guard_xfg_dispatch_function_pointer = get_qword_at_rva(rva + 288);
        }
        if (lc_size >= 312) {
            lc.guard_xfg_table_dispatch_function_pointer = get_qword_at_rva(rva + 296);
            lc.cast_guard_os_determined_failure_mode = get_qword_at_rva(rva + 304);
        }
        if (lc_size >= 320) {
            lc.guard_memcpy_function_pointer = get_qword_at_rva(rva + 312);
        }
    } else {
        if (lc_size >= 40) {
            lc.time_date_stamp = get_dword_at_rva(rva + 4);
            lc.major_version = get_word_at_rva(rva + 8);
            lc.minor_version = get_word_at_rva(rva + 10);
            lc.global_flags_clear = get_dword_at_rva(rva + 12);
            lc.global_flags_set = get_dword_at_rva(rva + 16);
            lc.critical_section_default_timeout = get_dword_at_rva(rva + 20);
            lc.de_commit_free_block_threshold = get_dword_at_rva(rva + 24);
            lc.de_commit_total_free_threshold = get_dword_at_rva(rva + 28);
            lc.lock_prefix_table = get_dword_at_rva(rva + 32);
            lc.maximum_allocation_size = get_dword_at_rva(rva + 36);
            lc.virtual_memory_threshold = get_dword_at_rva(rva + 40);
        }
        if (lc_size >= 52) {
            lc.process_affinity_mask = get_dword_at_rva(rva + 44);
            lc.process_heap_flags = get_dword_at_rva(rva + 48);
        }
        if (lc_size >= 56) {
            lc.csd_version = get_word_at_rva(rva + 52);
            lc.dependent_load_flags = get_word_at_rva(rva + 54);
        }
        if (lc_size >= 64) {
            lc.edit_list = get_dword_at_rva(rva + 56);
            lc.security_cookie = get_dword_at_rva(rva + 60);
        }
        if (lc_size >= 72) {
            lc.se_handler_table = get_dword_at_rva(rva + 64);
            lc.se_handler_count = get_dword_at_rva(rva + 68);
        }
        if (lc_size >= 80) {
            lc.guard_cf_check_function_pointer = get_dword_at_rva(rva + 72);
            lc.guard_cf_dispatch_function_pointer = get_dword_at_rva(rva + 76);
        }
        if (lc_size >= 88) {
            lc.guard_cf_function_table = get_dword_at_rva(rva + 80);
            lc.guard_cf_function_count = get_dword_at_rva(rva + 84);
        }
        if (lc_size >= 92) {
            lc.guard_flags = get_dword_at_rva(rva + 88);
        }
        if (lc_size >= 100) {
            lc.code_integrity_flags = get_word_at_rva(rva + 92);
            lc.code_integrity_catalog = get_word_at_rva(rva + 94);
            lc.code_integrity_catalog_offset = get_dword_at_rva(rva + 96);
            lc.code_integrity_reserved = get_dword_at_rva(rva + 100);
        }
        if (lc_size >= 108) {
            lc.guard_address_taken_iat_entry_table = get_dword_at_rva(rva + 104);
            lc.guard_address_taken_iat_entry_count = get_dword_at_rva(rva + 108);
        }
        if (lc_size >= 116) {
            lc.guard_long_jump_target_table = get_dword_at_rva(rva + 112);
            lc.guard_long_jump_target_count = get_dword_at_rva(rva + 116);
        }
        if (lc_size >= 124) {
            lc.dynamic_value_reloc_table = get_dword_at_rva(rva + 120);
            lc.chpe_metadata_pointer = get_dword_at_rva(rva + 124);
        }
        if (lc_size >= 132) {
            lc.guard_rf_failure_routine = get_dword_at_rva(rva + 128);
            lc.guard_rf_failure_routine_function_pointer = get_dword_at_rva(rva + 132);
        }
        if (lc_size >= 140) {
            lc.dynamic_value_reloc_table_offset = get_dword_at_rva(rva + 136);
            lc.dynamic_value_reloc_table_section = get_word_at_rva(rva + 140);
            lc.reserved2 = get_word_at_rva(rva + 142);
        }
        if (lc_size >= 148) {
            lc.guard_rf_verify_stack_pointer_function_pointer = get_dword_at_rva(rva + 144);
            lc.hot_patch_table_offset = get_dword_at_rva(rva + 148);
        }
        if (lc_size >= 152) {
            lc.reserved3 = get_dword_at_rva(rva + 152);
        }
        if (lc_size >= 160) {
            lc.enclave_configuration_pointer = get_dword_at_rva(rva + 156);
            lc.volatile_metadata_pointer = get_dword_at_rva(rva + 160);
        }
        if (lc_size >= 168) {
            lc.guard_eh_continuation_table = get_dword_at_rva(rva + 164);
            lc.guard_eh_continuation_count = get_dword_at_rva(rva + 168);
        }
    }

    return lc;
}

std::vector<BoundImportDescData> PE::parse_directory_bound_imports(std::uint32_t rva, std::uint32_t size) {
    std::vector<BoundImportDescData> result;

    while (rva + 8 <= data_size_) {
        std::uint32_t time_date_stamp;
        std::uint16_t offset_module_name, number_of_module_forwarder_refs;
        auto offset = get_offset_from_rva(rva);
        if (offset + 8 > data_size_) break;

        std::memcpy(&time_date_stamp, data_.data() + offset, 4);
        std::memcpy(&offset_module_name, data_.data() + offset + 4, 2);
        std::memcpy(&number_of_module_forwarder_refs, data_.data() + offset + 6, 2);

        if (time_date_stamp == 0 && offset_module_name == 0 && number_of_module_forwarder_refs == 0) {
            break;
        }

        BoundImportDescData desc;
        desc.struct_offset = rva;
        desc.time_date_stamp = time_date_stamp;

        auto name_offset = rva + offset_module_name;
        desc.name = get_string_at_rva(name_offset, 256);

        rva += 8;
        for (std::uint16_t i = 0; i < number_of_module_forwarder_refs; i++) {
            rva += 8;
        }

        result.push_back(desc);
    }

    return result;
}

std::optional<VersionInfo> PE::parse_version_information(std::uint32_t rva) {
    auto start_offset = get_offset_from_rva(rva);
    if (start_offset >= data_size_) return std::nullopt;

    // Read VS_VERSIONINFO header: Length(u16), ValueLength(u16), Type(u16)
    if (start_offset + 6 > data_size_) return std::nullopt;
    std::uint16_t length = get_word_at_offset(start_offset);
    std::uint16_t value_length = get_word_at_offset(start_offset + 2);

    if (length == 0 || length > data_size_ - start_offset) return std::nullopt;

    std::string key = get_string_u_at_rva(rva + 6);
    if (key != "VS_VERSION_INFO") return std::nullopt;

    VersionInfo vi;
    vi.name = key;

    // VS_FIXEDFILEINFO follows the key, dword-aligned
    auto ffi_offset = dword_align(6 + 2 * (static_cast<std::uint32_t>(key.size()) + 1), rva);
    auto ffi_abs = start_offset + ffi_offset;

    // Verify the magic signature for VS_FIXEDFILEINFO
    if (ffi_abs + 4 <= data_size_) {
        std::uint32_t signature = get_dword_at_offset(ffi_abs);
        if (signature == 0xFEEF04BD) {
            if (value_length >= 52 || value_length == 0) {
                auto abs = ffi_abs;
                if (abs + 52 <= data_size_) {
                    vi.signature = signature;
                    vi.struct_version = get_word_at_offset(abs + 8) | (get_word_at_offset(abs + 10) << 16);
                    vi.version_ms = get_dword_at_offset(abs + 12);
                    vi.version_ls = get_dword_at_offset(abs + 16);
                    vi.product_version_ms = get_dword_at_offset(abs + 20);
                    vi.product_version_ls = get_dword_at_offset(abs + 24);
                    vi.file_flags_mask = get_dword_at_offset(abs + 28);
                    vi.file_flags = get_dword_at_offset(abs + 32);
                    vi.file_os = get_dword_at_offset(abs + 36);
                    vi.file_type = get_dword_at_offset(abs + 40);
                    vi.file_subtype = get_dword_at_offset(abs + 44);
                    vi.file_date_ms = get_dword_at_offset(abs + 48);
                    vi.file_date_ls = get_dword_at_offset(abs + 52);
                }
            }
        }
    }

    // Parse StringFileInfo and VarFileInfo blocks
    auto stringfileinfo_offset = dword_align(
        ffi_offset + (value_length ? value_length : 52), rva);

    while (start_offset + stringfileinfo_offset + 6 <= data_size_) {
        auto sf_offset = start_offset + stringfileinfo_offset;
        std::uint16_t sf_length = get_word_at_offset(sf_offset);
        if (sf_length == 0 || sf_offset + sf_length > data_size_) break;

        std::uint16_t sf_value_length = get_word_at_offset(sf_offset + 2);
        std::string sf_key = get_string_u_at_rva(get_rva_from_offset(sf_offset + 6));

        if (sf_key.starts_with("StringFileInfo") && sf_value_length == 0) {
            auto st_offset = dword_align(
                stringfileinfo_offset + 6 + 2 * (static_cast<std::uint32_t>(sf_key.size()) + 1), rva);

            while (start_offset + st_offset + 6 <= data_size_ &&
                   st_offset < stringfileinfo_offset + sf_length) {
                auto st_abs = start_offset + st_offset;
                std::uint16_t st_length = get_word_at_offset(st_abs);
                if (st_length == 0 || st_abs + st_length > data_size_) break;

                std::string st_key = get_string_u_at_rva(get_rva_from_offset(st_abs + 6));

                // Parse individual String entries within the StringTable
                auto str_offset = dword_align(
                    st_offset + 6 + 2 * (static_cast<std::uint32_t>(st_key.size()) + 1), rva);

                while (start_offset + str_offset + 6 <= data_size_ &&
                       str_offset < st_offset + st_length) {
                    auto str_abs = start_offset + str_offset;
                    std::uint16_t str_length = get_word_at_offset(str_abs);
                    std::uint16_t str_value_length = get_word_at_offset(str_abs + 2);
                    if (str_length == 0 || str_abs + str_length > data_size_) break;

                    auto str_key_offset = str_abs + 6;
                    std::string str_key = get_string_u_at_rva(
                        get_rva_from_offset(str_key_offset));

                    if (!str_key.empty() && str_value_length > 0) {
                        auto val_rva = get_rva_from_offset(dword_align(
                            str_offset + 6 + 2 * (static_cast<std::uint32_t>(str_key.size()) + 1), rva));
                        std::string val = get_string_u_at_rva(val_rva, str_value_length);
                        vi.strings[str_key] = val;
                    }

                    str_offset = dword_align(str_offset + str_length, rva);
                }

                st_offset = dword_align(st_offset + st_length, rva);
            }
        }

        stringfileinfo_offset = dword_align(stringfileinfo_offset + sf_length, rva);
    }

    return vi;
}

std::vector<DelayImportDescData> PE::parse_delay_import_directory(std::uint32_t rva, std::uint32_t size) {
    std::vector<DelayImportDescData> import_descs;
    std::size_t desc_size = 32;
    std::size_t error_count = 0;

    while (true) {
        if (rva + desc_size > data_size_) break;

        auto import_desc = ImageDelayImportDescriptor::parse(data_, rva);
        if (import_desc.all_zeroes()) break;

        std::uint32_t int_rva = import_desc.DelayINT;
        std::uint32_t iat_rva = import_desc.DelayIAT;

        if (import_desc.grAttrs() == 0 &&
            file_header_.Machine == static_cast<std::uint16_t>(MachineType::I386)) {
            auto image_base = optional_header_32_.ImageBase;
            int_rva = (int_rva != 0) ? int_rva - image_base : 0;
            iat_rva = (iat_rva != 0) ? iat_rva - image_base : 0;
        }

        rva += desc_size;

        auto file_offset = get_offset_from_rva(rva);
        std::uint32_t max_len = static_cast<std::uint32_t>(data_size_) - file_offset;
        if (rva > int_rva || rva > iat_rva) {
            max_len = std::max(
                rva - int_rva,
                rva - iat_rva);
        }

        std::vector<ImportData> import_data;
        try {
            import_data = parse_imports(int_rva, iat_rva, 0, max_len);
        } catch (const PEFormatError& e) {
            add_warning("Error parsing the Delay import directory. "
                "Invalid import data at RVA: 0x" + std::to_string(rva) +
                " (" + e.what() + ")");
        }

        if (error_count > 5) {
            add_warning("Too many errors parsing the Delay import directory. "
                "Invalid import data at RVA: 0x" + std::to_string(rva));
            break;
        }

        if (import_data.empty()) {
            error_count++;
            continue;
        }

        std::string dll = get_string_at_rva(import_desc.Name, MAX_DLL_LENGTH);
        if (!is_valid_dos_filename(dll)) dll = "*invalid*";

        if (!dll.empty()) {
            for (auto& symbol : import_data) {
                if (symbol.name.empty()) {
                    auto funcname = ordlookup::ordinal_lookup(dll, symbol.ordinal);
                    if (!funcname.empty()) {
                        symbol.name = funcname;
                        symbol.name_from_ordinal = true;
                    }
                }
            }
            DelayImportDescData desc;
            desc.dll = dll;
            desc.imports = std::move(import_data);
            desc.struct_offset = static_cast<std::uint32_t>(rva - desc_size);
            import_descs.push_back(std::move(desc));
        }
    }

    return import_descs;
}

std::optional<ImageResourceDataEntry> PE::parse_resource_data_entry(std::uint32_t rva) {
    if (rva + 16 > data_size_) return std::nullopt;
    return ImageResourceDataEntry::parse(data_, rva);
}

std::optional<ResourceDirData> PE::parse_resources_directory(
    std::uint32_t rva, std::uint32_t size, std::uint32_t base_rva,
    int level, std::vector<std::uint32_t> dirs) {

    if (level > static_cast<int>(MAX_RESOURCE_DEPTH)) {
        add_warning("Error parsing the resources directory. "
            "Excessively nested table depth " + std::to_string(level));
        return std::nullopt;
    }

    if (rva + 16 > data_size_) {
        add_warning("Invalid resources directory. Can't read directory data at RVA: 0x" +
            std::to_string(rva));
        return std::nullopt;
    }

    if (base_rva == 0) base_rva = rva;

    auto resource_dir = ImageResourceDirectory::parse(data_, rva);
    std::uint32_t number_of_entries = resource_dir.NumberOfNamedEntries +
                                      resource_dir.NumberOfIdEntries;

    if (number_of_entries > MAX_ALLOWED_RESOURCE_ENTRIES) {
        add_warning("Error parsing the resources directory. "
            "The directory contains " + std::to_string(number_of_entries) + " entries");
        return std::nullopt;
    }

    std::uint32_t entry_rva = rva + 16;
    std::vector<ResourceDirEntryData> dir_entries;

    for (std::uint32_t idx = 0; idx < number_of_entries; idx++) {
        if (entry_rva + 8 > data_size_) break;

        auto res = ImageResourceDirectoryEntry::parse(data_, entry_rva);

        std::string entry_name;
        std::uint32_t entry_id = 0;

        if (res.is_name()) {
            auto name_offset = base_rva + res.name_id();
            entry_name = get_string_u_at_rva(name_offset, 256);
        } else {
            entry_id = res.Name & 0xFFFF;
        }

        if (res.is_directory()) {
            auto subdir_rva = base_rva + res.offset();

            bool cycle = false;
            for (auto d : dirs) {
                if (d == subdir_rva) { cycle = true; break; }
            }
            if (cycle) break;

            dirs.push_back(subdir_rva);
            auto subdir = parse_resources_directory(
                subdir_rva, size - (rva - base_rva), base_rva, level + 1, dirs);

            if (subdir) {
                dir_entries.push_back(ResourceDirEntryData{
                    entry_rva, entry_name, entry_id,
                    std::make_shared<ResourceDirData>(*subdir), nullptr});
            } else {
                break;
            }
        } else {
            auto data_entry_rva = base_rva + res.offset();
            auto data_entry = parse_resource_data_entry(data_entry_rva);

            if (data_entry) {
                auto entry_data = std::make_shared<ResourceDataEntryData>();
                entry_data->struct_offset = data_entry_rva;
                entry_data->lang = res.Name & 0x3FF;
                entry_data->sublang = res.Name >> 10;
                entry_data->data_rva = data_entry->OffsetToData;
                entry_data->size = data_entry->Size;

                dir_entries.push_back(ResourceDirEntryData{
                    entry_rva, entry_name, entry_id, nullptr, entry_data});
            } else {
                break;
            }
        }

        entry_rva += 8;
    }

    return ResourceDirData{rva, std::move(dir_entries)};
}

std::string PE::get_imphash() const {
    if (imports_.empty()) return "";

    std::string result;
    for (auto& entry : imports_) {
        std::string libname = entry.dll;
        std::transform(libname.begin(), libname.end(), libname.begin(),
            [](unsigned char c) { return std::tolower(c); });

        std::string ext;
        auto dot_pos = libname.rfind('.');
        if (dot_pos != std::string::npos) {
            ext = libname.substr(dot_pos + 1);
        }

        std::string base_name = libname;
        if (ext == "ocx" || ext == "sys" || ext == "dll") {
            base_name = libname.substr(0, dot_pos);
        }

        for (auto& imp : entry.imports) {
            std::string funcname;
            if (imp.name.empty() || imp.name_from_ordinal) {
                funcname = ordlookup::imphash_ordinal_lookup(libname, imp.ordinal);
            } else {
                funcname = imp.name;
            }
            if (funcname.empty()) continue;

            std::transform(funcname.begin(), funcname.end(), funcname.begin(),
                [](unsigned char c) { return std::tolower(c); });

            if (!result.empty()) result += ",";
            result += base_name + "." + funcname;
        }
    }

    MD5 md5;
    md5.update(result);
    return md5.hexdigest();
}

std::string PE::get_exphash() const {
    if (!exports_ || exports_->symbols.empty()) return "";
    std::string result;
    for (auto& exp : exports_->symbols) {
        if (exp.name.empty()) continue;
        if (!result.empty()) result += ",";
        std::string name = exp.name;
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char c) { return std::tolower(c); });
        result += name;
    }
    if (result.empty()) return "";

    MD5 md5;
    md5.update(result);
    return md5.hexdigest();
}

void PE::show_warnings() const {
    for (auto& w : warnings_) {
        std::cerr << "> " << w << "\n";
    }
}

std::string PE::dump_info() const {
    std::ostringstream ss;
    ss << "DOS Header:\n";
    ss << "  e_magic: 0x" << std::hex << dos_header_.e_magic << "\n";
    ss << "  e_lfanew: 0x" << dos_header_.e_lfanew << "\n";
    ss << "\nFile Header:\n";
    ss << "  Machine: 0x" << file_header_.Machine << "\n";
    ss << "  NumberOfSections: " << std::dec << file_header_.NumberOfSections << "\n";
    ss << "  Characteristics: 0x" << std::hex << file_header_.Characteristics << "\n";

    if (rich_header_) {
        ss << "\nRich Header:\n";
        ss << "  Checksum: 0x" << std::hex << rich_header_->checksum << "\n";
        ss << "  Values: " << std::dec << rich_header_->values.size() << " pairs\n";
    }

    ss << "\nSections:\n";
    for (auto& s : sections_) {
        ss << "  " << s.name() << ": VA=0x" << std::hex << s.VirtualAddress
           << " Size=0x" << s.SizeOfRawData
           << " Chars=0x" << s.Characteristics << "\n";
    }

    if (!imports_.empty()) {
        ss << "\nImports:\n";
        for (auto& imp : imports_) {
            ss << "  " << imp.dll << " (" << imp.imports.size() << " symbols)\n";
        }
    }

    if (!delay_imports_.empty()) {
        ss << "\nDelay Imports:\n";
        for (auto& imp : delay_imports_) {
            ss << "  " << imp.dll << " (" << imp.imports.size() << " symbols)\n";
        }
    }

    if (exports_) {
        ss << "\nExports:\n";
        ss << "  " << exports_->name << " (" << exports_->symbols.size() << " symbols)\n";
    }

    if (!relocations_.empty()) {
        ss << "\nRelocations:\n";
        std::size_t total_entries = 0;
        for (auto& r : relocations_) total_entries += r.entries.size();
        ss << "  " << relocations_.size() << " blocks (" << total_entries << " entries)\n";
    }

    if (tls_data_) {
        ss << "\nTLS:\n";
        ss << "  StartAddressOfRawData: 0x" << std::hex << tls_data_->start_address_of_raw_data << "\n";
        ss << "  AddressOfIndex: 0x" << tls_data_->address_of_index << "\n";
    }

    if (load_config_data_) {
        ss << "\nLoad Config:\n";
        ss << "  Size: " << std::dec << load_config_data_->size << "\n";
        ss << "  GuardFlags: 0x" << std::hex << load_config_data_->guard_flags << "\n";
    }

    if (version_info_) {
        ss << "\nVersion Info:\n";
        ss << "  Signature: 0x" << std::hex << version_info_->signature << "\n";
        ss << "  FileOS: 0x" << version_info_->file_os << "\n";
        ss << "  FileType: 0x" << version_info_->file_type << "\n";
        if (!version_info_->strings.empty()) {
            ss << "  Strings:\n";
            for (auto& [k, v] : version_info_->strings) {
                ss << "    " << k << ": " << v << "\n";
            }
        }
    }

    if (!resources_.empty()) {
        ss << "\nResources:\n";
        for (auto& res_dir : resources_) {
            ss << "  " << res_dir.entries.size() << " top-level entries\n";
        }
    }

    if (!exceptions_.empty()) {
        ss << "\nExceptions:\n";
        ss << "  " << exceptions_.size() << " entries\n";
    }

    if (!bound_imports_.empty()) {
        ss << "\nBound Imports:\n";
        ss << "  " << bound_imports_.size() << " entries\n";
    }

    if (!warnings_.empty()) {
        ss << "\nWarnings:\n";
        for (auto& w : warnings_) {
            ss << "  " << w << "\n";
        }
    }

    return ss.str();
}

std::vector<std::string> PE::get_resources_strings() const {
    std::vector<std::string> result;
    for (auto& res_dir : resources_) {
        for (auto& entry : res_dir.entries) {
            if (entry.directory) {
                for (auto& sub_entry : entry.directory->entries) {
                    if (sub_entry.data_entry && sub_entry.id == static_cast<std::uint32_t>(ResourceType::STRING)) {
                        auto rva = sub_entry.data_entry->data_rva;
                        auto size = sub_entry.data_entry->size;
                        if (rva + size <= data_size_) {
                            auto str = get_string_u_at_rva(rva, size / 2);
                            if (!str.empty()) {
                                result.push_back(str);
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}

std::optional<RichHeaderData> PE::parse_rich_header() {
    constexpr std::uint32_t DANS = 0x536E6144;
    constexpr std::uint32_t RICH = 0x68636952;

    auto optional_header_end = static_cast<std::size_t>(dos_header_.e_lfanew) + 4 + 20 +
                               file_header_.SizeOfOptionalHeader;
    auto search_end = std::min(optional_header_end, data_size_);

    if (search_end < 0x80) return std::nullopt;

    const std::uint8_t rich_tag_bytes[] = { 0x52, 0x69, 0x63, 0x68 };
    std::size_t rich_index = 0;
    for (std::size_t i = 0x80; i + 4 <= search_end; i++) {
        if (std::memcmp(data_.data() + i, rich_tag_bytes, 4) == 0) {
            rich_index = i;
            break;
        }
    }
    if (rich_index == 0) return std::nullopt;

    std::size_t block_len = rich_index + 8 - 0x80;
    block_len = 4 * (block_len / 4);
    if (block_len == 0) return std::nullopt;

    std::vector<std::uint32_t> data(block_len / 4);
    for (std::size_t i = 0; i < data.size(); i++) {
        std::memcpy(&data[i], data_.data() + 0x80 + i * 4, 4);
    }

    auto rich_pos = std::find(data.begin(), data.end(), RICH);
    if (rich_pos == data.end()) return std::nullopt;

    std::uint32_t checksum = *(rich_pos + 1);

    RichHeaderData result;
    result.checksum = checksum;
    result.raw_data.assign(data_.data() + 0x80, data_.data() + 0x80 + rich_index - 0x80);

    result.clear_data.resize(rich_index - 0x80);
    for (std::size_t i = 0; i + 3 < result.raw_data.size(); i += 4) {
        std::uint32_t val;
        std::memcpy(&val, result.raw_data.data() + i, 4);
        val ^= checksum;
        std::memcpy(result.clear_data.data() + i, &val, 4);
    }

    auto dans_pos = data.begin();
    if (data.size() >= 4) {
        if (data[0] != (DANS ^ checksum) ||
            data[1] != checksum ||
            data[2] != checksum ||
            data[3] != checksum) {
            add_warning("Rich Header is not in Microsoft format, possibly malformed");
        }
    }

    auto after_dans = dans_pos + 4;
    auto end_pos = rich_pos;
    for (auto it = after_dans; it + 1 < end_pos; it += 2) {
        result.values.push_back({*it ^ checksum, *(it + 1) ^ checksum});
    }

    return result;
}

std::string PE::get_rich_header_hash() const {
    if (!rich_header_ || rich_header_->clear_data.empty()) return "";

    MD5 md5;
    md5.update(rich_header_->clear_data);
    return md5.hexdigest();
}

} // namespace pefile
