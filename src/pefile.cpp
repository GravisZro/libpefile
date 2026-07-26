#include "pefile.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <functional>

#include "ordlookup.hpp"
#include "hashing.hpp"

namespace pefile {

namespace {
constexpr size_t MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69;
constexpr int MAX_SIMULTANEOUS_ERRORS = 3;
constexpr size_t MAX_ALLOWED_RESOURCE_ENTRIES = 4096;
constexpr size_t MAX_REPEATED_ADDRESSES = 15;
constexpr size_t MAX_ADDRESS_SPREAD = 128 * 1024 * 1024;
constexpr uint64_t ADDR_4GB = 0x100000000ULL;
}

// UnwindInfo parse (variable-size struct)
UnwindInfo UnwindInfo::parse(std::span<const uint8_t> data, size_t offset) {
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
    for (int i = 0; i < h.CountOfCodes && (p - data.data()) + 2 <= static_cast<long long>(data.size()); i++) {
        uint16_t code;
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
    m_data.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(m_data.data()), size);
    m_data_size = m_data.size();
    parse();
    if (!fast_load) {
        full_load();
    }
}

PE::PE(std::span<const uint8_t> data, bool fast_load) {
    m_data.assign(data.begin(), data.end());
    m_data_size = m_data.size();
    parse();
    if (!fast_load) {
        full_load();
    }
}

PE::~PE() = default;
PE::PE(PE&&) noexcept = default;
PE& PE::operator=(PE&&) noexcept = default;

void PE::parse() {
    if (m_data_size < 64) {
        throw PEFormatError("File too small for DOS header");
    }

    m_dos_header = DosHeader::parse(m_data, 0);
    if (m_dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        throw PEFormatError("Invalid DOS signature");
    }

    auto nt_headers_offset = static_cast<size_t>(m_dos_header.e_lfanew);
    if (nt_headers_offset + 4 > m_data_size) {
        throw PEFormatError("Invalid NT headers offset");
    }

    uint32_t signature = read_packed<uint32_t>(m_data, nt_headers_offset);

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

    m_file_header = FileHeader::parse(m_data, nt_headers_offset + 4);

    auto optional_header_offset = nt_headers_offset + 4 + 20;
    auto sections_offset = optional_header_offset + m_file_header.SizeOfOptionalHeader;

    if (sections_offset > m_data_size) {
        throw PEFormatError("Sections offset beyond file");
    }

    if (optional_header_offset + 256 <= m_data_size) {
        auto oh_data = std::span<const uint8_t>(
            m_data.data() + optional_header_offset,
            std::min<size_t>(256, m_data_size - optional_header_offset));
        m_optional_header_32 = OptionalHeader32::parse(oh_data, 0);
    }

    if (m_optional_header_32.Magic == OPTIONAL_HEADER_MAGIC_PE) {
        m_pe_type = OPTIONAL_HEADER_MAGIC_PE;
    } else if (m_optional_header_32.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS) {
        m_pe_type = OPTIONAL_HEADER_MAGIC_PE_PLUS;
        m_is_pe32_plus = true;
        m_optional_header_64 = read_packed<OptionalHeader64>(m_data, optional_header_offset);
    } else {
        add_warning("Invalid type in Optional Header: 0x" +
            std::to_string(m_optional_header_32.Magic));
    }

    if (m_pe_type == 0) {
        throw PEFormatError("No Optional Header found, invalid PE32 or PE32+ file.");
    }

    size_t dir_offset = optional_header_offset + (is_pe32_plus() ? 112 : 96);
    uint32_t num_dirs = is_pe32_plus() ?
        m_optional_header_64.NumberOfRvaAndSizes :
        m_optional_header_32.NumberOfRvaAndSizes;

    if (num_dirs > 0x10) {
        add_warning("Suspicious NumberOfRvaAndSizes: 0x" +
            std::to_string(num_dirs));
    }

    uint32_t dir_count = std::min(num_dirs, static_cast<uint32_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
    for (uint32_t i = 0; i < dir_count; i++) {
        if (dir_offset + 8 > m_data_size) break;
        auto dd = DataDirectory::parse(m_data, dir_offset);
        dd.name = std::string(directory_entry_name(static_cast<DirectoryEntry>(i)));
        m_data_directories.push_back(dd);
        dir_offset += 8;
    }

    parse_sections(sections_offset);

    m_rich_header = parse_rich_header();

    if (m_pe_type == OPTIONAL_HEADER_MAGIC_PE) {
        auto ep = m_optional_header_32.AddressOfEntryPoint;
        if (ep != 0 && get_section_by_rva(ep).has_value()) {
            auto ep_offset = get_offset_from_rva(ep);
            if (ep_offset > m_data_size) {
                add_warning("AddressOfEntryPoint lies outside the file");
            }
        }
    } else {
        auto ep = m_optional_header_64.AddressOfEntryPoint;
        if (ep != 0 && get_section_by_rva(ep).has_value()) {
            auto ep_offset = get_offset_from_rva(ep);
            if (ep_offset > m_data_size) {
                add_warning("AddressOfEntryPoint lies outside the file");
            }
        }
    }
}

void PE::full_load() {
    parse_data_directories();
}

void PE::parse_sections(size_t offset, size_t max_offset) {
    m_sections.clear();

    for (uint16_t i = 0; i < m_file_header.NumberOfSections; i++) {
        if (i >= MAX_SECTIONS) {
            add_warning("Too many sections");
            break;
        }

        auto section_offset = offset + 40 * i;
        if (section_offset + 40 > m_data_size) break;

        auto section_data = std::span<const uint8_t>(
            m_data.data() + section_offset,
            std::min<size_t>(40, m_data_size - section_offset));

        if (count_zeroes(section_data) == 40) {
            add_warning("Invalid section " + std::to_string(i) + ". Contents are null-bytes.");
            break;
        }

        auto section = SectionHeader::parse(section_data, 0);

        auto section_alignment = is_pe32_plus() ?
            m_optional_header_64.SectionAlignment : m_optional_header_32.SectionAlignment;
        auto file_alignment = is_pe32_plus() ?
            m_optional_header_64.FileAlignment : m_optional_header_32.FileAlignment;

        if (static_cast<uint64_t>(section.SizeOfRawData) + section.PointerToRawData > m_data_size) {
            add_warning("Error parsing section " + std::to_string(i) + ". SizeOfRawData is larger than file.");
        }

        if (section.VirtualSize > max_offset) {
            add_warning("Suspicious value found parsing section " + std::to_string(i) + ". VirtualSize is extremely large.");
        }

        if (adjust_section_alignment(section.VirtualAddress, section_alignment, file_alignment) > max_offset) {
            add_warning("Suspicious value found parsing section " + std::to_string(i) + ". VirtualAddress is beyond limit.");
        }

        m_sections.push_back(section);
    }

    std::sort(m_sections.begin(), m_sections.end(),
        [](const SectionHeader& a, const SectionHeader& b) {
            return a.VirtualAddress < b.VirtualAddress;
        });

    for (auto& section : m_sections) {
        if ((section.Characteristics & static_cast<uint32_t>(SectionCharacteristic::MEM_WRITE)) &&
            (section.Characteristics & static_cast<uint32_t>(SectionCharacteristic::MEM_EXECUTE))) {
            std::string name(section.Name, strnlen(section.Name, 8));
            if (name == "PAGE" && is_driver()) {
                continue;
            }
            add_warning("Suspicious flags set for section with write+execute.");
        }
    }
}

const SectionHeader* PE::find_section_for_rva(uint32_t rva) const {
    for (auto& s : m_sections) {
        if (s.VirtualAddress <= rva &&
            rva < s.VirtualAddress + static_cast<uint32_t>(std::max(s.SizeOfRawData, s.VirtualSize))) {
            return &s;
        }
    }
    return nullptr;
}

const SectionHeader* PE::find_section_for_offset(uint32_t offset) const {
    for (auto& s : m_sections) {
        if (s.PointerToRawData <= offset &&
            offset < static_cast<uint64_t>(s.PointerToRawData) + s.SizeOfRawData) {
            return &s;
        }
    }
    return nullptr;
}

uint32_t PE::get_offset_from_rva(uint32_t rva) const {
    for (auto& s : m_sections) {
        if (s.VirtualAddress <= rva &&
            rva < s.VirtualAddress + static_cast<uint32_t>(std::max(s.SizeOfRawData, s.VirtualSize))) {
            return s.PointerToRawData + (rva - s.VirtualAddress);
        }
    }
    return rva;
}

uint32_t PE::get_rva_from_offset(uint32_t offset) const {
    for (auto& s : m_sections) {
        if (s.PointerToRawData <= offset && offset < static_cast<uint64_t>(s.PointerToRawData) + s.SizeOfRawData) {
            return s.VirtualAddress + (offset - s.PointerToRawData);
        }
    }
    return offset;
}

std::span<const uint8_t> PE::get_data_span(uint32_t rva, uint32_t length) const {
    if (rva + length > m_data_size || rva + length < rva) {
        throw PEFormatError("RVA out of bounds");
    }
    return std::span<const uint8_t>(m_data.data() + rva, length);
}

std::span<const uint8_t> PE::get_data(uint32_t rva, std::optional<uint32_t> length) const {
    auto section = find_section_for_rva(rva);
    if (!section) {
        if (!length) {
            length = 1;
        }
        return get_data_span(rva, *length);
    }

    auto file_offset = get_offset_from_rva(rva);
    auto section_end = static_cast<uint64_t>(section->PointerToRawData) + section->SizeOfRawData;

    if (length) {
        auto end = file_offset + *length;
        if (end > m_data_size) end = m_data_size;
        if (file_offset >= m_data_size) throw PEFormatError("Offset out of bounds");
        return std::span<const uint8_t>(m_data.data() + file_offset, end - file_offset);
    }

    auto max_len = std::min(static_cast<uint32_t>(m_data_size), static_cast<uint32_t>(section_end)) - file_offset;
    if (file_offset >= m_data_size || max_len > m_data_size) throw PEFormatError("Offset out of bounds");
    return std::span<const uint8_t>(m_data.data() + file_offset, max_len);
}

std::vector<uint8_t> PE::get_data_copy(uint32_t rva, std::optional<uint32_t> length) const {
    auto span = get_data(rva, length);
    return {span.begin(), span.end()};
}

std::optional<std::reference_wrapper<const SectionHeader>> PE::get_section_by_rva(uint32_t rva) const {
    auto section = find_section_for_rva(rva);
    if (!section) return std::nullopt;
    return std::cref(*section);
}

std::optional<std::reference_wrapper<const SectionHeader>> PE::get_section_by_offset(uint32_t offset) const {
    auto section = find_section_for_offset(offset);
    if (!section) return std::nullopt;
    return std::cref(*section);
}

std::string PE::get_string_at_rva(uint32_t rva, size_t max_length) const {
    std::string result;
    auto base_offset = get_offset_from_rva(rva);
    if (base_offset >= m_data_size) return result;
    for (size_t i = 0; i < max_length && base_offset + i < m_data_size; i++) {
        char c = static_cast<char>(m_data[base_offset + i]);
        if (c == '\0') break;
        result += c;
    }
    return result;
}

std::string PE::get_string_u_at_rva(uint32_t rva, size_t max_length) const {
    std::string result;
    auto offset = get_offset_from_rva(rva);
    for (size_t i = 0; i < max_length * 2 && offset + i + 1 < m_data_size; i += 2) {
        char c1 = static_cast<char>(m_data[offset + i]);
        char c2 = static_cast<char>(m_data[offset + i + 1]);
        if (c1 == '\0' && c2 == '\0') break;
        if (c2 == '\0') {
            result += c1;
            break;
        }
        result += c1;
    }
    return result;
}

void PE::relocate_image(uint64_t new_image_base) {
    uint64_t current_imagebase = is_pe32_plus() ?
        m_optional_header_64.ImageBase : m_optional_header_32.ImageBase;
    int64_t relocation_difference =
        static_cast<int64_t>(new_image_base) - static_cast<int64_t>(current_imagebase);

    if (m_data_directories.size() > static_cast<size_t>(DirectoryEntry::BASERELOC) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)].Size) {
        if (m_relocations.empty()) {
            auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)];
            m_relocations = parse_relocations_directory(dir.VirtualAddress, dir.Size);
        }
        if (m_relocations.empty()) {
            add_warning("Relocating image but PE does not have a parseable DIRECTORY_ENTRY_BASERELOC");
        } else {
            constexpr uint32_t IMAGE_REL_BASED_ABSOLUTE = 0;
            constexpr uint32_t IMAGE_REL_BASED_HIGH = 1;
            constexpr uint32_t IMAGE_REL_BASED_LOW = 2;
            constexpr uint32_t IMAGE_REL_BASED_HIGHLOW = 3;
            constexpr uint32_t IMAGE_REL_BASED_HIGHADJ = 4;
            constexpr uint32_t IMAGE_REL_BASED_DIR64 = 10;

            for (auto& reloc : m_relocations) {
                size_t entry_idx = 0;
                while (entry_idx < reloc.entries.size()) {
                    auto& entry = reloc.entries[entry_idx];
                    entry_idx++;

                    if (entry.type == IMAGE_REL_BASED_ABSOLUTE) {
                        continue;
                    } else if (entry.type == IMAGE_REL_BASED_HIGH) {
                        uint16_t v = get_word_at_rva(entry.rva);
                        v = static_cast<uint16_t>(
                            (static_cast<uint32_t>(v) +
                             (static_cast<uint32_t>(relocation_difference) >> 16)) & 0xFFFF);
                        set_word_at_rva(entry.rva, v);
                    } else if (entry.type == IMAGE_REL_BASED_LOW) {
                        uint16_t v = get_word_at_rva(entry.rva);
                        v = static_cast<uint16_t>(
                            (static_cast<uint32_t>(v) +
                             static_cast<uint32_t>(relocation_difference & 0xFFFF)) & 0xFFFF);
                        set_word_at_rva(entry.rva, v);
                    } else if (entry.type == IMAGE_REL_BASED_HIGHLOW) {
                        uint32_t v = get_dword_at_rva(entry.rva);
                        v = static_cast<uint32_t>(
                            static_cast<int64_t>(v) + relocation_difference);
                        set_dword_at_rva(entry.rva, v);
                    } else if (entry.type == IMAGE_REL_BASED_HIGHADJ) {
                        if (entry_idx >= reloc.entries.size()) break;
                        const auto& next = reloc.entries[entry_idx];
                        entry_idx++;
                        uint16_t v = get_word_at_rva(entry.rva);
                        uint32_t result = ((static_cast<uint32_t>(v) << 16) +
                                           next.rva + static_cast<uint32_t>(relocation_difference)) & 0xFFFF0000;
                        set_word_at_rva(entry.rva, static_cast<uint16_t>(result >> 16));
                    } else if (entry.type == IMAGE_REL_BASED_DIR64) {
                        uint64_t v = get_qword_at_rva(entry.rva);
                        v = static_cast<uint64_t>(static_cast<int64_t>(v) + relocation_difference);
                        set_qword_at_rva(entry.rva, v);
                    }
                }
            }
        }
    }

    if (is_pe32_plus()) {
        m_optional_header_64.ImageBase = new_image_base;
    } else {
        m_optional_header_32.ImageBase = static_cast<uint32_t>(new_image_base);
    }

    for (auto& import_desc : m_imports) {
        for (auto& imp : import_desc.imports) {
            imp.address = static_cast<uint64_t>(
                static_cast<int64_t>(imp.address) + relocation_difference);
        }
    }

    if (m_tls_data) {
        m_tls_data->start_address_of_raw_data = static_cast<uint64_t>(
            static_cast<int64_t>(m_tls_data->start_address_of_raw_data) + relocation_difference);
        m_tls_data->end_address_of_raw_data = static_cast<uint64_t>(
            static_cast<int64_t>(m_tls_data->end_address_of_raw_data) + relocation_difference);
        m_tls_data->address_of_index = static_cast<uint64_t>(
            static_cast<int64_t>(m_tls_data->address_of_index) + relocation_difference);
        m_tls_data->address_of_callbacks = static_cast<uint64_t>(
            static_cast<int64_t>(m_tls_data->address_of_callbacks) + relocation_difference);
    }
}

std::vector<uint8_t> PE::get_memory_mapped_image(uint32_t max_virtual_address,
                                            std::optional<uint64_t> image_base) const {
    auto size_of_image = is_pe32_plus() ?
        m_optional_header_64.SizeOfImage : m_optional_header_32.SizeOfImage;
    auto image_size = std::min(size_of_image, max_virtual_address);
    std::vector<uint8_t> mapped(image_size, 0);

    auto headers_size = is_pe32_plus() ?
        m_optional_header_64.SizeOfHeaders : m_optional_header_32.SizeOfHeaders;
    auto copy_size = std::min(static_cast<size_t>(headers_size), m_data_size);
    std::memcpy(mapped.data(), m_data.data(), copy_size);

    for (auto& section : m_sections) {
        if (section.VirtualAddress >= max_virtual_address) continue;
        if (section.VirtualAddress + section.SizeOfRawData > max_virtual_address) continue;
        if (static_cast<uint64_t>(section.PointerToRawData) + section.SizeOfRawData > m_data_size) continue;
        if (static_cast<uint64_t>(section.VirtualAddress) + section.SizeOfRawData > image_size) continue;
        std::memcpy(mapped.data() + section.VirtualAddress,
                    m_data.data() + section.PointerToRawData,
                    section.SizeOfRawData);
    }

    if (image_base) {
        uint64_t current_imagebase = is_pe32_plus() ?
            m_optional_header_64.ImageBase : m_optional_header_32.ImageBase;
        int64_t delta = static_cast<int64_t>(*image_base) -
                        static_cast<int64_t>(current_imagebase);

        if (m_relocations.empty() &&
            m_data_directories.size() > static_cast<size_t>(DirectoryEntry::BASERELOC) &&
            m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)].Size) {
            const_cast<PE*>(this)->m_relocations = parse_relocations_directory(
                m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)].VirtualAddress,
                m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)].Size);
        }

        constexpr uint32_t R_HIGH = 1, R_LOW = 2, R_HIGHLOW = 3,
                           R_HIGHADJ = 4, R_DIR64 = 10;

        for (auto& reloc : m_relocations) {
            size_t entry_idx = 0;
            while (entry_idx < reloc.entries.size()) {
                auto& entry = reloc.entries[entry_idx];
                entry_idx++;
                uint32_t rva = entry.rva;
                if (rva >= mapped.size()) continue;

                if (entry.type == R_HIGH) {
                    if (rva + 2 > mapped.size()) continue;
                    uint16_t v;
                    std::memcpy(&v, mapped.data() + rva, 2);
                    v = static_cast<uint16_t>(
                        (static_cast<uint32_t>(v) +
                         (static_cast<uint32_t>(delta) >> 16)) & 0xFFFF);
                    std::memcpy(mapped.data() + rva, &v, 2);
                } else if (entry.type == R_LOW) {
                    if (rva + 2 > mapped.size()) continue;
                    uint16_t v;
                    std::memcpy(&v, mapped.data() + rva, 2);
                    v = static_cast<uint16_t>(
                        (static_cast<uint32_t>(v) +
                         static_cast<uint32_t>(delta & 0xFFFF)) & 0xFFFF);
                    std::memcpy(mapped.data() + rva, &v, 2);
                } else if (entry.type == R_HIGHLOW) {
                    if (rva + 4 > mapped.size()) continue;
                    uint32_t v;
                    std::memcpy(&v, mapped.data() + rva, 4);
                    v = static_cast<uint32_t>(static_cast<int64_t>(v) + delta);
                    std::memcpy(mapped.data() + rva, &v, 4);
                } else if (entry.type == R_HIGHADJ) {
                    if (entry_idx >= reloc.entries.size()) break;
                    const auto& next = reloc.entries[entry_idx];
                    entry_idx++;
                    if (rva + 2 > mapped.size()) continue;
                    uint16_t v;
                    std::memcpy(&v, mapped.data() + rva, 2);
                    uint32_t highadj = (((static_cast<uint32_t>(v) << 16) +
                                         next.rva +
                                         static_cast<uint32_t>(delta)) & 0xFFFF0000) >> 16;
                    std::memcpy(mapped.data() + rva, &highadj, 2);
                } else if (entry.type == R_DIR64) {
                    if (rva + 8 > mapped.size()) continue;
                    uint64_t v;
                    std::memcpy(&v, mapped.data() + rva, 8);
                    v = static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
                    std::memcpy(mapped.data() + rva, &v, 8);
                }
            }
        }
    }

    return mapped;
}

std::span<const uint8_t> PE::get_overlay() const {
    if (m_sections.empty()) return {};
    uint32_t max_end = 0;
    for (auto& s : m_sections) {
        auto end = static_cast<uint64_t>(s.PointerToRawData) + s.SizeOfRawData;
        if (end > max_end && end <= UINT32_MAX) max_end = static_cast<uint32_t>(end);
    }
    if (max_end >= m_data_size) return {};
    return std::span<const uint8_t>(m_data.data() + max_end, m_data_size - max_end);
}

std::optional<uint32_t> PE::get_overlay_data_start_offset() const {
    if (m_sections.empty()) return std::nullopt;
    uint32_t max_end = 0;
    for (auto& s : m_sections) {
        auto end = static_cast<uint64_t>(s.PointerToRawData) + s.SizeOfRawData;
        if (end > max_end && end <= UINT32_MAX) max_end = static_cast<uint32_t>(end);
    }
    if (max_end >= m_data_size) return std::nullopt;
    return max_end;
}

std::vector<uint8_t> PE::trim() const {
    if (m_sections.empty()) {
        return {m_data.begin(), m_data.end()};
    }
    uint32_t max_end = 0;
    for (auto& s : m_sections) {
        auto end = static_cast<uint64_t>(s.PointerToRawData) + s.SizeOfRawData;
        if (end > max_end && end <= UINT32_MAX) max_end = static_cast<uint32_t>(end);
    }
    return {m_data.begin(), m_data.begin() + std::min(max_end, static_cast<uint32_t>(m_data_size))};
}

bool PE::is_exe() const {
    return (m_file_header.Characteristics & static_cast<uint16_t>(ImageCharacteristic::EXECUTABLE_IMAGE)) != 0 &&
           (m_file_header.Characteristics & static_cast<uint16_t>(ImageCharacteristic::DLL)) == 0;
}

bool PE::is_dll() const {
    return (m_file_header.Characteristics & static_cast<uint16_t>(ImageCharacteristic::DLL)) != 0;
}

bool PE::is_driver() const {
    auto sub = is_pe32_plus() ? m_optional_header_64.Subsystem : m_optional_header_32.Subsystem;
    if (sub == 1) return true;
    if (sub == 10 || sub == 11 || sub == 12 || sub == 13) return true;
    return false;
}

bool PE::has_relocs() const {
    return !m_relocations.empty();
}

bool PE::has_dynamic_relocs() const {
    if (m_load_config_data && m_load_config_data->dynamic_value_reloc_table != 0) {
        return true;
    }
    return false;
}

bool PE::verify_checksum() const {
    return generate_checksum() == (is_pe32_plus() ?
        m_optional_header_64.CheckSum : m_optional_header_32.CheckSum);
}

uint32_t PE::generate_checksum() const {
    uint64_t checksum = 0;
    size_t size = m_data_size;
    auto ptr = m_data.data();

    // The checksum field itself must be treated as zero during computation.
    // It sits at NT headers offset + 24 (sig+COFF) + 64 (within optional header).
    auto checksum_offset = static_cast<size_t>(m_dos_header.e_lfanew) + 88;
    auto checksum_dword_idx = checksum_offset / 4;

    for (size_t i = 0; i < size / 4; i++) {
        uint32_t dword_val;
        std::memcpy(&dword_val, ptr + i * 4, 4);
        if (i == checksum_dword_idx) dword_val = 0;
        checksum += dword_val;
        if (checksum > 0xFFFFFFFF) {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
    }

    ptr += (size / 4) * 4;
    size_t remaining = size % 4;
    if (remaining > 0) {
        uint32_t dword_val = 0;
        std::memcpy(&dword_val, ptr, remaining);
        checksum += dword_val;
        if (checksum > 0xFFFFFFFF) {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
    }

    checksum = static_cast<uint32_t>((checksum & 0xFFFF) + (checksum >> 16));
    checksum = static_cast<uint32_t>(checksum + (checksum >> 16));
    checksum &= 0xFFFF;
    checksum += size;

    return static_cast<uint32_t>(checksum);
}

uint8_t PE::get_byte_at_rva(uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset >= m_data_size) return 0;
    return m_data[offset];
}

uint16_t PE::get_word_at_rva(uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset + 2 > m_data_size) return 0;
    uint16_t val;
    std::memcpy(&val, m_data.data() + offset, 2);
    return val;
}

uint32_t PE::get_dword_at_rva(uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset + 4 > m_data_size) return 0;
    uint32_t val;
    std::memcpy(&val, m_data.data() + offset, 4);
    return val;
}

uint64_t PE::get_qword_at_rva(uint32_t rva) const {
    auto offset = get_offset_from_rva(rva);
    if (offset + 8 > m_data_size) return 0;
    uint64_t val;
    std::memcpy(&val, m_data.data() + offset, 8);
    return val;
}

uint8_t PE::get_byte_at_offset(uint32_t offset) const {
    if (offset >= m_data_size) return 0;
    return m_data[offset];
}

uint16_t PE::get_word_at_offset(uint32_t offset) const {
    if (offset + 2 > m_data_size) return 0;
    uint16_t val;
    std::memcpy(&val, m_data.data() + offset, 2);
    return val;
}

uint32_t PE::get_dword_at_offset(uint32_t offset) const {
    if (offset + 4 > m_data_size) return 0;
    uint32_t val;
    std::memcpy(&val, m_data.data() + offset, 4);
    return val;
}

uint64_t PE::get_qword_at_offset(uint32_t offset) const {
    if (offset + 8 > m_data_size) return 0;
    uint64_t val;
    std::memcpy(&val, m_data.data() + offset, 8);
    return val;
}

bool PE::set_bytes_at_rva(uint32_t rva, std::span<const uint8_t> data) {
    auto offset = get_offset_from_rva(rva);
    if (offset + data.size() > m_data_size) return false;
    std::memcpy(m_data.data() + offset, data.data(), data.size());
    return true;
}

bool PE::set_bytes_at_offset(uint32_t offset, std::span<const uint8_t> data) {
    if (offset + data.size() > m_data_size) return false;
    std::memcpy(m_data.data() + offset, data.data(), data.size());
    return true;
}

bool PE::set_word_at_rva(uint32_t rva, uint16_t word) {
    return set_bytes_at_rva(rva, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&word), 2));
}

bool PE::set_dword_at_rva(uint32_t rva, uint32_t dword) {
    return set_bytes_at_rva(rva, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&dword), 4));
}

bool PE::set_qword_at_rva(uint32_t rva, uint64_t qword) {
    return set_bytes_at_rva(rva, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&qword), 8));
}

bool PE::set_word_at_offset(uint32_t offset, uint16_t word) {
    return set_bytes_at_offset(offset, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&word), 2));
}

bool PE::set_dword_at_offset(uint32_t offset, uint32_t dword) {
    return set_bytes_at_offset(offset, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&dword), 4));
}

bool PE::set_qword_at_offset(uint32_t offset, uint64_t qword) {
    return set_bytes_at_offset(offset, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&qword), 8));
}

bool PE::set_version_string(const std::string& key, const std::string& value) {
    if (!m_version_info) return false;
    auto it = m_version_info->entries.find(key);
    if (it == m_version_info->entries.end()) return false;

    auto& entry = it->second;
    std::vector<uint8_t> utf16(value.size() * 2 + 2, 0);
    for (size_t i = 0; i < value.size(); i++) {
        utf16[i * 2] = static_cast<uint8_t>(value[i]);
        utf16[i * 2 + 1] = 0;
    }
    utf16[value.size() * 2] = 0;
    utf16[value.size() * 2 + 1] = 0;

    if (utf16.size() > entry.max_byte_length) {
        utf16.resize(entry.max_byte_length);
    }
    std::vector<uint8_t> padded(entry.max_byte_length, 0);
    std::memcpy(padded.data(), utf16.data(), utf16.size());

    if (!set_bytes_at_offset(entry.value_offset,
                              std::span<const uint8_t>(padded.data(), padded.size()))) {
        return false;
    }

    entry.value = value;
    m_version_info->strings[key] = value;
    return true;
}

std::vector<uint8_t> PE::write() const {
    return m_data;
}

bool PE::write(const std::string& filename) const {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(m_data.data()), m_data_size);
    return file.good();
}

// ============================================================================
// Directory Parsers
// ============================================================================

void PE::parse_data_directories(std::initializer_list<int> directories) {
    std::set<int> set;
    for (int d : directories) set.insert(d);
    parse_data_directories(set);
}

void PE::parse_data_directories(const std::set<int>& directories) {
    if (directories.count(static_cast<int>(DirectoryEntry::EXPORT)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::EXPORT) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::EXPORT)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::EXPORT)];
        m_exports = parse_export_directory(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::IMPORT)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::IMPORT) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::IMPORT)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::IMPORT)];
        m_imports = parse_import_directory(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::BASERELOC)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::BASERELOC) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::BASERELOC)];
        m_relocations = parse_relocations_directory(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::DEBUG)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::DEBUG) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::DEBUG)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::DEBUG)];
        m_debug_data = parse_debug_directory(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::TLS)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::TLS) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::TLS)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::TLS)];
        m_tls_data = parse_directory_tls(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::EXCEPTION)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::EXCEPTION) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::EXCEPTION)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::EXCEPTION)];
        m_exceptions = parse_exceptions_directory(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::LOAD_CONFIG)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::LOAD_CONFIG) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::LOAD_CONFIG)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::LOAD_CONFIG)];
        m_load_config_data = parse_directory_load_config(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::BOUND_IMPORT)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::BOUND_IMPORT) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::BOUND_IMPORT)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::BOUND_IMPORT)];
        m_bound_imports = parse_directory_bound_imports(dir.VirtualAddress, dir.Size);
    }

    if (directories.count(static_cast<int>(DirectoryEntry::RESOURCE)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::RESOURCE) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::RESOURCE)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::RESOURCE)];
        auto result = parse_resources_directory(dir.VirtualAddress, dir.Size);
        if (result) {
            m_resources.push_back(*result);

            for (auto& entry : result->entries) {
                if (entry.id == 16 && entry.directory) {
                    for (auto& sub : entry.directory->entries) {
                        if (sub.data_entry) {
                            m_version_info = parse_version_information(sub.data_entry->data_rva);
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    if (directories.count(static_cast<int>(DirectoryEntry::DELAY_IMPORT)) &&
        m_data_directories.size() > static_cast<size_t>(DirectoryEntry::DELAY_IMPORT) &&
        m_data_directories[static_cast<size_t>(DirectoryEntry::DELAY_IMPORT)].VirtualAddress) {
        auto& dir = m_data_directories[static_cast<size_t>(DirectoryEntry::DELAY_IMPORT)];
        m_delay_imports = parse_delay_import_directory(dir.VirtualAddress, dir.Size);
    }
}

void PE::parse_data_directories() {
    std::set<int> all;
    for (size_t i = 0; i < m_data_directories.size() && i < 16; i++) {
        all.insert(static_cast<int>(i));
    }
    parse_data_directories(all);
}

std::vector<ImportDescData> PE::parse_import_directory(uint32_t rva, uint32_t size) {
    std::vector<ImportDescData> import_descs;
    size_t desc_size = 20;
    uint32_t end_rva = rva + size;

    while (true) {
        if (rva + desc_size > m_data_size) break;
        if (rva + desc_size > end_rva) break;

        auto import_desc = ImageImportDescriptor::parse(m_data, get_offset_from_rva(rva));
        if (import_desc.all_zeroes()) {
            break;
        }

        rva += desc_size;

        auto file_offset = get_offset_from_rva(rva);
        uint32_t max_len = static_cast<uint32_t>(m_data_size) - file_offset;
        if (import_desc.OriginalFirstThunk != 0 && rva > import_desc.OriginalFirstThunk) {
            max_len = std::max(max_len, rva - import_desc.OriginalFirstThunk);
        }
        if (import_desc.FirstThunk != 0 && rva > import_desc.FirstThunk) {
            max_len = std::max(max_len, rva - import_desc.FirstThunk);
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
            import_descs.push_back({dll, import_data, static_cast<uint32_t>(rva - desc_size)});
        }
    }

    return import_descs;
}

std::vector<ImportData> PE::parse_imports(
    uint32_t original_first_thunk,
    uint32_t first_thunk,
    uint32_t forwarder_chain,
    uint32_t max_length) {

    std::vector<ImportData> imported_symbols;

    uint64_t ordinal_flag;
    size_t entry_size;
    if (m_pe_type == OPTIONAL_HEADER_MAGIC_PE) {
        ordinal_flag = IMAGE_ORDINAL_FLAG;
        entry_size = 4;
    } else {
        ordinal_flag = IMAGE_ORDINAL_FLAG64;
        entry_size = 8;
    }

    uint32_t ilt_rva = original_first_thunk;
    uint32_t iat_rva = first_thunk;

    uint32_t start_rva = ilt_rva;
    size_t num_invalid = 0;

    while (ilt_rva != 0 || iat_rva != 0) {
        uint32_t current_rva = ilt_rva ? ilt_rva : iat_rva;

        if (max_length > 0 && current_rva >= start_rva + max_length) break;

        if (current_rva + entry_size > m_data_size) break;

        uint64_t address_of_data = 0;
        auto offset = get_offset_from_rva(current_rva);
        if (entry_size == 4) {
            uint32_t val;
            std::memcpy(&val, m_data.data() + offset, 4);
            address_of_data = val;
        } else {
            std::memcpy(&address_of_data, m_data.data() + offset, 8);
        }

        if (address_of_data == 0) break;

        uint16_t imp_ord = 0;
        uint16_t imp_hint = 0;
        std::string imp_name;
        bool import_by_ordinal = false;
        uint32_t name_offset = 0;

        if (address_of_data & ordinal_flag) {
            import_by_ordinal = true;
            imp_ord = static_cast<uint16_t>(address_of_data & 0xFFFF);
        } else {
            if (address_of_data + 2 < m_data_size) {
                auto name_rva = static_cast<uint32_t>(address_of_data);
                auto hint_offset = get_offset_from_rva(name_rva);
                if (hint_offset + 2 <= m_data_size) {
                    std::memcpy(&imp_hint, m_data.data() + hint_offset, 2);
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

        auto thunk_offset = static_cast<uint32_t>(get_offset_from_rva(current_rva));
        auto thunk_rva = current_rva;

        uint64_t imp_address = current_rva +
            (is_pe32_plus() ? m_optional_header_64.ImageBase : m_optional_header_32.ImageBase);

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

std::optional<ExportDirData> PE::parse_export_directory(uint32_t rva, uint32_t size) {
    if (rva + 40 > m_data_size) return std::nullopt;

    auto export_dir = ImageExportDirectory::parse(m_data, get_offset_from_rva(rva));
    if (export_dir.NumberOfFunctions == 0 && export_dir.NumberOfNames == 0) {
        return std::nullopt;
    }

    auto length_until_eof = [this](uint32_t r) -> uint32_t {
        auto off = get_offset_from_rva(r);
        return static_cast<uint32_t>(m_data_size) - off;
    };

    auto addr_of_names = get_offset_from_rva(export_dir.AddressOfNames);
    auto addr_of_name_ordinals = get_offset_from_rva(export_dir.AddressOfNameOrdinals);
    auto addr_of_functions = get_offset_from_rva(export_dir.AddressOfFunctions);

    std::vector<ExportData> exports;

    for (uint32_t i = 0; i < std::min(export_dir.NumberOfNames,
            length_until_eof(export_dir.AddressOfNames) / 4); i++) {
        if (addr_of_name_ordinals + i * 2 + 2 > m_data_size) break;
        uint16_t symbol_ordinal;
        std::memcpy(&symbol_ordinal, m_data.data() + addr_of_name_ordinals + i * 2, 2);

        uint32_t symbol_address = 0;
        if (addr_of_functions + symbol_ordinal * 4 + 4 <= m_data_size) {
            std::memcpy(&symbol_address, m_data.data() + addr_of_functions + symbol_ordinal * 4, 4);
        }

        if (symbol_address == 0) continue;

        std::string forwarder;
        if (rva <= symbol_address && symbol_address < rva + size) {
            forwarder = get_string_at_rva(symbol_address);
        }

        uint32_t symbol_name_rva = 0;
        if (addr_of_names + i * 4 + 4 <= m_data_size) {
            std::memcpy(&symbol_name_rva, m_data.data() + addr_of_names + i * 4, 4);
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

std::vector<DebugData> PE::parse_debug_directory(uint32_t rva, uint32_t size) {
    std::vector<DebugData> debug;
    size_t dbg_size = 28;
    uint32_t count = static_cast<uint32_t>(size / dbg_size);

    for (uint32_t idx = 0; idx < count; idx++) {
        auto dbg_rva = rva + dbg_size * idx;
        if (dbg_rva + dbg_size > m_data_size) break;

        auto dbg = ImageDebugDirectory::parse(m_data, dbg_rva);

        DebugData data;
        data.type = dbg.Type;
        data.size_of_data = dbg.SizeOfData;
        data.address_of_raw_data = dbg.AddressOfRawData;
        data.pointer_to_raw_data = dbg.PointerToRawData;
        debug.push_back(data);
    }

    return debug;
}

std::vector<BaseRelocationData> PE::parse_relocations_directory(uint32_t rva, uint32_t size) const {
    std::vector<BaseRelocationData> relocations;
    uint32_t end = rva + size;

    while (rva < end) {
        if (rva + 8 > m_data_size) break;

        auto rlc = ImageBaseRelocation::parse(m_data, get_offset_from_rva(rva));
        if (rlc.VirtualAddress == 0 && rlc.SizeOfBlock == 0) break;
        if (rlc.SizeOfBlock < 8 || rlc.SizeOfBlock > m_data_size) break;

        uint32_t base_rva = rlc.VirtualAddress;
        uint32_t entries_size = rlc.SizeOfBlock - 8;
        uint32_t entry_rva = rva + 8;

        BaseRelocationData base_reloc;
        base_reloc.struct_offset = rva;

        std::set<std::pair<uint32_t, uint32_t>> seen;
        for (uint32_t i = 0; i < entries_size / 2; i++) {
            auto entry_offset = get_offset_from_rva(entry_rva + i * 2);
            if (entry_offset + 2 > m_data_size) break;

            uint16_t word;
            std::memcpy(&word, m_data.data() + entry_offset, 2);

            uint32_t reloc_type = word >> 12;
            uint32_t reloc_offset = word & 0x0FFF;

            auto key = std::make_pair(reloc_offset, reloc_type);
            if (seen.count(key)) continue;
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

std::optional<TlsData> PE::parse_directory_tls(uint32_t rva, uint32_t size) {
    TlsData tls;
    tls.struct_offset = rva;

    if (is_pe32_plus()) {
        if (rva + 40 > m_data_size) return std::nullopt;
        auto dir = ImageTlsDirectory64::parse(m_data, get_offset_from_rva(rva));
        tls.start_address_of_raw_data = dir.StartAddressOfRawData;
        tls.end_address_of_raw_data = dir.EndAddressOfRawData;
        tls.address_of_index = dir.AddressOfIndex;
        tls.address_of_callbacks = dir.AddressOfCallBacks;
    } else {
        if (rva + 24 > m_data_size) return std::nullopt;
        auto dir = ImageTlsDirectory32::parse(m_data, get_offset_from_rva(rva));
        tls.start_address_of_raw_data = dir.StartAddressOfRawData;
        tls.end_address_of_raw_data = dir.EndAddressOfRawData;
        tls.address_of_index = dir.AddressOfIndex;
        tls.address_of_callbacks = dir.AddressOfCallBacks;
    }

    return tls;
}

std::vector<ExceptionsDirEntryData> PE::parse_exceptions_directory(uint32_t rva, uint32_t size) {
    std::vector<ExceptionsDirEntryData> result;

    if (m_file_header.Machine != static_cast<uint16_t>(MachineType::AMD64) &&
        m_file_header.Machine != static_cast<uint16_t>(MachineType::IA64)) {
        return result;
    }

    size_t rf_size = 12;
    uint32_t end = rva + size;

    while (rva + rf_size <= end && rva + rf_size <= m_data_size) {
        auto rf = RuntimeFunction::parse(m_data, get_offset_from_rva(rva));

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

std::optional<LoadConfigData> PE::parse_directory_load_config(uint32_t rva, uint32_t size) {
    if (rva + 4 > m_data_size) return std::nullopt;

    LoadConfigData lc;
    lc.struct_offset = rva;

    uint32_t lc_size = get_dword_at_rva(rva);
    lc.size = lc_size;

    auto offset = get_offset_from_rva(rva);
    if (offset + lc_size > m_data_size) return lc;

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
        if (lc_size >= 72) {
            lc.lock_prefix_table = get_qword_at_rva(rva + 40);
            lc.maximum_allocation_size = get_qword_at_rva(rva + 48);
            lc.virtual_memory_threshold = get_qword_at_rva(rva + 56);
            lc.process_affinity_mask = get_qword_at_rva(rva + 64);
        }
        if (lc_size >= 76) {
            lc.process_heap_flags = get_dword_at_rva(rva + 72);
        }
        if (lc_size >= 80) {
            lc.csd_version = get_word_at_rva(rva + 76);
            lc.dependent_load_flags = get_word_at_rva(rva + 78);
        }
        if (lc_size >= 96) {
            lc.edit_list = get_qword_at_rva(rva + 80);
            lc.security_cookie = get_qword_at_rva(rva + 88);
        }
        if (lc_size >= 112) {
            lc.se_handler_table = get_qword_at_rva(rva + 96);
            lc.se_handler_count = get_qword_at_rva(rva + 104);
        }
        if (lc_size >= 128) {
            lc.guard_cf_check_function_pointer = get_qword_at_rva(rva + 112);
            lc.guard_cf_dispatch_function_pointer = get_qword_at_rva(rva + 120);
        }
        if (lc_size >= 144) {
            lc.guard_cf_function_table = get_qword_at_rva(rva + 128);
            lc.guard_cf_function_count = get_qword_at_rva(rva + 136);
        }
        if (lc_size >= 144) {
            lc.guard_flags = get_dword_at_rva(rva + 140);
        }
        if (lc_size >= 156) {
            lc.code_integrity_flags = get_word_at_rva(rva + 144);
            lc.code_integrity_catalog = get_word_at_rva(rva + 146);
            lc.code_integrity_catalog_offset = get_dword_at_rva(rva + 148);
            lc.code_integrity_reserved = get_dword_at_rva(rva + 152);
        }
        if (lc_size >= 172) {
            lc.guard_address_taken_iat_entry_table = get_qword_at_rva(rva + 156);
            lc.guard_address_taken_iat_entry_count = get_qword_at_rva(rva + 164);
        }
        if (lc_size >= 188) {
            lc.guard_long_jump_target_table = get_qword_at_rva(rva + 172);
            lc.guard_long_jump_target_count = get_qword_at_rva(rva + 180);
        }
        if (lc_size >= 204) {
            lc.dynamic_value_reloc_table = get_qword_at_rva(rva + 188);
            lc.chpe_metadata_pointer = get_qword_at_rva(rva + 196);
        }
        if (lc_size >= 220) {
            lc.guard_rf_failure_routine = get_qword_at_rva(rva + 204);
            lc.guard_rf_failure_routine_function_pointer = get_qword_at_rva(rva + 212);
        }
        if (lc_size >= 228) {
            lc.dynamic_value_reloc_table_offset = get_dword_at_rva(rva + 220);
            lc.dynamic_value_reloc_table_section = get_word_at_rva(rva + 224);
            lc.reserved2 = get_word_at_rva(rva + 226);
        }
        if (lc_size >= 240) {
            lc.guard_rf_verify_stack_pointer_function_pointer = get_qword_at_rva(rva + 228);
            lc.hot_patch_table_offset = get_dword_at_rva(rva + 236);
        }
        if (lc_size >= 244) {
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
        if (lc_size >= 44) {
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
        if (lc_size >= 104) {
            lc.code_integrity_flags = get_word_at_rva(rva + 92);
            lc.code_integrity_catalog = get_word_at_rva(rva + 94);
            lc.code_integrity_catalog_offset = get_dword_at_rva(rva + 96);
            lc.code_integrity_reserved = get_dword_at_rva(rva + 100);
        }
        if (lc_size >= 112) {
            lc.guard_address_taken_iat_entry_table = get_dword_at_rva(rva + 104);
            lc.guard_address_taken_iat_entry_count = get_dword_at_rva(rva + 108);
        }
        if (lc_size >= 120) {
            lc.guard_long_jump_target_table = get_dword_at_rva(rva + 112);
            lc.guard_long_jump_target_count = get_dword_at_rva(rva + 116);
        }
        if (lc_size >= 128) {
            lc.dynamic_value_reloc_table = get_dword_at_rva(rva + 120);
            lc.chpe_metadata_pointer = get_dword_at_rva(rva + 124);
        }
        if (lc_size >= 136) {
            lc.guard_rf_failure_routine = get_dword_at_rva(rva + 128);
            lc.guard_rf_failure_routine_function_pointer = get_dword_at_rva(rva + 132);
        }
        if (lc_size >= 144) {
            lc.dynamic_value_reloc_table_offset = get_dword_at_rva(rva + 136);
            lc.dynamic_value_reloc_table_section = get_word_at_rva(rva + 140);
            lc.reserved2 = get_word_at_rva(rva + 142);
        }
        if (lc_size >= 152) {
            lc.guard_rf_verify_stack_pointer_function_pointer = get_dword_at_rva(rva + 144);
            lc.hot_patch_table_offset = get_dword_at_rva(rva + 148);
        }
        if (lc_size >= 156) {
            lc.reserved3 = get_dword_at_rva(rva + 152);
        }
        if (lc_size >= 164) {
            lc.enclave_configuration_pointer = get_dword_at_rva(rva + 156);
            lc.volatile_metadata_pointer = get_dword_at_rva(rva + 160);
        }
        if (lc_size >= 172) {
            lc.guard_eh_continuation_table = get_dword_at_rva(rva + 164);
            lc.guard_eh_continuation_count = get_dword_at_rva(rva + 168);
        }
    }

    return lc;
}

std::vector<BoundImportDescData> PE::parse_directory_bound_imports(uint32_t rva, uint32_t size) {
    std::vector<BoundImportDescData> result;

    while (rva + 8 <= m_data_size) {
        uint32_t time_date_stamp;
        uint16_t offset_module_name, number_of_module_forwarder_refs;
        auto offset = get_offset_from_rva(rva);
        if (offset + 8 > m_data_size) break;

        std::memcpy(&time_date_stamp, m_data.data() + offset, 4);
        std::memcpy(&offset_module_name, m_data.data() + offset + 4, 2);
        std::memcpy(&number_of_module_forwarder_refs, m_data.data() + offset + 6, 2);

        if (time_date_stamp == 0 && offset_module_name == 0 && number_of_module_forwarder_refs == 0) {
            break;
        }

        BoundImportDescData desc;
        desc.struct_offset = rva;
        desc.time_date_stamp = time_date_stamp;

        auto name_offset = rva + offset_module_name;
        desc.name = get_string_at_rva(name_offset, 256);

        rva += 8;
        for (uint16_t i = 0; i < number_of_module_forwarder_refs; i++) {
            rva += 8;
        }

        result.push_back(desc);
    }

    return result;
}

std::optional<VersionInfo> PE::parse_version_information(uint32_t rva) {
    auto start_offset = get_offset_from_rva(rva);
    if (start_offset >= m_data_size) return std::nullopt;

    // Read VS_VERSIONINFO header: Length(u16), ValueLength(u16), Type(u16)
    if (start_offset + 6 > m_data_size) return std::nullopt;
    uint16_t length = get_word_at_offset(start_offset);
    uint16_t value_length = get_word_at_offset(start_offset + 2);

    if (length == 0 || length > m_data_size - start_offset) return std::nullopt;

    std::string key = get_string_u_at_rva(rva + 6);
    if (key != "VS_VERSION_INFO") return std::nullopt;

    VersionInfo vi;
    vi.name = key;
    vi.base_rva = rva;

    // VS_FIXEDFILEINFO follows the key, dword-aligned
    auto ffi_offset = dword_align(6 + 2 * (static_cast<uint32_t>(key.size()) + 1), rva);
    auto ffi_abs = start_offset + ffi_offset;

    // Verify the magic signature for VS_FIXEDFILEINFO
    if (ffi_abs + 4 <= m_data_size) {
        uint32_t signature = get_dword_at_offset(ffi_abs);
        if (signature == 0xFEEF04BD) {
            if (value_length >= 52 || value_length == 0) {
                auto abs = ffi_abs;
                if (abs + 56 <= m_data_size) {
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

    while (start_offset + stringfileinfo_offset + 6 <= m_data_size) {
        auto sf_offset = start_offset + stringfileinfo_offset;
        uint16_t sf_length = get_word_at_offset(sf_offset);
        if (sf_length == 0 || sf_offset + sf_length > m_data_size) break;

        uint16_t sf_value_length = get_word_at_offset(sf_offset + 2);
        std::string sf_key = get_string_u_at_rva(get_rva_from_offset(sf_offset + 6));

        if (sf_key.starts_with("StringFileInfo") && sf_value_length == 0) {
            auto st_offset = dword_align(
                stringfileinfo_offset + 6 + 2 * (static_cast<uint32_t>(sf_key.size()) + 1), rva);

            while (start_offset + st_offset + 6 <= m_data_size &&
                   st_offset < stringfileinfo_offset + sf_length) {
                auto st_abs = start_offset + st_offset;
                uint16_t st_length = get_word_at_offset(st_abs);
                if (st_length == 0 || st_abs + st_length > m_data_size) break;

                std::string st_key = get_string_u_at_rva(get_rva_from_offset(st_abs + 6));

                // Parse individual String entries within the StringTable
                auto str_offset = dword_align(
                    st_offset + 6 + 2 * (static_cast<uint32_t>(st_key.size()) + 1), rva);

                while (start_offset + str_offset + 6 <= m_data_size &&
                       str_offset < st_offset + st_length) {
                    auto str_abs = start_offset + str_offset;
                    uint16_t str_length = get_word_at_offset(str_abs);
                    uint16_t str_value_length = get_word_at_offset(str_abs + 2);
                    if (str_length == 0 || str_abs + str_length > m_data_size) break;

                    auto str_key_offset = str_abs + 6;
                    std::string str_key = get_string_u_at_rva(
                        get_rva_from_offset(str_key_offset));

                    if (!str_key.empty() && str_value_length > 0) {
                        auto val_rva = get_rva_from_offset(dword_align(
                            str_offset + 6 + 2 * (static_cast<uint32_t>(str_key.size()) + 1), rva));
                        std::string val = get_string_u_at_rva(val_rva, str_value_length);
                        vi.strings[str_key] = val;

                        VersionStringEntry entry;
                        entry.value = val;
                        entry.value_rva = val_rva;
                        entry.value_offset = get_offset_from_rva(val_rva);
                        entry.max_byte_length = str_value_length;
                        vi.entries[str_key] = entry;
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

std::vector<DelayImportDescData> PE::parse_delay_import_directory(uint32_t rva, uint32_t size) {
    std::vector<DelayImportDescData> import_descs;
    size_t desc_size = 32;
    size_t error_count = 0;
    uint32_t end_rva = rva + size;

    while (true) {
        if (rva + desc_size > m_data_size) break;
        if (rva + desc_size > end_rva) break;

        auto import_desc = ImageDelayImportDescriptor::parse(m_data, get_offset_from_rva(rva));
        if (import_desc.all_zeroes()) break;

        uint32_t int_rva = import_desc.DelayINT;
        uint32_t iat_rva = import_desc.DelayIAT;

        if (import_desc.grAttrs() == 0 &&
            m_file_header.Machine == static_cast<uint16_t>(MachineType::I386)) {
            auto image_base = m_optional_header_32.ImageBase;
            int_rva = (int_rva != 0) ? int_rva - image_base : 0;
            iat_rva = (iat_rva != 0) ? iat_rva - image_base : 0;
        }

        rva += desc_size;

        auto file_offset = get_offset_from_rva(rva);
        uint32_t max_len = static_cast<uint32_t>(m_data_size) - file_offset;
        if (int_rva != 0 && rva > int_rva) {
            max_len = std::max(max_len, rva - int_rva);
        }
        if (iat_rva != 0 && rva > iat_rva) {
            max_len = std::max(max_len, rva - iat_rva);
        }

        std::vector<ImportData> import_data;
        try {
            import_data = parse_imports(int_rva, iat_rva, 0, max_len);
        } catch (const PEFormatError& e) {
            add_warning("Error parsing the Delay import directory. "
                "Invalid import data at RVA: 0x" + std::to_string(rva) +
                " (" + e.what() + ")");
        }

        if (import_data.empty()) {
            if (++error_count > 5) {
                add_warning("Too many errors parsing the Delay import directory. "
                    "Invalid import data at RVA: 0x" + std::to_string(rva));
                break;
            }
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
            desc.struct_offset = static_cast<uint32_t>(rva - desc_size);
            import_descs.push_back(std::move(desc));
        }
    }

    return import_descs;
}

std::optional<ImageResourceDataEntry> PE::parse_resource_data_entry(uint32_t rva) {
    if (rva + 16 > m_data_size) return std::nullopt;
    return ImageResourceDataEntry::parse(m_data, rva);
}

std::optional<ResourceDirData> PE::parse_resources_directory(
    uint32_t rva, uint32_t size, uint32_t base_rva,
    int level, std::vector<uint32_t> dirs) {

    if (level > static_cast<int>(MAX_RESOURCE_DEPTH)) {
        add_warning("Error parsing the resources directory. "
            "Excessively nested table depth " + std::to_string(level));
        return std::nullopt;
    }

    if (rva + 16 > m_data_size) {
        add_warning("Invalid resources directory. Can't read directory data at RVA: 0x" +
            std::to_string(rva));
        return std::nullopt;
    }

    if (base_rva == 0) base_rva = rva;

    auto resource_dir = ImageResourceDirectory::parse(m_data, rva);
    uint32_t number_of_entries = resource_dir.NumberOfNamedEntries +
                                      resource_dir.NumberOfIdEntries;

    if (number_of_entries > MAX_ALLOWED_RESOURCE_ENTRIES) {
        add_warning("Error parsing the resources directory. "
            "The directory contains " + std::to_string(number_of_entries) + " entries");
        return std::nullopt;
    }

    uint32_t entry_rva = rva + 16;
    std::vector<ResourceDirEntryData> dir_entries;

    for (uint32_t idx = 0; idx < number_of_entries; idx++) {
        if (entry_rva + 8 > m_data_size) break;

        auto res = ImageResourceDirectoryEntry::parse(m_data, entry_rva);

        std::string entry_name;
        uint32_t entry_id = 0;

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
    if (m_imports.empty()) return "";

    std::string result;
    for (auto& entry : m_imports) {
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

    return hash_helpers::md5_hex(result);
}

std::string PE::get_exphash() const {
    if (!m_exports || m_exports->symbols.empty()) return "";
    std::string result;
    for (auto& exp : m_exports->symbols) {
        if (exp.name.empty()) continue;
        if (!result.empty()) result += ",";
        std::string name = exp.name;
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char c) { return std::tolower(c); });
        result += name;
    }
    if (result.empty()) return "";

    return hash_helpers::md5_hex(result);
}

void PE::show_warnings() const {
    for (auto& w : m_warnings) {
        std::cerr << "> " << w << "\n";
    }
}

std::string PE::dump_info() const {
    std::ostringstream ss;
    ss << "DOS Header:\n";
    ss << "  e_magic: 0x" << std::hex << m_dos_header.e_magic << "\n";
    ss << "  e_lfanew: 0x" << m_dos_header.e_lfanew << "\n";
    ss << "\nFile Header:\n";
    ss << "  Machine: 0x" << m_file_header.Machine << "\n";
    ss << "  NumberOfSections: " << std::dec << m_file_header.NumberOfSections << "\n";
    ss << "  Characteristics: 0x" << std::hex << m_file_header.Characteristics << "\n";

    if (m_rich_header) {
        ss << "\nRich Header:\n";
        ss << "  Checksum: 0x" << std::hex << m_rich_header->checksum << "\n";
        ss << "  Values: " << std::dec << m_rich_header->values.size() << " pairs\n";
    }

    ss << "\nSections:\n";
    for (auto& s : m_sections) {
        ss << "  " << s.name() << ": VA=0x" << std::hex << s.VirtualAddress
           << " Size=0x" << s.SizeOfRawData
           << " Chars=0x" << s.Characteristics << "\n";
    }

    if (!m_imports.empty()) {
        ss << "\nImports:\n";
        for (auto& imp : m_imports) {
            ss << "  " << imp.dll << " (" << imp.imports.size() << " symbols)\n";
        }
    }

    if (!m_delay_imports.empty()) {
        ss << "\nDelay Imports:\n";
        for (auto& imp : m_delay_imports) {
            ss << "  " << imp.dll << " (" << imp.imports.size() << " symbols)\n";
        }
    }

    if (m_exports) {
        ss << "\nExports:\n";
        ss << "  " << m_exports->name << " (" << m_exports->symbols.size() << " symbols)\n";
    }

    if (!m_relocations.empty()) {
        ss << "\nRelocations:\n";
        size_t total_entries = 0;
        for (auto& r : m_relocations) total_entries += r.entries.size();
        ss << "  " << m_relocations.size() << " blocks (" << total_entries << " entries)\n";
    }

    if (m_tls_data) {
        ss << "\nTLS:\n";
        ss << "  StartAddressOfRawData: 0x" << std::hex << m_tls_data->start_address_of_raw_data << "\n";
        ss << "  AddressOfIndex: 0x" << m_tls_data->address_of_index << "\n";
    }

    if (m_load_config_data) {
        ss << "\nLoad Config:\n";
        ss << "  Size: " << std::dec << m_load_config_data->size << "\n";
        ss << "  GuardFlags: 0x" << std::hex << m_load_config_data->guard_flags << "\n";
    }

    if (m_version_info) {
        ss << "\nVersion Info:\n";
        ss << "  Signature: 0x" << std::hex << m_version_info->signature << "\n";
        ss << "  FileOS: 0x" << m_version_info->file_os << "\n";
        ss << "  FileType: 0x" << m_version_info->file_type << "\n";
        if (!m_version_info->strings.empty()) {
            ss << "  Strings:\n";
            for (auto& [k, v] : m_version_info->strings) {
                ss << "    " << k << ": " << v << "\n";
            }
        }
    }

    if (!m_resources.empty()) {
        ss << "\nResources:\n";
        for (auto& res_dir : m_resources) {
            ss << "  " << res_dir.entries.size() << " top-level entries\n";
        }
    }

    if (!m_exceptions.empty()) {
        ss << "\nExceptions:\n";
        ss << "  " << m_exceptions.size() << " entries\n";
    }

    if (!m_bound_imports.empty()) {
        ss << "\nBound Imports:\n";
        ss << "  " << m_bound_imports.size() << " entries\n";
    }

    if (!m_warnings.empty()) {
        ss << "\nWarnings:\n";
        for (auto& w : m_warnings) {
            ss << "  " << w << "\n";
        }
    }

    return ss.str();
}

std::vector<std::string> PE::get_resources_strings() const {
    std::vector<std::string> result;
    for (auto& res_dir : m_resources) {
        for (auto& entry : res_dir.entries) {
            if (entry.directory) {
                for (auto& sub_entry : entry.directory->entries) {
                    if (sub_entry.data_entry && sub_entry.id == static_cast<uint32_t>(ResourceType::STRING)) {
                        auto rva = sub_entry.data_entry->data_rva;
                        auto size = sub_entry.data_entry->size;
                        if (rva + size <= m_data_size) {
                            if (auto str = get_string_u_at_rva(rva, size / 2); !str.empty()) {
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
    constexpr uint32_t DANS = 0x536E6144;
    constexpr uint32_t RICH = 0x68636952;

    auto optional_header_end = static_cast<size_t>(m_dos_header.e_lfanew) + 4 + 20 +
                               m_file_header.SizeOfOptionalHeader;
    auto search_end = std::min(optional_header_end, m_data_size);

    if (search_end < 0x80) return std::nullopt;

    const uint8_t rich_tag_bytes[] = { 0x52, 0x69, 0x63, 0x68 };
    size_t rich_index = 0;
    for (size_t i = 0x80; i + 4 <= search_end; i++) {
        if (std::memcmp(m_data.data() + i, rich_tag_bytes, 4) == 0) {
            rich_index = i;
            break;
        }
    }
    if (rich_index == 0) return std::nullopt;

    size_t block_len = rich_index + 8 - 0x80;
    block_len = 4 * (block_len / 4);
    if (block_len == 0) return std::nullopt;

    std::vector<uint32_t> data(block_len / 4);
    for (size_t i = 0; i < data.size(); i++) {
        std::memcpy(&data[i], m_data.data() + 0x80 + i * 4, 4);
    }

    auto rich_pos = std::find(data.begin(), data.end(), RICH);
    if (rich_pos == data.end()) return std::nullopt;

    uint32_t checksum = *(rich_pos + 1);

    RichHeaderData result;
    result.checksum = checksum;
    result.raw_data.assign(m_data.data() + 0x80, m_data.data() + 0x80 + rich_index - 0x80);

    result.clear_data.resize(rich_index - 0x80);
    for (size_t i = 0; i + 3 < result.raw_data.size(); i += 4) {
        uint32_t val;
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

std::string PE::get_rich_header_hash(const std::string& algorithm) const {
    if (!m_rich_header || m_rich_header->clear_data.empty()) return "";

    std::string algo_lower;
    algo_lower.reserve(algorithm.size());
    for (char c : algorithm) algo_lower.push_back(static_cast<char>(std::tolower(c)));

    if (algo_lower == "md5") {
        return hash_helpers::md5_hex(m_rich_header->clear_data);
    }
    if (algo_lower == "sha1") {
        return hash_helpers::sha1_hex(m_rich_header->clear_data);
    }
    if (algo_lower == "sha256") {
        return hash_helpers::sha256_hex(m_rich_header->clear_data);
    }
    if (algo_lower == "sha512") {
        return hash_helpers::sha512_hex(m_rich_header->clear_data);
    }

    throw std::invalid_argument("Unknown rich header hash algorithm: " + algorithm);
}

} // namespace pefile
