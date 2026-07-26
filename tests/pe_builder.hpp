#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

namespace test_helpers {

class PeBuilder {
public:
    PeBuilder(bool is_64 = false) : is_64_(is_64) {
        dos_header.resize(64, 0);
        dos_header[0] = 0x4D;
        dos_header[1] = 0x5A;
        std::uint32_t e_lfanew = 0x40;
        std::memcpy(dos_header.data() + 0x3C, &e_lfanew, 4);
    }

    void set_characteristics(std::uint16_t c) { file_characteristics = c; }
    void set_machine(std::uint16_t m) { machine = m; }
    void set_subsystem(std::uint16_t s) { subsystem = s; }
    void set_entry_point(std::uint32_t ep) { entry_point = ep; }
    void set_image_base(std::uint64_t ib) { image_base = ib; }
    void set_num_sections(std::uint16_t n) { num_sections = n; }
    void set_num_data_dirs(std::uint32_t n) { num_data_dirs = n; }

    void add_section(const std::string& name, std::uint32_t virtual_size,
                     std::uint32_t virtual_address, std::uint32_t size_of_raw_data,
                     std::uint32_t pointer_to_raw_data, std::uint32_t characteristics,
                     const std::vector<std::uint8_t>& data = {}) {
        Section sec{};
        std::strncpy(sec.name, name.c_str(), 8);
        sec.virtual_size = virtual_size;
        sec.virtual_address = virtual_address;
        sec.size_of_raw_data = size_of_raw_data;
        sec.pointer_to_raw_data = pointer_to_raw_data;
        sec.characteristics = characteristics;
        sec.data = data;
        sections.push_back(sec);
    }

    void add_export_directory(std::uint32_t rva, std::uint32_t size,
                               const std::vector<std::uint8_t>& data) {
        data_dirs[0] = {rva, size};
        export_data = data;
    }

    void add_import_directory(std::uint32_t rva, std::uint32_t size,
                               const std::vector<std::uint8_t>& data) {
        data_dirs[1] = {rva, size};
        import_data = data;
    }

    void add_resource_directory(std::uint32_t rva, std::uint32_t size,
                                 const std::vector<std::uint8_t>& data) {
        data_dirs[2] = {rva, size};
        resource_data = data;
    }

    void add_exception_directory(std::uint32_t rva, std::uint32_t size,
                                  const std::vector<std::uint8_t>& data) {
        data_dirs[3] = {rva, size};
        exception_data = data;
    }

    void add_reloc_directory(std::uint32_t rva, std::uint32_t size,
                              const std::vector<std::uint8_t>& data) {
        data_dirs[5] = {rva, size};
        reloc_data = data;
    }

    void add_debug_directory(std::uint32_t rva, std::uint32_t size,
                              const std::vector<std::uint8_t>& data) {
        data_dirs[6] = {rva, size};
        debug_data = data;
    }

    void add_tls_directory(std::uint32_t rva, std::uint32_t size,
                            const std::vector<std::uint8_t>& data) {
        data_dirs[9] = {rva, size};
        tls_data = data;
    }

    void add_load_config_directory(std::uint32_t rva, std::uint32_t size,
                                    const std::vector<std::uint8_t>& data) {
        data_dirs[10] = {rva, size};
        load_config_data = data;
    }

    void add_delay_import_directory(std::uint32_t rva, std::uint32_t size,
                                     const std::vector<std::uint8_t>& data) {
        data_dirs[13] = {rva, size};
        delay_import_data = data;
    }

    std::vector<std::uint8_t> build() {
        if (num_sections == 0) {
            num_sections = static_cast<std::uint16_t>(sections.size());
        }
        if (num_data_dirs == 0) {
            num_data_dirs = 16;
        }

        std::vector<std::uint8_t> result;

        result.insert(result.end(), dos_header.begin(), dos_header.end());

        // PE signature
        push_u32(result, 0x00004550); // "PE\0\0"

        // COFF header (20 bytes)
        push_u16(result, machine);
        push_u16(result, num_sections);
        push_u32(result, 0); // TimeDateStamp
        push_u32(result, 0); // PointerToSymbolTable
        push_u32(result, 0); // NumberOfSymbols
        push_u16(result, is_64_ ? 240 : 224); // SizeOfOptionalHeader
        push_u16(result, file_characteristics);

        // Optional header
        if (is_64_) {
            build_optional_header_64(result);
        } else {
            build_optional_header_32(result);
        }

        // Sections
        for (auto& sec : sections) {
            std::uint8_t sec_buf[40] = {};
            std::memcpy(sec_buf, sec.name, 8);
            std::memcpy(sec_buf + 8, &sec.virtual_size, 4);
            std::memcpy(sec_buf + 12, &sec.virtual_address, 4);
            std::memcpy(sec_buf + 16, &sec.size_of_raw_data, 4);
            std::memcpy(sec_buf + 20, &sec.pointer_to_raw_data, 4);
            std::memcpy(sec_buf + 36, &sec.characteristics, 4);
            result.insert(result.end(), sec_buf, sec_buf + 40);
        }

        // Section data
        for (auto& sec : sections) {
            while (result.size() < sec.pointer_to_raw_data) {
                result.push_back(0);
            }
            if (!sec.data.empty()) {
                result.insert(result.end(), sec.data.begin(), sec.data.end());
            }
            while (result.size() < sec.pointer_to_raw_data + sec.size_of_raw_data) {
                result.push_back(0);
            }
        }

        return result;
    }

private:
    void push_u16(std::vector<std::uint8_t>& v, std::uint16_t val) {
        v.push_back(static_cast<std::uint8_t>(val & 0xFF));
        v.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    }

    void push_u32(std::vector<std::uint8_t>& v, std::uint32_t val) {
        for (int i = 0; i < 4; i++) {
            v.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
        }
    }

    void push_u64(std::vector<std::uint8_t>& v, std::uint64_t val) {
        for (int i = 0; i < 8; i++) {
            v.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
        }
    }

    void push_data_dir(std::vector<std::uint8_t>& v, std::uint32_t rva, std::uint32_t size) {
        push_u32(v, rva);
        push_u32(v, size);
    }

    void build_optional_header_32(std::vector<std::uint8_t>& result) {
        push_u16(result, 0x10B); // Magic PE32
        result.push_back(0); result.push_back(0); // LinkerVersion
        push_u32(result, 0x200); // SizeOfCode
        push_u32(result, 0);     // SizeOfInitializedData
        push_u32(result, 0);     // SizeOfUninitializedData
        push_u32(result, entry_point);
        push_u32(result, 0x1000); // BaseOfCode
        push_u32(result, 0x2000); // BaseOfData
        push_u32(result, static_cast<std::uint32_t>(image_base));
        push_u32(result, 0x1000); // SectionAlignment
        push_u32(result, 0x200);  // FileAlignment
        push_u16(result, 4); push_u16(result, 0); // OSVersion
        push_u16(result, 0); push_u16(result, 0); // ImageVersion
        push_u16(result, 4); push_u16(result, 0); // SubsystemVersion
        push_u32(result, 0);     // Win32VersionValue
        push_u32(result, 0x4000); // SizeOfImage
        push_u32(result, 0x200);  // SizeOfHeaders
        push_u32(result, 0);     // CheckSum
        push_u16(result, subsystem);
        push_u16(result, 0);     // DllCharacteristics
        push_u32(result, 0x100000); // SizeOfStackReserve
        push_u32(result, 0x1000);   // SizeOfStackCommit
        push_u32(result, 0x100000); // SizeOfHeapReserve
        push_u32(result, 0x1000);   // SizeOfHeapCommit
        push_u32(result, 0);     // LoaderFlags
        push_u32(result, num_data_dirs); // NumberOfRvaAndSizes
        for (auto& dd : data_dirs) {
            push_data_dir(result, dd.first, dd.second);
        }
    }

    void build_optional_header_64(std::vector<std::uint8_t>& result) {
        push_u16(result, 0x20B); // Magic PE32+
        result.push_back(0); result.push_back(0); // LinkerVersion
        push_u32(result, 0x200); // SizeOfCode
        push_u32(result, 0);     // SizeOfInitializedData
        push_u32(result, 0);     // SizeOfUninitializedData
        push_u32(result, entry_point);
        push_u32(result, 0x1000); // BaseOfCode
        push_u64(result, image_base);
        push_u32(result, 0x1000); // SectionAlignment
        push_u32(result, 0x200);  // FileAlignment
        push_u16(result, 4); push_u16(result, 0); // OSVersion
        push_u16(result, 0); push_u16(result, 0); // ImageVersion
        push_u16(result, 4); push_u16(result, 0); // SubsystemVersion
        push_u32(result, 0);     // Win32VersionValue
        push_u32(result, 0x4000); // SizeOfImage
        push_u32(result, 0x200);  // SizeOfHeaders
        push_u32(result, 0);     // CheckSum
        push_u16(result, subsystem);
        push_u16(result, 0);     // DllCharacteristics
        push_u64(result, 0x100000); // SizeOfStackReserve
        push_u64(result, 0x1000);   // SizeOfStackCommit
        push_u64(result, 0x100000); // SizeOfHeapReserve
        push_u64(result, 0x1000);   // SizeOfHeapCommit
        push_u32(result, 0);     // LoaderFlags
        push_u32(result, num_data_dirs); // NumberOfRvaAndSizes
        for (auto& dd : data_dirs) {
            push_data_dir(result, dd.first, dd.second);
        }
    }

    bool is_64_;
    std::vector<std::uint8_t> dos_header;
    std::uint16_t machine = 0x14C;
    std::uint16_t num_sections = 0;
    std::uint16_t file_characteristics = 0x0102; // EXECUTABLE_IMAGE | 32BIT_MACHINE
    std::uint32_t entry_point = 0x1000;
    std::uint64_t image_base = 0x00400000;
    std::uint16_t subsystem = 3; // WINDOWS_CUI
    std::uint32_t num_data_dirs = 16;

    struct Section {
        char name[8] = {};
        std::uint32_t virtual_size = 0;
        std::uint32_t virtual_address = 0;
        std::uint32_t size_of_raw_data = 0;
        std::uint32_t pointer_to_raw_data = 0;
        std::uint32_t characteristics = 0;
        std::vector<std::uint8_t> data;
    };

    std::vector<Section> sections;
    std::pair<std::uint32_t, std::uint32_t> data_dirs[16] = {};

    std::vector<std::uint8_t> export_data;
    std::vector<std::uint8_t> import_data;
    std::vector<std::uint8_t> resource_data;
    std::vector<std::uint8_t> exception_data;
    std::vector<std::uint8_t> reloc_data;
    std::vector<std::uint8_t> debug_data;
    std::vector<std::uint8_t> tls_data;
    std::vector<std::uint8_t> load_config_data;
    std::vector<std::uint8_t> delay_import_data;
};

} // namespace test_helpers
