#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

#include "pe_structures.hpp"

namespace test_helpers {

class PeBuilder {
public:
    PeBuilder(bool is_64 = false) : is_64_(is_64) {}

    void set_characteristics(uint16_t c) { file_header_.Characteristics = c; }
    void set_machine(uint16_t m) { file_header_.Machine = m; }
    void set_subsystem(uint16_t s) { subsystem_ = s; }
    void set_entry_point(uint32_t ep) { entry_point_ = ep; }
    void set_image_base(uint64_t ib) { image_base_ = ib; }
    void set_num_sections(uint16_t n) { file_header_.NumberOfSections = n; }
    void set_num_data_dirs(uint32_t n) { num_data_dirs_ = n; }

    void add_section(const std::string& name, uint32_t virtual_size,
                     uint32_t virtual_address, uint32_t size_of_raw_data,
                     uint32_t pointer_to_raw_data, uint32_t characteristics,
                     const std::vector<uint8_t>& data = {}) {
        pefile::SectionHeader sec{};
        std::strncpy(sec.Name, name.c_str(), 8);
        sec.VirtualSize = virtual_size;
        sec.VirtualAddress = virtual_address;
        sec.SizeOfRawData = size_of_raw_data;
        sec.PointerToRawData = pointer_to_raw_data;
        sec.Characteristics = characteristics;
        section_data_.push_back(data);
        sections_.push_back(sec);
    }

    void add_export_directory(uint32_t rva, uint32_t size,
                               const std::vector<uint8_t>& data) {
        data_dirs_[0] = {rva, size};
        export_data_ = data;
    }

    void add_import_directory(uint32_t rva, uint32_t size,
                               const std::vector<uint8_t>& data) {
        data_dirs_[1] = {rva, size};
        import_data_ = data;
    }

    void add_resource_directory(uint32_t rva, uint32_t size,
                                 const std::vector<uint8_t>& data) {
        data_dirs_[2] = {rva, size};
        resource_data_ = data;
    }

    void add_exception_directory(uint32_t rva, uint32_t size,
                                  const std::vector<uint8_t>& data) {
        data_dirs_[3] = {rva, size};
        exception_data_ = data;
    }

    void add_reloc_directory(uint32_t rva, uint32_t size,
                              const std::vector<uint8_t>& data) {
        data_dirs_[5] = {rva, size};
        reloc_data_ = data;
    }

    void add_debug_directory(uint32_t rva, uint32_t size,
                              const std::vector<uint8_t>& data) {
        data_dirs_[6] = {rva, size};
        debug_data_ = data;
    }

    void add_tls_directory(uint32_t rva, uint32_t size,
                            const std::vector<uint8_t>& data) {
        data_dirs_[9] = {rva, size};
        tls_data_ = data;
    }

    void add_load_config_directory(uint32_t rva, uint32_t size,
                                    const std::vector<uint8_t>& data) {
        data_dirs_[10] = {rva, size};
        load_config_data_ = data;
    }

    void add_delay_import_directory(uint32_t rva, uint32_t size,
                                     const std::vector<uint8_t>& data) {
        data_dirs_[13] = {rva, size};
        delay_import_data_ = data;
    }

    std::vector<uint8_t> build() {
        if (file_header_.NumberOfSections == 0) {
            file_header_.NumberOfSections = static_cast<uint16_t>(sections_.size());
        }
        if (num_data_dirs_ == 0) {
            num_data_dirs_ = 16;
        }

        std::vector<uint8_t> result;

        // DOS header (64 bytes)
        pefile::DosHeader dos{};
        dos.e_magic = 0x5A4D;
        dos.e_lfanew = 0x40;
        push_struct(result, dos);

        // PE signature
        push_u32(result, 0x00004550); // "PE\0\0"

        // COFF file header
        file_header_.SizeOfOptionalHeader = is_64_ ? 240 : 224;
        push_struct(result, file_header_);

        // Optional header + data directories
        if (is_64_) {
            build_optional_header_64(result);
        } else {
            build_optional_header_32(result);
        }

        // Section headers
        for (auto& sec : sections_) {
            push_struct(result, sec);
        }

        // Section data
        for (size_t i = 0; i < sections_.size(); i++) {
            while (result.size() < sections_[i].PointerToRawData) {
                result.push_back(0);
            }
            if (!section_data_[i].empty()) {
                result.insert(result.end(), section_data_[i].begin(), section_data_[i].end());
            }
            while (result.size() < sections_[i].PointerToRawData + sections_[i].SizeOfRawData) {
                result.push_back(0);
            }
        }

        return result;
    }

private:
    template <typename T>
    static void push_struct(std::vector<uint8_t>& v, const T& s) {
        auto* p = reinterpret_cast<const uint8_t*>(&s);
        v.insert(v.end(), p, p + sizeof(T));
    }

    static void push_u32(std::vector<uint8_t>& v, uint32_t val) {
        v.push_back(static_cast<uint8_t>(val & 0xFF));
        v.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        v.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        v.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    }

    void build_optional_header_32(std::vector<uint8_t>& result) {
        pefile::OptionalHeader32 opt{};
        opt.Magic = 0x10B;
        opt.SizeOfCode = 0x200;
        opt.AddressOfEntryPoint = entry_point_;
        opt.BaseOfCode = 0x1000;
        opt.BaseOfData = 0x2000;
        opt.ImageBase = static_cast<uint32_t>(image_base_);
        opt.SectionAlignment = 0x1000;
        opt.FileAlignment = 0x200;
        opt.MajorOperatingSystemVersion = 4;
        opt.MajorSubsystemVersion = 4;
        opt.SizeOfImage = 0x4000;
        opt.SizeOfHeaders = 0x200;
        opt.Subsystem = subsystem_;
        opt.SizeOfStackReserve = 0x100000;
        opt.SizeOfStackCommit = 0x1000;
        opt.SizeOfHeapReserve = 0x100000;
        opt.SizeOfHeapCommit = 0x1000;
        opt.NumberOfRvaAndSizes = num_data_dirs_;

        // Write optional header fields before data directories
        auto* base = reinterpret_cast<const uint8_t*>(&opt);
        size_t fields_size = sizeof(pefile::OptionalHeader32) - sizeof(pefile::DataDirectoryRaw) * 16;
        result.insert(result.end(), base, base + fields_size);

        // Data directories
        for (auto& dd : data_dirs_) {
            push_struct(result, dd);
        }
    }

    void build_optional_header_64(std::vector<uint8_t>& result) {
        pefile::OptionalHeader64 opt{};
        opt.Magic = 0x20B;
        opt.SizeOfCode = 0x200;
        opt.AddressOfEntryPoint = entry_point_;
        opt.BaseOfCode = 0x1000;
        opt.ImageBase = image_base_;
        opt.SectionAlignment = 0x1000;
        opt.FileAlignment = 0x200;
        opt.MajorOperatingSystemVersion = 4;
        opt.MajorSubsystemVersion = 4;
        opt.SizeOfImage = 0x4000;
        opt.SizeOfHeaders = 0x200;
        opt.Subsystem = subsystem_;
        opt.SizeOfStackReserve = 0x100000;
        opt.SizeOfStackCommit = 0x1000;
        opt.SizeOfHeapReserve = 0x100000;
        opt.SizeOfHeapCommit = 0x1000;
        opt.NumberOfRvaAndSizes = num_data_dirs_;

        // Write optional header fields before data directories
        auto* base = reinterpret_cast<const uint8_t*>(&opt);
        size_t fields_size = sizeof(pefile::OptionalHeader64) - sizeof(pefile::DataDirectoryRaw) * 16;
        result.insert(result.end(), base, base + fields_size);

        // Data directories
        for (auto& dd : data_dirs_) {
            push_struct(result, dd);
        }
    }

    bool is_64_;
    pefile::FileHeader file_header_{};
    uint16_t subsystem_ = 3; // WINDOWS_CUI
    uint32_t entry_point_ = 0x1000;
    uint64_t image_base_ = 0x00400000;
    uint32_t num_data_dirs_ = 16;

    std::vector<pefile::SectionHeader> sections_;
    std::vector<std::vector<uint8_t>> section_data_;
    pefile::DataDirectoryRaw data_dirs_[16] = {};

    std::vector<uint8_t> export_data_;
    std::vector<uint8_t> import_data_;
    std::vector<uint8_t> resource_data_;
    std::vector<uint8_t> exception_data_;
    std::vector<uint8_t> reloc_data_;
    std::vector<uint8_t> debug_data_;
    std::vector<uint8_t> tls_data_;
    std::vector<uint8_t> load_config_data_;
    std::vector<uint8_t> delay_import_data_;
};

} // namespace test_helpers
