#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <functional>
#include <memory>
#include <array>

#include "pe_structures.hpp"
#include "pe_containers.hpp"
#include "pe_constants.hpp"

namespace pefile {

class PE {
public:
    PE(const std::string& filename, bool fast_load = false);
    PE(std::span<const std::uint8_t> data, bool fast_load = false);
    ~PE();

    PE(const PE&) = delete;
    PE& operator=(const PE&) = delete;
    PE(PE&&) noexcept;
    PE& operator=(PE&&) noexcept;

    bool is_exe() const;
    bool is_dll() const;
    bool is_driver() const;
    bool has_relocs() const;
    bool has_dynamic_relocs() const;
    bool verify_checksum() const;
    std::uint32_t generate_checksum() const;

    std::span<const std::uint8_t> get_data(std::uint32_t rva = 0,
                                            std::optional<std::uint32_t> length = std::nullopt) const;
    std::vector<std::uint8_t> get_data_copy(std::uint32_t rva = 0,
                                             std::optional<std::uint32_t> length = std::nullopt) const;

    std::optional<std::reference_wrapper<const SectionHeader>> get_section_by_rva(std::uint32_t rva) const;
    std::optional<std::reference_wrapper<const SectionHeader>> get_section_by_offset(std::uint32_t offset) const;
    std::uint32_t get_offset_from_rva(std::uint32_t rva) const;
    std::uint32_t get_rva_from_offset(std::uint32_t offset) const;

    std::string get_string_at_rva(std::uint32_t rva,
                                   std::size_t max_length = MAX_STRING_LENGTH) const;
    std::string get_string_u_at_rva(std::uint32_t rva,
                                     std::size_t max_length = 0x10000) const;

    std::vector<std::uint8_t> get_memory_mapped_image(
        std::uint32_t max_virtual_address = 0x10000000) const;

    std::span<const std::uint8_t> get_overlay() const;
    std::optional<std::uint32_t> get_overlay_data_start_offset() const;
    std::vector<std::uint8_t> trim() const;

    std::string get_imphash() const;
    std::string get_exphash() const;

    std::optional<RichHeaderData> parse_rich_header();
    std::string get_rich_header_hash() const;

    std::vector<std::string> get_warnings() const { return warnings_; }
    void show_warnings() const;

    std::string dump_info() const;

    std::vector<std::string> get_resources_strings() const;

    std::uint8_t get_byte_at_rva(std::uint32_t rva) const;
    std::uint16_t get_word_at_rva(std::uint32_t rva) const;
    std::uint32_t get_dword_at_rva(std::uint32_t rva) const;
    std::uint64_t get_qword_at_rva(std::uint32_t rva) const;

    std::uint8_t get_byte_at_offset(std::uint32_t offset) const;
    std::uint16_t get_word_at_offset(std::uint32_t offset) const;
    std::uint32_t get_dword_at_offset(std::uint32_t offset) const;
    std::uint64_t get_qword_at_offset(std::uint32_t offset) const;

    bool set_bytes_at_rva(std::uint32_t rva, std::span<const std::uint8_t> data);
    bool set_bytes_at_offset(std::uint32_t offset, std::span<const std::uint8_t> data);
    bool set_word_at_rva(std::uint32_t rva, std::uint16_t word);
    bool set_dword_at_rva(std::uint32_t rva, std::uint32_t dword);
    bool set_qword_at_rva(std::uint32_t rva, std::uint64_t qword);
    bool set_word_at_offset(std::uint32_t offset, std::uint16_t word);
    bool set_dword_at_offset(std::uint32_t offset, std::uint32_t dword);
    bool set_qword_at_offset(std::uint32_t offset, std::uint64_t qword);

    std::vector<std::uint8_t> write() const;
    bool write(const std::string& filename) const;

    void parse_data_directories();

    const DosHeader& dos_header() const { return dos_header_; }
    const FileHeader& file_header() const { return file_header_; }
    bool is_pe32_plus() const { return is_pe32_plus_; }
    const OptionalHeader32& optional_header_32() const { return optional_header_32_; }
    const OptionalHeader64& optional_header_64() const { return optional_header_64_; }
    const std::vector<DataDirectory>& data_directories() const { return data_directories_; }
    const std::vector<SectionHeader>& sections() const { return sections_; }

    const std::vector<ImportDescData>& imports() const { return imports_; }
    const std::optional<ExportDirData>& exports() const { return exports_; }
    const std::vector<DebugData>& debug_data() const { return debug_data_; }
    const std::vector<BaseRelocationData>& relocations() const { return relocations_; }
    const std::optional<TlsData>& tls_data() const { return tls_data_; }
    const std::vector<ExceptionsDirEntryData>& exceptions() const { return exceptions_; }
    const std::optional<LoadConfigData>& load_config_data() const { return load_config_data_; }
    const std::optional<VersionInfo>& version_info() const { return version_info_; }
    const std::optional<RichHeaderData>& rich_header() const { return rich_header_; }
    const std::vector<ResourceDirData>& resources() const { return resources_; }
    const std::vector<DelayImportDescData>& delay_imports() const { return delay_imports_; }

    std::uint32_t pe_type() const { return pe_type_; }

private:
    void parse();
    void full_load();
    void parse_sections(std::size_t offset, std::size_t max_offset = 0x10000000);

    std::vector<ImportDescData> parse_import_directory(std::uint32_t rva, std::uint32_t size);
    std::vector<ImportData> parse_imports(std::uint32_t original_first_thunk,
                                           std::uint32_t first_thunk,
                                           std::uint32_t forwarder_chain,
                                           std::uint32_t max_length = 0);
    std::optional<ExportDirData> parse_export_directory(std::uint32_t rva, std::uint32_t size);
    std::vector<DebugData> parse_debug_directory(std::uint32_t rva, std::uint32_t size);
    std::vector<BaseRelocationData> parse_relocations_directory(std::uint32_t rva, std::uint32_t size);
    std::optional<TlsData> parse_directory_tls(std::uint32_t rva, std::uint32_t size);
    std::vector<ExceptionsDirEntryData> parse_exceptions_directory(std::uint32_t rva, std::uint32_t size);
    std::optional<LoadConfigData> parse_directory_load_config(std::uint32_t rva, std::uint32_t size);
    std::vector<BoundImportDescData> parse_directory_bound_imports(std::uint32_t rva, std::uint32_t size);
    std::optional<VersionInfo> parse_version_information(std::uint32_t rva);
    std::vector<DelayImportDescData> parse_delay_import_directory(std::uint32_t rva, std::uint32_t size);
    std::optional<ResourceDirData> parse_resources_directory(std::uint32_t rva, std::uint32_t size = 0,
                                                            std::uint32_t base_rva = 0, int level = 0,
                                                            std::vector<std::uint32_t> dirs = {});
    std::optional<ImageResourceDataEntry> parse_resource_data_entry(std::uint32_t rva);

    const SectionHeader* find_section_for_rva(std::uint32_t rva) const;
    const SectionHeader* find_section_for_offset(std::uint32_t offset) const;
    std::span<const std::uint8_t> get_data_span(std::uint32_t rva, std::uint32_t length) const;

    mutable std::vector<std::uint8_t> data_;
    std::size_t data_size_ = 0;

    DosHeader dos_header_{};
    FileHeader file_header_{};
    bool is_pe32_plus_ = false;
    OptionalHeader32 optional_header_32_{};
    OptionalHeader64 optional_header_64_{};
    std::vector<DataDirectory> data_directories_;
    std::vector<SectionHeader> sections_;

    std::vector<ImportDescData> imports_;
    std::optional<ExportDirData> exports_;
    std::vector<DebugData> debug_data_;
    std::vector<BaseRelocationData> relocations_;
    std::optional<TlsData> tls_data_;
    std::vector<ExceptionsDirEntryData> exceptions_;
    std::optional<LoadConfigData> load_config_data_;
    std::optional<VersionInfo> version_info_;
    std::optional<RichHeaderData> rich_header_;
    std::vector<ResourceDirData> resources_;
    std::vector<BoundImportDescData> bound_imports_;
    std::vector<DelayImportDescData> delay_imports_;

    std::uint32_t pe_type_ = 0;
    std::uint32_t overlay_offset_ = 0;
    std::vector<std::string> warnings_;

    mutable const SectionHeader* last_section_by_rva_ = nullptr;
    mutable const SectionHeader* last_section_by_offset_ = nullptr;

    void add_warning(const std::string& w) { warnings_.push_back(w); }
};

} // namespace pefile
