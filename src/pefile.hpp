#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "pe_constants.hpp"
#include "pe_containers.hpp"
#include "pe_structures.hpp"

namespace pefile
{

  class PE
  {
  public:
    PE(const std::string& filename, bool fast_load = false);
    PE(std::span<const uint8_t> data, bool fast_load = false);
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
    uint32_t generate_checksum() const;

    std::span<const uint8_t> get_data(uint32_t rva = 0,
                                           std::optional<uint32_t> length = std::nullopt) const;
    std::vector<uint8_t> get_data_copy(uint32_t rva = 0,
                                            std::optional<uint32_t> length = std::nullopt) const;

    std::optional<std::reference_wrapper<const SectionHeader> > get_section_by_rva(uint32_t rva) const;
    std::optional<std::reference_wrapper<const SectionHeader> > get_section_by_offset(
        uint32_t offset) const;
    uint32_t get_offset_from_rva(uint32_t rva) const;
    uint32_t get_rva_from_offset(uint32_t offset) const;

    std::string get_string_at_rva(uint32_t rva, size_t max_length = MAX_STRING_LENGTH) const;
    std::string get_string_u_at_rva(uint32_t rva, size_t max_length = 0x10000) const;

    std::vector<uint8_t> get_memory_mapped_image(uint32_t max_virtual_address = 0x10000000) const;

    std::span<const uint8_t> get_overlay() const;
    std::optional<uint32_t> get_overlay_data_start_offset() const;
    std::vector<uint8_t> trim() const;

    std::string get_imphash() const;
    std::string get_exphash() const;

    std::optional<RichHeaderData> parse_rich_header();
    std::string get_rich_header_hash() const;

    std::vector<std::string> get_warnings() const { return m_warnings; }
    void show_warnings() const;

    std::string dump_info() const;

    std::vector<std::string> get_resources_strings() const;

    uint8_t get_byte_at_rva(uint32_t rva) const;
    uint16_t get_word_at_rva(uint32_t rva) const;
    uint32_t get_dword_at_rva(uint32_t rva) const;
    uint64_t get_qword_at_rva(uint32_t rva) const;

    uint8_t get_byte_at_offset(uint32_t offset) const;
    uint16_t get_word_at_offset(uint32_t offset) const;
    uint32_t get_dword_at_offset(uint32_t offset) const;
    uint64_t get_qword_at_offset(uint32_t offset) const;

    bool set_bytes_at_rva(uint32_t rva, std::span<const uint8_t> data);
    bool set_bytes_at_offset(uint32_t offset, std::span<const uint8_t> data);
    bool set_word_at_rva(uint32_t rva, uint16_t word);
    bool set_dword_at_rva(uint32_t rva, uint32_t dword);
    bool set_qword_at_rva(uint32_t rva, uint64_t qword);
    bool set_word_at_offset(uint32_t offset, uint16_t word);
    bool set_dword_at_offset(uint32_t offset, uint32_t dword);
    bool set_qword_at_offset(uint32_t offset, uint64_t qword);

    std::vector<uint8_t> write() const;
    bool write(const std::string& filename) const;

    void parse_data_directories();

    const DosHeader& dos_header() const { return m_dos_header; }
    const FileHeader& file_header() const { return m_file_header; }
    bool is_pe32_plus() const { return m_is_pe32_plus; }
    const OptionalHeader32& optional_header_32() const { return m_optional_header_32; }
    const OptionalHeader64& optional_header_64() const { return m_optional_header_64; }
    const std::vector<DataDirectory>& data_directories() const { return m_data_directories; }
    const std::vector<SectionHeader>& sections() const { return m_sections; }

    const std::vector<ImportDescData>& imports() const { return m_imports; }
    const std::optional<ExportDirData>& exports() const { return m_exports; }
    const std::vector<DebugData>& debug_data() const { return m_debug_data; }
    const std::vector<BaseRelocationData>& relocations() const { return m_relocations; }
    const std::optional<TlsData>& tls_data() const { return m_tls_data; }
    const std::vector<ExceptionsDirEntryData>& exceptions() const { return m_exceptions; }
    const std::optional<LoadConfigData>& load_config_data() const { return m_load_config_data; }
    const std::optional<VersionInfo>& version_info() const { return m_version_info; }
    const std::optional<RichHeaderData>& rich_header() const { return m_rich_header; }
    const std::vector<ResourceDirData>& resources() const { return m_resources; }
    const std::vector<DelayImportDescData>& delay_imports() const { return m_delay_imports; }

    uint32_t pe_type() const { return m_pe_type; }

  private:
    void parse();
    void full_load();
    void parse_sections(size_t offset, size_t max_offset = 0x10000000);

    std::vector<ImportDescData> parse_import_directory(uint32_t rva, uint32_t size);
    std::vector<ImportData> parse_imports(uint32_t original_first_thunk,
                                          uint32_t first_thunk,
                                          uint32_t forwarder_chain,
                                          uint32_t max_length = 0);
    std::optional<ExportDirData> parse_export_directory(uint32_t rva, uint32_t size);
    std::vector<DebugData> parse_debug_directory(uint32_t rva, uint32_t size);
    std::vector<BaseRelocationData> parse_relocations_directory(uint32_t rva, uint32_t size);
    std::optional<TlsData> parse_directory_tls(uint32_t rva, uint32_t size);
    std::vector<ExceptionsDirEntryData> parse_exceptions_directory(uint32_t rva, uint32_t size);
    std::optional<LoadConfigData> parse_directory_load_config(uint32_t rva, uint32_t size);
    std::vector<BoundImportDescData> parse_directory_bound_imports(uint32_t rva, uint32_t size);
    std::optional<VersionInfo> parse_version_information(uint32_t rva);
    std::vector<DelayImportDescData> parse_delay_import_directory(uint32_t rva, uint32_t size);
    std::optional<ResourceDirData> parse_resources_directory(uint32_t rva,
                                                             uint32_t size = 0,
                                                             uint32_t base_rva = 0,
                                                             int level = 0,
                                                             std::vector<uint32_t> dirs = {});
    std::optional<ImageResourceDataEntry> parse_resource_data_entry(uint32_t rva);

    const SectionHeader* find_section_for_rva(uint32_t rva) const;
    const SectionHeader* find_section_for_offset(uint32_t offset) const;
    std::span<const uint8_t> get_data_span(uint32_t rva, uint32_t length) const;

    std::vector<uint8_t> m_data;
    size_t m_data_size = 0;

    DosHeader m_dos_header{};
    FileHeader m_file_header{};
    bool m_is_pe32_plus = false;
    OptionalHeader32 m_optional_header_32{};
    OptionalHeader64 m_optional_header_64{};
    std::vector<DataDirectory> m_data_directories;
    std::vector<SectionHeader> m_sections;

    std::vector<ImportDescData> m_imports;
    std::optional<ExportDirData> m_exports;
    std::vector<DebugData> m_debug_data;
    std::vector<BaseRelocationData> m_relocations;
    std::optional<TlsData> m_tls_data;
    std::vector<ExceptionsDirEntryData> m_exceptions;
    std::optional<LoadConfigData> m_load_config_data;
    std::optional<VersionInfo> m_version_info;
    std::optional<RichHeaderData> m_rich_header;
    std::vector<ResourceDirData> m_resources;
    std::vector<BoundImportDescData> m_bound_imports;
    std::vector<DelayImportDescData> m_delay_imports;

    uint32_t m_pe_type = 0;
    std::vector<std::string> m_warnings;

    void add_warning(const std::string& w) { m_warnings.push_back(w); }
  };

} // namespace pefile
