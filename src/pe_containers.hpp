#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <optional>

namespace pefile {

class PE;

struct ImportData {
    std::uint16_t ordinal = 0;
    std::string name;
    bool bound = false;
    bool import_by_ordinal = false;
    std::uint16_t hint = 0;
    std::uint64_t address = 0;
    std::uint64_t name_offset = 0;
    bool name_from_ordinal = false;
    std::uint32_t hint_name_table_rva = 0;
    std::uint32_t thunk_offset = 0;
    std::uint32_t thunk_rva = 0;
    PE* pe = nullptr;
};

struct ImportDescData {
    std::string dll;
    std::vector<ImportData> imports;
    std::uint32_t struct_offset = 0;
};

struct DelayImportDescData {
    std::string dll;
    std::vector<ImportData> imports;
    std::uint32_t struct_offset = 0;
};

struct ExportData {
    std::uint32_t ordinal = 0;
    std::uint64_t address = 0;
    std::string name;
    std::string forwarder;
    bool is_forwarder = false;
    std::uint32_t ordinal_offset = 0;
    std::uint64_t address_offset = 0;
    std::uint64_t name_offset = 0;
    std::uint64_t forwarder_offset = 0;
};

struct ExportDirData {
    std::uint32_t struct_offset = 0;
    std::vector<ExportData> symbols;
    std::string name;
};

struct ResourceDirEntryData {
    std::uint32_t struct_offset = 0;
    std::string name;
    std::uint32_t id = 0;
    std::shared_ptr<struct ResourceDirData> directory;
    std::shared_ptr<struct ResourceDataEntryData> data_entry;
};

struct ResourceDirData {
    std::uint32_t struct_offset = 0;
    std::vector<ResourceDirEntryData> entries;
};

struct ResourceDataEntryData {
    std::uint32_t struct_offset = 0;
    std::uint32_t lang = 0;
    std::uint32_t sublang = 0;
    std::uint32_t data_rva = 0;
    std::uint32_t size = 0;
};

struct RelocationData {
    std::uint32_t type = 0;
    std::uint32_t rva = 0;
    std::uint32_t base_rva = 0;
    std::uint32_t struct_offset = 0;
};

struct BaseRelocationData {
    std::uint32_t struct_offset = 0;
    std::vector<RelocationData> entries;
};

struct DebugData {
    std::uint32_t struct_offset = 0;
    std::uint32_t type = 0;
    std::uint32_t size_of_data = 0;
    std::uint32_t address_of_raw_data = 0;
    std::uint32_t pointer_to_raw_data = 0;
};

struct TlsData {
    std::uint32_t struct_offset = 0;
    std::uint64_t start_address_of_raw_data = 0;
    std::uint64_t end_address_of_raw_data = 0;
    std::uint64_t address_of_index = 0;
    std::uint64_t address_of_callbacks = 0;
};

struct BoundImportDescData {
    std::uint32_t struct_offset = 0;
    std::string name;
    std::uint32_t time_date_stamp = 0;
    std::vector<struct BoundImportRefData> entries;
};

struct BoundImportRefData {
    std::uint32_t struct_offset = 0;
    std::uint16_t offset = 0;
    std::uint16_t time_date_stamp = 0;
};

struct ExceptionsDirEntryData {
    std::uint32_t struct_offset = 0;
    std::uint32_t begin_address = 0;
    std::uint32_t end_address = 0;
    std::uint32_t unwind_data = 0;
};

struct LoadConfigData {
    std::uint32_t struct_offset = 0;
    std::uint32_t size = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t global_flags_clear = 0;
    std::uint32_t global_flags_set = 0;
    std::uint32_t critical_section_default_timeout = 0;
    std::uint64_t de_commit_free_block_threshold = 0;
    std::uint64_t de_commit_total_free_threshold = 0;
    std::uint64_t lock_prefix_table = 0;
    std::uint64_t maximum_allocation_size = 0;
    std::uint64_t virtual_memory_threshold = 0;
    std::uint64_t process_affinity_mask = 0;
    std::uint32_t process_heap_flags = 0;
    std::uint16_t csd_version = 0;
    std::uint16_t dependent_load_flags = 0;
    std::uint64_t edit_list = 0;
    std::uint64_t security_cookie = 0;
    std::uint64_t se_handler_table = 0;
    std::uint64_t se_handler_count = 0;
    std::uint64_t guard_cf_check_function_pointer = 0;
    std::uint64_t guard_cf_dispatch_function_pointer = 0;
    std::uint64_t guard_cf_function_table = 0;
    std::uint64_t guard_cf_function_count = 0;
    std::uint32_t guard_flags = 0;
    std::uint16_t code_integrity_flags = 0;
    std::uint16_t code_integrity_catalog = 0;
    std::uint32_t code_integrity_catalog_offset = 0;
    std::uint32_t code_integrity_reserved = 0;
    std::uint64_t guard_address_taken_iat_entry_table = 0;
    std::uint64_t guard_address_taken_iat_entry_count = 0;
    std::uint64_t guard_long_jump_target_table = 0;
    std::uint64_t guard_long_jump_target_count = 0;
    std::uint64_t dynamic_value_reloc_table = 0;
    std::uint64_t chpe_metadata_pointer = 0;
    std::uint64_t guard_rf_failure_routine = 0;
    std::uint64_t guard_rf_failure_routine_function_pointer = 0;
    std::uint32_t dynamic_value_reloc_table_offset = 0;
    std::uint16_t dynamic_value_reloc_table_section = 0;
    std::uint16_t reserved2 = 0;
    std::uint64_t guard_rf_verify_stack_pointer_function_pointer = 0;
    std::uint32_t hot_patch_table_offset = 0;
    std::uint32_t reserved3 = 0;
    std::uint64_t enclave_configuration_pointer = 0;
    std::uint64_t volatile_metadata_pointer = 0;
    std::uint64_t guard_eh_continuation_table = 0;
    std::uint64_t guard_eh_continuation_count = 0;
    std::uint64_t guard_xfg_check_function_pointer = 0;
    std::uint64_t guard_xfg_dispatch_function_pointer = 0;
    std::uint64_t guard_xfg_table_dispatch_function_pointer = 0;
    std::uint64_t cast_guard_os_determined_failure_mode = 0;
    std::uint64_t guard_memcpy_function_pointer = 0;
};

struct DynamicRelocationData {
    std::uint32_t struct_offset = 0;
    std::uint32_t symbol = 0;
};

struct VersionInfo {
    std::string name;
    std::uint32_t signature = 0;
    std::uint16_t struct_version = 0;
    std::uint32_t version_ms = 0;
    std::uint32_t version_ls = 0;
    std::uint32_t product_version_ms = 0;
    std::uint32_t product_version_ls = 0;
    std::uint32_t file_flags_mask = 0;
    std::uint32_t file_flags = 0;
    std::uint32_t file_os = 0;
    std::uint32_t file_type = 0;
    std::uint32_t file_subtype = 0;
    std::uint32_t file_date_ms = 0;
    std::uint32_t file_date_ls = 0;
    std::unordered_map<std::string, std::string> strings;
};

} // namespace pefile
