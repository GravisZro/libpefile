#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "pe_structures.hpp"

namespace test_helpers
{

  class PeBuilder
  {
  public:
    PeBuilder(bool is_64 = false) : m_is_64(is_64) {}

    void set_characteristics(uint16_t c) { m_file_header.Characteristics = c; }
    void set_machine(uint16_t m) { m_file_header.Machine = m; }
    void set_subsystem(uint16_t s) { m_subsystem = s; }
    void set_entry_point(uint32_t ep) { m_entry_point = ep; }
    void set_image_base(uint64_t ib) { m_image_base = ib; }
    void set_num_sections(uint16_t n) { m_file_header.NumberOfSections = n; }
    void set_num_data_dirs(uint32_t n) { m_num_data_dirs = n; }

    void add_section(const std::string& name,
                     uint32_t virtual_size,
                     uint32_t virtual_address,
                     uint32_t size_of_raw_data,
                     uint32_t pointer_to_raw_data,
                     uint32_t characteristics,
                     const std::vector<uint8_t>& data = {})
    {
      pefile::SectionHeader sec{};
      std::strncpy(sec.Name, name.c_str(), 8);
      sec.VirtualSize = virtual_size;
      sec.VirtualAddress = virtual_address;
      sec.SizeOfRawData = size_of_raw_data;
      sec.PointerToRawData = pointer_to_raw_data;
      sec.Characteristics = characteristics;
      m_section_data.push_back(data);
      m_sections.push_back(sec);
    }

    void add_export_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[0] = {rva, size};
      m_export_data = data;
    }

    void add_import_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[1] = {rva, size};
      m_import_data = data;
    }

    void add_resource_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[2] = {rva, size};
      m_resource_data = data;
    }

    void add_exception_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[3] = {rva, size};
      m_exception_data = data;
    }

    void add_reloc_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[5] = {rva, size};
      m_reloc_data = data;
    }

    void add_debug_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[6] = {rva, size};
      m_debug_data = data;
    }

    void add_tls_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[9] = {rva, size};
      m_tls_data = data;
    }

    void add_load_config_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[10] = {rva, size};
      m_load_config_data = data;
    }

    void add_delay_import_directory(uint32_t rva, uint32_t size, const std::vector<uint8_t>& data)
    {
      m_data_dirs[13] = {rva, size};
      m_delay_import_data = data;
    }

    std::vector<uint8_t> build()
    {
      if (m_file_header.NumberOfSections == 0)
        m_file_header.NumberOfSections = static_cast<uint16_t>(m_sections.size());
      if (m_num_data_dirs == 0)
        m_num_data_dirs = 16;

      std::vector<uint8_t> result;

      // DOS header (64 bytes)
      pefile::DosHeader dos{};
      dos.e_magic = 0x5A4D;
      dos.e_lfanew = 0x40;
      push_struct(result, dos);

      // PE signature
      push_u32(result, 0x00004550); // "PE\0\0"

      // COFF file header
      m_file_header.SizeOfOptionalHeader = m_is_64 ? 240 : 224;
      push_struct(result, m_file_header);

      // Optional header + data directories
      if (m_is_64)
        build_optional_header_64(result);
      else
        build_optional_header_32(result);

      // Section headers
      for (auto& sec : m_sections)
        push_struct(result, sec);

      // Section data
      for (size_t i = 0; i < m_sections.size(); i++)
      {
        while (result.size() < m_sections[i].PointerToRawData)
          result.push_back(0);

        if (!m_section_data[i].empty())
          result.insert(result.end(), m_section_data[i].begin(), m_section_data[i].end());

        while (result.size() < m_sections[i].PointerToRawData + m_sections[i].SizeOfRawData)
          result.push_back(0);
      }

      return result;
    }

  private:
    template<typename T>
    static void push_struct(std::vector<uint8_t>& v, const T& s)
    {
      auto* p = reinterpret_cast<const uint8_t*>(&s);
      v.insert(v.end(), p, p + sizeof(T));
    }

    static void push_u32(std::vector<uint8_t>& v, uint32_t val)
    {
      v.push_back(static_cast<uint8_t>(val & 0xFF));
      v.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
      v.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
      v.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    }

    void build_optional_header_32(std::vector<uint8_t>& result)
    {
      pefile::OptionalHeader32 opt{};
      opt.Magic = 0x10B;
      opt.SizeOfCode = 0x200;
      opt.AddressOfEntryPoint = m_entry_point;
      opt.BaseOfCode = 0x1000;
      opt.BaseOfData = 0x2000;
      opt.ImageBase = static_cast<uint32_t>(m_image_base);
      opt.SectionAlignment = 0x1000;
      opt.FileAlignment = 0x200;
      opt.MajorOperatingSystemVersion = 4;
      opt.MajorSubsystemVersion = 4;
      opt.SizeOfImage = 0x4000;
      opt.SizeOfHeaders = 0x200;
      opt.Subsystem = m_subsystem;
      opt.SizeOfStackReserve = 0x100000;
      opt.SizeOfStackCommit = 0x1000;
      opt.SizeOfHeapReserve = 0x100000;
      opt.SizeOfHeapCommit = 0x1000;
      opt.NumberOfRvaAndSizes = m_num_data_dirs;

      // Write optional header fields before data directories
      auto* base = reinterpret_cast<const uint8_t*>(&opt);
      size_t fields_size = sizeof(pefile::OptionalHeader32);
      result.insert(result.end(), base, base + fields_size);

      // Data directories
      for (auto& dd : m_data_dirs)
        push_struct(result, dd);
    }

    void build_optional_header_64(std::vector<uint8_t>& result)
    {
      pefile::OptionalHeader64 opt{};
      opt.Magic = 0x20B;
      opt.SizeOfCode = 0x200;
      opt.AddressOfEntryPoint = m_entry_point;
      opt.BaseOfCode = 0x1000;
      opt.ImageBase = m_image_base;
      opt.SectionAlignment = 0x1000;
      opt.FileAlignment = 0x200;
      opt.MajorOperatingSystemVersion = 4;
      opt.MajorSubsystemVersion = 4;
      opt.SizeOfImage = 0x4000;
      opt.SizeOfHeaders = 0x200;
      opt.Subsystem = m_subsystem;
      opt.SizeOfStackReserve = 0x100000;
      opt.SizeOfStackCommit = 0x1000;
      opt.SizeOfHeapReserve = 0x100000;
      opt.SizeOfHeapCommit = 0x1000;
      opt.NumberOfRvaAndSizes = m_num_data_dirs;

      // Write optional header fields before data directories
      auto* base = reinterpret_cast<const uint8_t*>(&opt);
      size_t fields_size = sizeof(pefile::OptionalHeader64);
      result.insert(result.end(), base, base + fields_size);

      // Data directories
      for (auto& dd : m_data_dirs)
        push_struct(result, dd);
    }

    bool m_is_64;
    pefile::FileHeader m_file_header{};
    uint16_t m_subsystem = 3; // WINDOWS_CUI
    uint32_t m_entry_point = 0x1000;
    uint64_t m_image_base = 0x00400000;
    uint32_t m_num_data_dirs = 16;

    std::vector<pefile::SectionHeader> m_sections;
    std::vector<std::vector<uint8_t> > m_section_data;
    pefile::DataDirectoryRaw m_data_dirs[16] = {};

    std::vector<uint8_t> m_export_data;
    std::vector<uint8_t> m_import_data;
    std::vector<uint8_t> m_resource_data;
    std::vector<uint8_t> m_exception_data;
    std::vector<uint8_t> m_reloc_data;
    std::vector<uint8_t> m_debug_data;
    std::vector<uint8_t> m_tls_data;
    std::vector<uint8_t> m_load_config_data;
    std::vector<uint8_t> m_delay_import_data;
  };

} // namespace test_helpers
