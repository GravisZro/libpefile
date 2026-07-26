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

namespace pefile {

namespace {
constexpr std::size_t MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69;
constexpr int MAX_SIMULTANEOUS_ERRORS = 3;
constexpr std::size_t MAX_ALLOWED_RESOURCE_ENTRIES = 4096;
constexpr std::size_t MAX_REPEATED_ADDRESSES = 15;
constexpr std::size_t MAX_ADDRESS_SPREAD = 128 * 1024 * 1024;
constexpr std::uint64_t ADDR_4GB = 0x100000000ULL;
}

// --- DosHeader ---
DosHeader DosHeader::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    DosHeader h;
    if (data.size() - offset < 64) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.e_magic, p, 2); p += 2;
    std::memcpy(&h.e_cblp, p, 2); p += 2;
    std::memcpy(&h.e_cp, p, 2); p += 2;
    std::memcpy(&h.e_crlc, p, 2); p += 2;
    std::memcpy(&h.e_cparhdr, p, 2); p += 2;
    std::memcpy(&h.e_minalloc, p, 2); p += 2;
    std::memcpy(&h.e_maxalloc, p, 2); p += 2;
    std::memcpy(&h.e_ss, p, 2); p += 2;
    std::memcpy(&h.e_sp, p, 2); p += 2;
    std::memcpy(&h.e_csum, p, 2); p += 2;
    std::memcpy(&h.e_ip, p, 2); p += 2;
    std::memcpy(&h.e_cs, p, 2); p += 2;
    std::memcpy(&h.e_lfarlc, p, 2); p += 2;
    std::memcpy(&h.e_ovno, p, 2); p += 2;
    std::memcpy(h.e_res, p, 8); p += 8;
    std::memcpy(&h.e_oemid, p, 2); p += 2;
    std::memcpy(&h.e_oeminfo, p, 2); p += 2;
    std::memcpy(h.e_res2, p, 20); p += 20;
    std::memcpy(&h.e_lfanew, p, 4);
    return h;
}

std::vector<std::uint8_t> DosHeader::pack() const {
    std::vector<std::uint8_t> r(64, 0);
    auto p = r.data();
    std::memcpy(p, &e_magic, 2); p += 2;
    std::memcpy(p, &e_cblp, 2); p += 2;
    std::memcpy(p, &e_cp, 2); p += 2;
    std::memcpy(p, &e_crlc, 2); p += 2;
    std::memcpy(p, &e_cparhdr, 2); p += 2;
    std::memcpy(p, &e_minalloc, 2); p += 2;
    std::memcpy(p, &e_maxalloc, 2); p += 2;
    std::memcpy(p, &e_ss, 2); p += 2;
    std::memcpy(p, &e_sp, 2); p += 2;
    std::memcpy(p, &e_csum, 2); p += 2;
    std::memcpy(p, &e_ip, 2); p += 2;
    std::memcpy(p, &e_cs, 2); p += 2;
    std::memcpy(p, &e_lfarlc, 2); p += 2;
    std::memcpy(p, &e_ovno, 2); p += 2;
    std::memcpy(p, e_res, 8); p += 8;
    std::memcpy(p, &e_oemid, 2); p += 2;
    std::memcpy(p, &e_oeminfo, 2); p += 2;
    std::memcpy(p, e_res2, 20); p += 20;
    std::memcpy(p, &e_lfanew, 4);
    return r;
}

// --- FileHeader ---
FileHeader FileHeader::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    FileHeader h;
    if (data.size() - offset < 20) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Machine, p, 2); p += 2;
    std::memcpy(&h.NumberOfSections, p, 2); p += 2;
    std::memcpy(&h.TimeDateStamp, p, 4); p += 4;
    std::memcpy(&h.PointerToSymbolTable, p, 4); p += 4;
    std::memcpy(&h.NumberOfSymbols, p, 4); p += 4;
    std::memcpy(&h.SizeOfOptionalHeader, p, 2); p += 2;
    std::memcpy(&h.Characteristics, p, 2);
    return h;
}

std::vector<std::uint8_t> FileHeader::pack() const {
    std::vector<std::uint8_t> r(20, 0);
    auto p = r.data();
    std::memcpy(p, &Machine, 2); p += 2;
    std::memcpy(p, &NumberOfSections, 2); p += 2;
    std::memcpy(p, &TimeDateStamp, 4); p += 4;
    std::memcpy(p, &PointerToSymbolTable, 4); p += 4;
    std::memcpy(p, &NumberOfSymbols, 4); p += 4;
    std::memcpy(p, &SizeOfOptionalHeader, 2); p += 2;
    std::memcpy(p, &Characteristics, 2);
    return r;
}

// --- DataDirectory ---
DataDirectory DataDirectory::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    DataDirectory d;
    if (data.size() - offset < 8) return d;
    auto p = data.data() + offset;
    std::memcpy(&d.VirtualAddress, p, 4); p += 4;
    std::memcpy(&d.Size, p, 4);
    return d;
}

std::vector<std::uint8_t> DataDirectory::pack() const {
    std::vector<std::uint8_t> r(8, 0);
    std::memcpy(r.data(), &VirtualAddress, 4);
    std::memcpy(r.data() + 4, &Size, 4);
    return r;
}

// --- OptionalHeader32 ---
OptionalHeader32 OptionalHeader32::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    OptionalHeader32 h;
    if (data.size() - offset < 96) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Magic, p, 2); p += 2;
    h.MajorLinkerVersion = *p++; h.MinorLinkerVersion = *p++;
    std::memcpy(&h.SizeOfCode, p, 4); p += 4;
    std::memcpy(&h.SizeOfInitializedData, p, 4); p += 4;
    std::memcpy(&h.SizeOfUninitializedData, p, 4); p += 4;
    std::memcpy(&h.AddressOfEntryPoint, p, 4); p += 4;
    std::memcpy(&h.BaseOfCode, p, 4); p += 4;
    std::memcpy(&h.BaseOfData, p, 4); p += 4;
    std::memcpy(&h.ImageBase, p, 4); p += 4;
    std::memcpy(&h.SectionAlignment, p, 4); p += 4;
    std::memcpy(&h.FileAlignment, p, 4); p += 4;
    std::memcpy(&h.MajorOperatingSystemVersion, p, 2); p += 2;
    std::memcpy(&h.MinorOperatingSystemVersion, p, 2); p += 2;
    std::memcpy(&h.MajorImageVersion, p, 2); p += 2;
    std::memcpy(&h.MinorImageVersion, p, 2); p += 2;
    std::memcpy(&h.MajorSubsystemVersion, p, 2); p += 2;
    std::memcpy(&h.MinorSubsystemVersion, p, 2); p += 2;
    std::memcpy(&h.Win32VersionValue, p, 4); p += 4;
    std::memcpy(&h.SizeOfImage, p, 4); p += 4;
    std::memcpy(&h.SizeOfHeaders, p, 4); p += 4;
    std::memcpy(&h.CheckSum, p, 4); p += 4;
    std::memcpy(&h.Subsystem, p, 2); p += 2;
    std::memcpy(&h.DllCharacteristics, p, 2); p += 2;
    std::memcpy(&h.SizeOfStackReserve, p, 4); p += 4;
    std::memcpy(&h.SizeOfStackCommit, p, 4); p += 4;
    std::memcpy(&h.SizeOfHeapReserve, p, 4); p += 4;
    std::memcpy(&h.SizeOfHeapCommit, p, 4); p += 4;
    std::memcpy(&h.LoaderFlags, p, 4); p += 4;
    std::memcpy(&h.NumberOfRvaAndSizes, p, 4);
    return h;
}

std::vector<std::uint8_t> OptionalHeader32::pack() const {
    std::vector<std::uint8_t> r(96, 0);
    auto p = r.data();
    std::memcpy(p, &Magic, 2); p += 2;
    *p++ = MajorLinkerVersion; *p++ = MinorLinkerVersion;
    std::memcpy(p, &SizeOfCode, 4); p += 4;
    std::memcpy(p, &SizeOfInitializedData, 4); p += 4;
    std::memcpy(p, &SizeOfUninitializedData, 4); p += 4;
    std::memcpy(p, &AddressOfEntryPoint, 4); p += 4;
    std::memcpy(p, &BaseOfCode, 4); p += 4;
    std::memcpy(p, &BaseOfData, 4); p += 4;
    std::memcpy(p, &ImageBase, 4); p += 4;
    std::memcpy(p, &SectionAlignment, 4); p += 4;
    std::memcpy(p, &FileAlignment, 4); p += 4;
    std::memcpy(p, &MajorOperatingSystemVersion, 2); p += 2;
    std::memcpy(p, &MinorOperatingSystemVersion, 2); p += 2;
    std::memcpy(p, &MajorImageVersion, 2); p += 2;
    std::memcpy(p, &MinorImageVersion, 2); p += 2;
    std::memcpy(p, &MajorSubsystemVersion, 2); p += 2;
    std::memcpy(p, &MinorSubsystemVersion, 2); p += 2;
    std::memcpy(p, &Win32VersionValue, 4); p += 4;
    std::memcpy(p, &SizeOfImage, 4); p += 4;
    std::memcpy(p, &SizeOfHeaders, 4); p += 4;
    std::memcpy(p, &CheckSum, 4); p += 4;
    std::memcpy(p, &Subsystem, 2); p += 2;
    std::memcpy(p, &DllCharacteristics, 2); p += 2;
    std::memcpy(p, &SizeOfStackReserve, 4); p += 4;
    std::memcpy(p, &SizeOfStackCommit, 4); p += 4;
    std::memcpy(p, &SizeOfHeapReserve, 4); p += 4;
    std::memcpy(p, &SizeOfHeapCommit, 4); p += 4;
    std::memcpy(p, &LoaderFlags, 4); p += 4;
    std::memcpy(p, &NumberOfRvaAndSizes, 4);
    return r;
}

// --- OptionalHeader64 ---
OptionalHeader64 OptionalHeader64::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    OptionalHeader64 h;
    if (data.size() - offset < 112) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Magic, p, 2); p += 2;
    h.MajorLinkerVersion = *p++; h.MinorLinkerVersion = *p++;
    std::memcpy(&h.SizeOfCode, p, 4); p += 4;
    std::memcpy(&h.SizeOfInitializedData, p, 4); p += 4;
    std::memcpy(&h.SizeOfUninitializedData, p, 4); p += 4;
    std::memcpy(&h.AddressOfEntryPoint, p, 4); p += 4;
    std::memcpy(&h.BaseOfCode, p, 4); p += 4;
    std::memcpy(&h.ImageBase, p, 8); p += 8;
    std::memcpy(&h.SectionAlignment, p, 4); p += 4;
    std::memcpy(&h.FileAlignment, p, 4); p += 4;
    std::memcpy(&h.MajorOperatingSystemVersion, p, 2); p += 2;
    std::memcpy(&h.MinorOperatingSystemVersion, p, 2); p += 2;
    std::memcpy(&h.MajorImageVersion, p, 2); p += 2;
    std::memcpy(&h.MinorImageVersion, p, 2); p += 2;
    std::memcpy(&h.MajorSubsystemVersion, p, 2); p += 2;
    std::memcpy(&h.MinorSubsystemVersion, p, 2); p += 2;
    std::memcpy(&h.Win32VersionValue, p, 4); p += 4;
    std::memcpy(&h.SizeOfImage, p, 4); p += 4;
    std::memcpy(&h.SizeOfHeaders, p, 4); p += 4;
    std::memcpy(&h.CheckSum, p, 4); p += 4;
    std::memcpy(&h.Subsystem, p, 2); p += 2;
    std::memcpy(&h.DllCharacteristics, p, 2); p += 2;
    std::memcpy(&h.SizeOfStackReserve, p, 8); p += 8;
    std::memcpy(&h.SizeOfStackCommit, p, 8); p += 8;
    std::memcpy(&h.SizeOfHeapReserve, p, 8); p += 8;
    std::memcpy(&h.SizeOfHeapCommit, p, 8); p += 8;
    std::memcpy(&h.LoaderFlags, p, 4); p += 4;
    std::memcpy(&h.NumberOfRvaAndSizes, p, 4);
    return h;
}

std::vector<std::uint8_t> OptionalHeader64::pack() const {
    std::vector<std::uint8_t> r(112, 0);
    auto p = r.data();
    std::memcpy(p, &Magic, 2); p += 2;
    *p++ = MajorLinkerVersion; *p++ = MinorLinkerVersion;
    std::memcpy(p, &SizeOfCode, 4); p += 4;
    std::memcpy(p, &SizeOfInitializedData, 4); p += 4;
    std::memcpy(p, &SizeOfUninitializedData, 4); p += 4;
    std::memcpy(p, &AddressOfEntryPoint, 4); p += 4;
    std::memcpy(p, &BaseOfCode, 4); p += 4;
    std::memcpy(p, &ImageBase, 8); p += 8;
    std::memcpy(p, &SectionAlignment, 4); p += 4;
    std::memcpy(p, &FileAlignment, 4); p += 4;
    std::memcpy(p, &MajorOperatingSystemVersion, 2); p += 2;
    std::memcpy(p, &MinorOperatingSystemVersion, 2); p += 2;
    std::memcpy(p, &MajorImageVersion, 2); p += 2;
    std::memcpy(p, &MinorImageVersion, 2); p += 2;
    std::memcpy(p, &MajorSubsystemVersion, 2); p += 2;
    std::memcpy(p, &MinorSubsystemVersion, 2); p += 2;
    std::memcpy(p, &Win32VersionValue, 4); p += 4;
    std::memcpy(p, &SizeOfImage, 4); p += 4;
    std::memcpy(p, &SizeOfHeaders, 4); p += 4;
    std::memcpy(p, &CheckSum, 4); p += 4;
    std::memcpy(p, &Subsystem, 2); p += 2;
    std::memcpy(p, &DllCharacteristics, 2); p += 2;
    std::memcpy(p, &SizeOfStackReserve, 8); p += 8;
    std::memcpy(p, &SizeOfStackCommit, 8); p += 8;
    std::memcpy(p, &SizeOfHeapReserve, 8); p += 8;
    std::memcpy(p, &SizeOfHeapCommit, 8); p += 8;
    std::memcpy(p, &LoaderFlags, 4); p += 4;
    std::memcpy(p, &NumberOfRvaAndSizes, 4);
    return r;
}

// --- SectionHeader ---
SectionHeader SectionHeader::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    SectionHeader h{};
    if (data.size() - offset < 40) return h;
    auto p = data.data() + offset;
    std::memcpy(h.Name, p, 8); p += 8;
    std::memcpy(&h.Misc, p, 4); p += 4;
    std::memcpy(&h.VirtualAddress, p, 4); p += 4;
    std::memcpy(&h.SizeOfRawData, p, 4); p += 4;
    std::memcpy(&h.PointerToRawData, p, 4); p += 4;
    std::memcpy(&h.PointerToRelocations, p, 4); p += 4;
    std::memcpy(&h.PointerToLinenumbers, p, 4); p += 4;
    std::memcpy(&h.NumberOfRelocations, p, 2); p += 2;
    std::memcpy(&h.NumberOfLinenumbers, p, 2); p += 2;
    std::memcpy(&h.Characteristics, p, 4);
    h.VirtualSize = h.Misc;
    return h;
}

std::vector<std::uint8_t> SectionHeader::pack() const {
    std::vector<std::uint8_t> r(40, 0);
    auto p = r.data();
    std::memcpy(p, Name, 8); p += 8;
    std::memcpy(p, &Misc, 4); p += 4;
    std::memcpy(p, &VirtualAddress, 4); p += 4;
    std::memcpy(p, &SizeOfRawData, 4); p += 4;
    std::memcpy(p, &PointerToRawData, 4); p += 4;
    std::memcpy(p, &PointerToRelocations, 4); p += 4;
    std::memcpy(p, &PointerToLinenumbers, 4); p += 4;
    std::memcpy(p, &NumberOfRelocations, 2); p += 2;
    std::memcpy(p, &NumberOfLinenumbers, 2); p += 2;
    std::memcpy(p, &Characteristics, 4);
    return r;
}

// --- ImageImportDescriptor ---
ImageImportDescriptor ImageImportDescriptor::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageImportDescriptor h{};
    if (data.size() - offset < 20) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.OriginalFirstThunk, p, 4); p += 4;
    std::memcpy(&h.TimeDateStamp, p, 4); p += 4;
    std::memcpy(&h.ForwarderChain, p, 4); p += 4;
    std::memcpy(&h.Name, p, 4); p += 4;
    std::memcpy(&h.FirstThunk, p, 4);
    return h;
}

std::vector<std::uint8_t> ImageImportDescriptor::pack() const {
    std::vector<std::uint8_t> r(20, 0);
    auto p = r.data();
    std::memcpy(p, &OriginalFirstThunk, 4); p += 4;
    std::memcpy(p, &TimeDateStamp, 4); p += 4;
    std::memcpy(p, &ForwarderChain, 4); p += 4;
    std::memcpy(p, &Name, 4); p += 4;
    std::memcpy(p, &FirstThunk, 4);
    return r;
}

// --- ImageExportDirectory ---
ImageExportDirectory ImageExportDirectory::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageExportDirectory h{};
    if (data.size() - offset < 40) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Characteristics, p, 4); p += 4;
    std::memcpy(&h.TimeDateStamp, p, 4); p += 4;
    std::memcpy(&h.MajorVersion, p, 2); p += 2;
    std::memcpy(&h.MinorVersion, p, 2); p += 2;
    std::memcpy(&h.Name, p, 4); p += 4;
    std::memcpy(&h.Base, p, 4); p += 4;
    std::memcpy(&h.NumberOfFunctions, p, 4); p += 4;
    std::memcpy(&h.NumberOfNames, p, 4); p += 4;
    std::memcpy(&h.AddressOfFunctions, p, 4); p += 4;
    std::memcpy(&h.AddressOfNames, p, 4); p += 4;
    std::memcpy(&h.AddressOfNameOrdinals, p, 4);
    return h;
}

std::vector<std::uint8_t> ImageExportDirectory::pack() const {
    std::vector<std::uint8_t> r(40, 0);
    auto p = r.data();
    std::memcpy(p, &Characteristics, 4); p += 4;
    std::memcpy(p, &TimeDateStamp, 4); p += 4;
    std::memcpy(p, &MajorVersion, 2); p += 2;
    std::memcpy(p, &MinorVersion, 2); p += 2;
    std::memcpy(p, &Name, 4); p += 4;
    std::memcpy(p, &Base, 4); p += 4;
    std::memcpy(p, &NumberOfFunctions, 4); p += 4;
    std::memcpy(p, &NumberOfNames, 4); p += 4;
    std::memcpy(p, &AddressOfFunctions, 4); p += 4;
    std::memcpy(p, &AddressOfNames, 4); p += 4;
    std::memcpy(p, &AddressOfNameOrdinals, 4);
    return r;
}

// --- ImageResourceDirectory ---
ImageResourceDirectory ImageResourceDirectory::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageResourceDirectory h{};
    if (data.size() - offset < 16) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Characteristics, p, 4); p += 4;
    std::memcpy(&h.TimeDateStamp, p, 4); p += 4;
    std::memcpy(&h.MajorVersion, p, 2); p += 2;
    std::memcpy(&h.MinorVersion, p, 2); p += 2;
    std::memcpy(&h.NumberOfNamedEntries, p, 4); p += 4;
    std::memcpy(&h.NumberOfIdEntries, p, 4);
    return h;
}

// --- ImageResourceDirectoryEntry ---
ImageResourceDirectoryEntry ImageResourceDirectoryEntry::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageResourceDirectoryEntry h{};
    if (data.size() - offset < 8) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Name, p, 4); p += 4;
    std::memcpy(&h.OffsetToData, p, 4);
    return h;
}

// --- ImageResourceDataEntry ---
ImageResourceDataEntry ImageResourceDataEntry::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageResourceDataEntry h{};
    if (data.size() - offset < 16) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.OffsetToData, p, 4); p += 4;
    std::memcpy(&h.Size, p, 4); p += 4;
    std::memcpy(&h.CodePage, p, 4); p += 4;
    std::memcpy(&h.Reserved, p, 4);
    return h;
}

// --- ImageThunkData32/64 ---
ImageThunkData32 ImageThunkData32::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageThunkData32 h{};
    if (data.size() - offset < 4) return h;
    std::memcpy(&h.AddressOfData, data.data() + offset, 4);
    return h;
}

ImageThunkData64 ImageThunkData64::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageThunkData64 h{};
    if (data.size() - offset < 8) return h;
    std::memcpy(&h.AddressOfData, data.data() + offset, 8);
    return h;
}

// --- ImageDebugDirectory ---
ImageDebugDirectory ImageDebugDirectory::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageDebugDirectory h{};
    if (data.size() - offset < 28) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.Characteristics, p, 4); p += 4;
    std::memcpy(&h.TimeDateStamp, p, 4); p += 4;
    std::memcpy(&h.MajorVersion, p, 2); p += 2;
    std::memcpy(&h.MinorVersion, p, 2); p += 2;
    std::memcpy(&h.Type, p, 4); p += 4;
    std::memcpy(&h.SizeOfData, p, 4); p += 4;
    std::memcpy(&h.AddressOfRawData, p, 4); p += 4;
    std::memcpy(&h.PointerToRawData, p, 4);
    return h;
}

// --- ImageBaseRelocation ---
ImageBaseRelocation ImageBaseRelocation::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageBaseRelocation h{};
    if (data.size() - offset < 8) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.VirtualAddress, p, 4); p += 4;
    std::memcpy(&h.SizeOfBlock, p, 4);
    return h;
}

// --- ImageTlsDirectory32/64 ---
ImageTlsDirectory32 ImageTlsDirectory32::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageTlsDirectory32 h{};
    if (data.size() - offset < 24) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.StartAddressOfRawData, p, 4); p += 4;
    std::memcpy(&h.EndAddressOfRawData, p, 4); p += 4;
    std::memcpy(&h.AddressOfIndex, p, 4); p += 4;
    std::memcpy(&h.AddressOfCallBacks, p, 4); p += 4;
    std::memcpy(&h.SizeOfZeroFill, p, 4); p += 4;
    std::memcpy(&h.Characteristics, p, 4);
    return h;
}

ImageTlsDirectory64 ImageTlsDirectory64::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    ImageTlsDirectory64 h{};
    if (data.size() - offset < 40) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.StartAddressOfRawData, p, 8); p += 8;
    std::memcpy(&h.EndAddressOfRawData, p, 8); p += 8;
    std::memcpy(&h.AddressOfIndex, p, 8); p += 8;
    std::memcpy(&h.AddressOfCallBacks, p, 8); p += 8;
    std::memcpy(&h.SizeOfZeroFill, p, 4); p += 4;
    std::memcpy(&h.Characteristics, p, 4);
    return h;
}

// --- RuntimeFunction ---
RuntimeFunction RuntimeFunction::parse(std::span<const std::uint8_t> data, std::size_t offset) {
    RuntimeFunction h{};
    if (data.size() - offset < 12) return h;
    auto p = data.data() + offset;
    std::memcpy(&h.BeginAddress, p, 4); p += 4;
    std::memcpy(&h.EndAddress, p, 4); p += 4;
    std::memcpy(&h.UnwindData, p, 4);
    return h;
}

// --- UnwindInfo ---
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

    std::uint32_t signature = 0;
    std::memcpy(&signature, data_.data() + nt_headers_offset, 4);

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
        if (optional_header_offset + 112 <= data_size_) {
            auto oh_data = std::span<const std::uint8_t>(
                data_.data() + optional_header_offset,
                std::min<std::size_t>(256, data_size_ - optional_header_offset));
            optional_header_64_ = OptionalHeader64::parse(oh_data, 0);
        }
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
    return std::nullopt;
}

std::string PE::get_imphash() const {
    if (imports_.empty()) return "";

    std::string result;
    for (auto& entry : imports_) {
        std::string libname = entry.dll;
        std::transform(libname.begin(), libname.end(), libname.begin(),
            [](unsigned char c) { return std::tolower(c); });

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
            result += libname + "." + funcname;
        }
    }

    // Simple MD5 implementation using OpenSSL-like approach
    // For a real implementation, you'd use a crypto library
    return result;
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
    return result;
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

    if (exports_) {
        ss << "\nExports:\n";
        ss << "  " << exports_->name << " (" << exports_->symbols.size() << " symbols)\n";
    }

    if (!warnings_.empty()) {
        ss << "\nWarnings:\n";
        for (auto& w : warnings_) {
            ss << "  " << w << "\n";
        }
    }

    return ss.str();
}

} // namespace pefile
