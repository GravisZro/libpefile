#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

namespace pefile {

class PEFormatError : public std::runtime_error {
public:
    explicit PEFormatError(const std::string& value)
        : std::runtime_error(value), value_(value) {}
    const std::string& value() const { return value_; }
private:
    std::string value_;
};

struct DosHeader {
    std::uint16_t e_magic = 0;
    std::uint16_t e_cblp = 0;
    std::uint16_t e_cp = 0;
    std::uint16_t e_crlc = 0;
    std::uint16_t e_cparhdr = 0;
    std::uint16_t e_minalloc = 0;
    std::uint16_t e_maxalloc = 0;
    std::uint16_t e_ss = 0;
    std::uint16_t e_sp = 0;
    std::uint16_t e_csum = 0;
    std::uint16_t e_ip = 0;
    std::uint16_t e_cs = 0;
    std::uint16_t e_lfarlc = 0;
    std::uint16_t e_ovno = 0;
    std::uint16_t e_res[4] = {};
    std::uint16_t e_oemid = 0;
    std::uint16_t e_oeminfo = 0;
    std::uint16_t e_res2[10] = {};
    std::int32_t  e_lfanew = 0;

    static DosHeader parse(std::span<const std::uint8_t> data, std::size_t offset = 0);
    std::vector<std::uint8_t> pack() const;
};

struct FileHeader {
    std::uint16_t Machine = 0;
    std::uint16_t NumberOfSections = 0;
    std::uint32_t TimeDateStamp = 0;
    std::uint32_t PointerToSymbolTable = 0;
    std::uint32_t NumberOfSymbols = 0;
    std::uint16_t SizeOfOptionalHeader = 0;
    std::uint16_t Characteristics = 0;

    static FileHeader parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct DataDirectory {
    std::uint32_t VirtualAddress = 0;
    std::uint32_t Size = 0;
    std::string name;

    static DataDirectory parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct OptionalHeader32 {
    std::uint16_t Magic = 0;
    std::uint8_t  MajorLinkerVersion = 0;
    std::uint8_t  MinorLinkerVersion = 0;
    std::uint32_t SizeOfCode = 0;
    std::uint32_t SizeOfInitializedData = 0;
    std::uint32_t SizeOfUninitializedData = 0;
    std::uint32_t AddressOfEntryPoint = 0;
    std::uint32_t BaseOfCode = 0;
    std::uint32_t BaseOfData = 0;
    std::uint32_t ImageBase = 0;
    std::uint32_t SectionAlignment = 0;
    std::uint32_t FileAlignment = 0;
    std::uint16_t MajorOperatingSystemVersion = 0;
    std::uint16_t MinorOperatingSystemVersion = 0;
    std::uint16_t MajorImageVersion = 0;
    std::uint16_t MinorImageVersion = 0;
    std::uint16_t MajorSubsystemVersion = 0;
    std::uint16_t MinorSubsystemVersion = 0;
    std::uint32_t Win32VersionValue = 0;
    std::uint32_t SizeOfImage = 0;
    std::uint32_t SizeOfHeaders = 0;
    std::uint32_t CheckSum = 0;
    std::uint16_t Subsystem = 0;
    std::uint16_t DllCharacteristics = 0;
    std::uint32_t SizeOfStackReserve = 0;
    std::uint32_t SizeOfStackCommit = 0;
    std::uint32_t SizeOfHeapReserve = 0;
    std::uint32_t SizeOfHeapCommit = 0;
    std::uint32_t LoaderFlags = 0;
    std::uint32_t NumberOfRvaAndSizes = 0;

    static OptionalHeader32 parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct OptionalHeader64 {
    std::uint16_t Magic = 0;
    std::uint8_t  MajorLinkerVersion = 0;
    std::uint8_t  MinorLinkerVersion = 0;
    std::uint32_t SizeOfCode = 0;
    std::uint32_t SizeOfInitializedData = 0;
    std::uint32_t SizeOfUninitializedData = 0;
    std::uint32_t AddressOfEntryPoint = 0;
    std::uint32_t BaseOfCode = 0;
    std::uint64_t ImageBase = 0;
    std::uint32_t SectionAlignment = 0;
    std::uint32_t FileAlignment = 0;
    std::uint16_t MajorOperatingSystemVersion = 0;
    std::uint16_t MinorOperatingSystemVersion = 0;
    std::uint16_t MajorImageVersion = 0;
    std::uint16_t MinorImageVersion = 0;
    std::uint16_t MajorSubsystemVersion = 0;
    std::uint16_t MinorSubsystemVersion = 0;
    std::uint32_t Win32VersionValue = 0;
    std::uint32_t SizeOfImage = 0;
    std::uint32_t SizeOfHeaders = 0;
    std::uint32_t CheckSum = 0;
    std::uint16_t Subsystem = 0;
    std::uint16_t DllCharacteristics = 0;
    std::uint64_t SizeOfStackReserve = 0;
    std::uint64_t SizeOfStackCommit = 0;
    std::uint64_t SizeOfHeapReserve = 0;
    std::uint64_t SizeOfHeapCommit = 0;
    std::uint32_t LoaderFlags = 0;
    std::uint32_t NumberOfRvaAndSizes = 0;

    static OptionalHeader64 parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct SectionHeader {
    char Name[8] = {};
    std::uint32_t Misc = 0;
    std::uint32_t VirtualSize = 0;
    std::uint32_t VirtualAddress = 0;
    std::uint32_t SizeOfRawData = 0;
    std::uint32_t PointerToRawData = 0;
    std::uint32_t PointerToRelocations = 0;
    std::uint32_t PointerToLinenumbers = 0;
    std::uint16_t NumberOfRelocations = 0;
    std::uint16_t NumberOfLinenumbers = 0;
    std::uint32_t Characteristics = 0;

    std::string name() const {
        return std::string(Name, strnlen(Name, 8));
    }

    static SectionHeader parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct ImageImportDescriptor {
    std::uint32_t OriginalFirstThunk = 0;
    std::uint32_t TimeDateStamp = 0;
    std::uint32_t ForwarderChain = 0;
    std::uint32_t Name = 0;
    std::uint32_t FirstThunk = 0;

    static ImageImportDescriptor parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct ImageExportDirectory {
    std::uint32_t Characteristics = 0;
    std::uint32_t TimeDateStamp = 0;
    std::uint16_t MajorVersion = 0;
    std::uint16_t MinorVersion = 0;
    std::uint32_t Name = 0;
    std::uint32_t Base = 0;
    std::uint32_t NumberOfFunctions = 0;
    std::uint32_t NumberOfNames = 0;
    std::uint32_t AddressOfFunctions = 0;
    std::uint32_t AddressOfNames = 0;
    std::uint32_t AddressOfNameOrdinals = 0;

    static ImageExportDirectory parse(std::span<const std::uint8_t> data, std::size_t offset);
    std::vector<std::uint8_t> pack() const;
};

struct ImageResourceDirectory {
    std::uint32_t Characteristics = 0;
    std::uint32_t TimeDateStamp = 0;
    std::uint16_t MajorVersion = 0;
    std::uint16_t MinorVersion = 0;
    std::uint32_t NumberOfNamedEntries = 0;
    std::uint32_t NumberOfIdEntries = 0;

    static ImageResourceDirectory parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageResourceDirectoryEntry {
    std::uint32_t Name = 0;
    std::uint32_t OffsetToData = 0;
    bool is_name() const { return (Name & 0x80000000) != 0; }
    bool is_directory() const { return (OffsetToData & 0x80000000) != 0; }
    std::uint32_t name_id() const { return Name & 0x7FFFFFFF; }
    std::uint32_t offset() const { return OffsetToData & 0x7FFFFFFF; }

    static ImageResourceDirectoryEntry parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageResourceDataEntry {
    std::uint32_t OffsetToData = 0;
    std::uint32_t Size = 0;
    std::uint32_t CodePage = 0;
    std::uint32_t Reserved = 0;

    static ImageResourceDataEntry parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageThunkData32 {
    union {
        std::uint32_t ForwarderString = 0;
        std::uint32_t Function;
        std::uint32_t Ordinal;
        std::uint32_t AddressOfData;
    };
    static ImageThunkData32 parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageThunkData64 {
    union {
        std::uint64_t ForwarderString = 0;
        std::uint64_t Function;
        std::uint64_t Ordinal;
        std::uint64_t AddressOfData;
    };
    static ImageThunkData64 parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageDebugDirectory {
    std::uint32_t Characteristics = 0;
    std::uint32_t TimeDateStamp = 0;
    std::uint16_t MajorVersion = 0;
    std::uint16_t MinorVersion = 0;
    std::uint32_t Type = 0;
    std::uint32_t SizeOfData = 0;
    std::uint32_t AddressOfRawData = 0;
    std::uint32_t PointerToRawData = 0;

    static ImageDebugDirectory parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageBaseRelocation {
    std::uint32_t VirtualAddress = 0;
    std::uint32_t SizeOfBlock = 0;

    static ImageBaseRelocation parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageTlsDirectory32 {
    std::uint32_t StartAddressOfRawData = 0;
    std::uint32_t EndAddressOfRawData = 0;
    std::uint32_t AddressOfIndex = 0;
    std::uint32_t AddressOfCallBacks = 0;
    std::uint32_t SizeOfZeroFill = 0;
    std::uint32_t Characteristics = 0;

    static ImageTlsDirectory32 parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct ImageTlsDirectory64 {
    std::uint64_t StartAddressOfRawData = 0;
    std::uint64_t EndAddressOfRawData = 0;
    std::uint64_t AddressOfIndex = 0;
    std::uint64_t AddressOfCallBacks = 0;
    std::uint32_t SizeOfZeroFill = 0;
    std::uint32_t Characteristics = 0;

    static ImageTlsDirectory64 parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct RuntimeFunction {
    std::uint32_t BeginAddress = 0;
    std::uint32_t EndAddress = 0;
    std::uint32_t UnwindData = 0;

    static RuntimeFunction parse(std::span<const std::uint8_t> data, std::size_t offset);
};

struct UnwindInfo {
    std::uint8_t Version = 0;
    std::uint8_t Flags = 0;
    std::uint8_t SizeOfProlog = 0;
    std::uint8_t CountOfCodes = 0;
    std::uint8_t FrameRegister = 0;
    std::uint8_t FrameOffset = 0;
    std::vector<std::uint16_t> UnwindCodes;

    bool chained() const { return (Flags & 0x04) != 0; }

    static UnwindInfo parse(std::span<const std::uint8_t> data, std::size_t offset);
};

} // namespace pefile
