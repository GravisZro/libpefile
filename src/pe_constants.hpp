#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <array>
#include <algorithm>

namespace pefile {

constexpr std::uint32_t MAX_STRING_LENGTH = 0x100000;
constexpr std::uint32_t MAX_IMPORT_SYMBOLS = 0x2000;
constexpr std::uint32_t MAX_DLL_LENGTH = 0x200;
constexpr std::uint32_t MAX_IMPORT_NAME_LENGTH = 0x200;
constexpr std::uint32_t MAX_SYMBOL_NAME_LENGTH = 0x200;
constexpr std::uint32_t MAX_SECTIONS = 0x800;
constexpr std::uint32_t MAX_RESOURCE_ENTRIES = 0x8000;
constexpr std::uint32_t MAX_RESOURCE_DEPTH = 32;
constexpr std::uint32_t MAX_SYMBOL_EXPORT_COUNT = 0x2000;
constexpr std::uint32_t MIN_VALID_FILE_ALIGNMENT = 0x200;
constexpr std::uint32_t SECTOR_SIZE = 0x200;
constexpr std::uint32_t VS_VERSION_INFO_MAGIC_LEN = 6;

constexpr std::uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr std::uint16_t IMAGE_DOSZM_SIGNATURE = 0x4D5A;
constexpr std::uint32_t IMAGE_NT_SIGNATURE = 0x00004550;
constexpr std::uint16_t IMAGE_NE_SIGNATURE = 0x454E;
constexpr std::uint16_t IMAGE_LE_SIGNATURE = 0x454C;
constexpr std::uint16_t IMAGE_LX_SIGNATURE = 0x584C;
constexpr std::uint16_t IMAGE_TE_SIGNATURE = 0x5A56;

constexpr std::uint32_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
constexpr std::uint64_t IMAGE_ORDINAL_FLAG = 0x80000000;
constexpr std::uint64_t IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;
constexpr std::uint16_t OPTIONAL_HEADER_MAGIC_PE = 0x10B;
constexpr std::uint16_t OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B;

constexpr int UWOP_PUSH_NONVOL = 0;
constexpr int UWOP_ALLOC_LARGE = 1;
constexpr int UWOP_ALLOC_SMALL = 2;
constexpr int UWOP_SET_FPREG = 3;
constexpr int UWOP_SAVE_NONVOL = 4;
constexpr int UWOP_SAVE_NONVOL_FAR = 5;
constexpr int UWOP_EPILOG = 6;
constexpr int UWOP_SAVE_XMM128 = 8;
constexpr int UWOP_SAVE_XMM128_FAR = 9;
constexpr int UWOP_PUSH_MACHFRAME = 10;

enum class DirectoryEntry : std::uint32_t {
    EXPORT = 0,
    IMPORT = 1,
    RESOURCE = 2,
    EXCEPTION = 3,
    SECURITY = 4,
    BASERELOC = 5,
    DEBUG = 6,
    COPYRIGHT = 7,
    GLOBALPTR = 8,
    TLS = 9,
    LOAD_CONFIG = 10,
    BOUND_IMPORT = 11,
    IAT = 12,
    DELAY_IMPORT = 13,
    COM_DESCRIPTOR = 14,
    RESERVED = 15,
};

inline std::string_view directory_entry_name(DirectoryEntry e) {
    static constexpr std::string_view names[] = {
        "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
        "IMAGE_DIRECTORY_ENTRY_SECURITY",
        "IMAGE_DIRECTORY_ENTRY_BASERELOC",
        "IMAGE_DIRECTORY_ENTRY_DEBUG",
        "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
        "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
        "IMAGE_DIRECTORY_ENTRY_TLS",
        "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
        "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_IAT",
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
        "IMAGE_DIRECTORY_ENTRY_RESERVED",
    };
    auto idx = static_cast<std::uint32_t>(e);
    return idx < 16 ? names[idx] : "UNKNOWN";
}

enum class ImageCharacteristic : std::uint16_t {
    RELOCS_STRIPPED = 0x0001,
    EXECUTABLE_IMAGE = 0x0002,
    LINE_NUMS_STRIPPED = 0x0004,
    LOCAL_SYMS_STRIPPED = 0x0008,
    AGGRESIVE_WS_TRIM = 0x0010,
    LARGE_ADDRESS_AWARE = 0x0020,
    _16BIT_MACHINE = 0x0040,
    BYTES_REVERSED_LO = 0x0080,
    _32BIT_MACHINE = 0x0100,
    DEBUG_STRIPPED = 0x0200,
    REMOVABLE_RUN_FROM_SWAP = 0x0400,
    NET_RUN_FROM_SWAP = 0x0800,
    SYSTEM = 0x1000,
    DLL = 0x2000,
    UP_SYSTEM_ONLY = 0x4000,
    BYTES_REVERSED_HI = 0x8000,
};

inline std::string_view image_characteristic_name(ImageCharacteristic c) {
    switch (c) {
        case ImageCharacteristic::RELOCS_STRIPPED: return "IMAGE_FILE_RELOCS_STRIPPED";
        case ImageCharacteristic::EXECUTABLE_IMAGE: return "IMAGE_FILE_EXECUTABLE_IMAGE";
        case ImageCharacteristic::LINE_NUMS_STRIPPED: return "IMAGE_FILE_LINE_NUMS_STRIPPED";
        case ImageCharacteristic::LOCAL_SYMS_STRIPPED: return "IMAGE_FILE_LOCAL_SYMS_STRIPPED";
        case ImageCharacteristic::AGGRESIVE_WS_TRIM: return "IMAGE_FILE_AGGRESIVE_WS_TRIM";
        case ImageCharacteristic::LARGE_ADDRESS_AWARE: return "IMAGE_FILE_LARGE_ADDRESS_AWARE";
        case ImageCharacteristic::_16BIT_MACHINE: return "IMAGE_FILE_16BIT_MACHINE";
        case ImageCharacteristic::BYTES_REVERSED_LO: return "IMAGE_FILE_BYTES_REVERSED_LO";
        case ImageCharacteristic::_32BIT_MACHINE: return "IMAGE_FILE_32BIT_MACHINE";
        case ImageCharacteristic::DEBUG_STRIPPED: return "IMAGE_FILE_DEBUG_STRIPPED";
        case ImageCharacteristic::REMOVABLE_RUN_FROM_SWAP: return "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP";
        case ImageCharacteristic::NET_RUN_FROM_SWAP: return "IMAGE_FILE_NET_RUN_FROM_SWAP";
        case ImageCharacteristic::SYSTEM: return "IMAGE_FILE_SYSTEM";
        case ImageCharacteristic::DLL: return "IMAGE_FILE_DLL";
        case ImageCharacteristic::UP_SYSTEM_ONLY: return "IMAGE_FILE_UP_SYSTEM_ONLY";
        case ImageCharacteristic::BYTES_REVERSED_HI: return "IMAGE_FILE_BYTES_REVERSED_HI";
        default: return "UNKNOWN";
    }
}

inline std::vector<std::pair<std::string, std::uint16_t>> retrieve_image_characteristics() {
    return {
        {"IMAGE_FILE_RELOCS_STRIPPED", 0x0001},
        {"IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002},
        {"IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004},
        {"IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008},
        {"IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010},
        {"IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020},
        {"IMAGE_FILE_16BIT_MACHINE", 0x0040},
        {"IMAGE_FILE_BYTES_REVERSED_LO", 0x0080},
        {"IMAGE_FILE_32BIT_MACHINE", 0x0100},
        {"IMAGE_FILE_DEBUG_STRIPPED", 0x0200},
        {"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400},
        {"IMAGE_FILE_NET_RUN_FROM_SWAP", 0x0800},
        {"IMAGE_FILE_SYSTEM", 0x1000},
        {"IMAGE_FILE_DLL", 0x2000},
        {"IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000},
        {"IMAGE_FILE_BYTES_REVERSED_HI", 0x8000},
    };
}

enum class SectionCharacteristic : std::uint32_t {
    CNT_CODE = 0x00000020,
    CNT_INITIALIZED_DATA = 0x00000040,
    CNT_UNINITIALIZED_DATA = 0x00000080,
    LNK_OTHER = 0x00000100,
    LNK_INFO = 0x00000200,
    LNK_REMOVE = 0x00000800,
    LNK_COMDAT = 0x00001000,
    NO_DEFER_SPEC_EXC = 0x00004000,
    GPREL = 0x00008000,
    ALIGN_1BYTES = 0x00100000,
    ALIGN_2BYTES = 0x00200000,
    ALIGN_4BYTES = 0x00300000,
    ALIGN_8BYTES = 0x00400000,
    ALIGN_16BYTES = 0x00500000,
    ALIGN_32BYTES = 0x00600000,
    ALIGN_64BYTES = 0x00700000,
    ALIGN_128BYTES = 0x00800000,
    ALIGN_256BYTES = 0x00900000,
    ALIGN_512BYTES = 0x00A00000,
    ALIGN_1024BYTES = 0x00B00000,
    ALIGN_2048BYTES = 0x00C00000,
    ALIGN_4096BYTES = 0x00D00000,
    ALIGN_8192BYTES = 0x00E00000,
    LNK_NRELOC_OVFL = 0x01000000,
    MEM_DISCARDABLE = 0x02000000,
    MEM_NOT_CACHED = 0x04000000,
    MEM_NOT_PAGED = 0x08000000,
    MEM_SHARED = 0x10000000,
    MEM_EXECUTE = 0x20000000,
    MEM_READ = 0x40000000,
    MEM_WRITE = 0x80000000,
};

enum class DebugType : std::uint32_t {
    UNKNOWN = 0,
    COFF = 1,
    CODEVIEW = 2,
    FPO = 3,
    MISC = 4,
    EXCEPTION = 5,
    FIXUP = 6,
    OMAP_TO_SRC = 7,
    OMAP_FROM_SRC = 8,
    BORLAND = 9,
    RESERVED10 = 10,
    CLSID = 11,
    VC_FEATURE = 12,
    POGO = 13,
    ILTCG = 14,
    MPX = 15,
    REPRO = 16,
    EX_DLLCHARACTERISTICS = 17,
};

enum class SubsystemType : std::uint16_t {
    UNKNOWN = 0,
    NATIVE = 1,
    WINDOWS_GUI = 2,
    WINDOWS_CUI = 3,
    OS2_CUI = 5,
    POSIX_CUI = 7,
    NATIVE_WINDOWS = 8,
    WINDOWS_CE_GUI = 9,
    EFI_APPLICATION = 10,
    EFI_BOOT_SERVICE_DRIVER = 11,
    EFI_RUNTIME_DRIVER = 12,
    EFI_ROM = 13,
    XBOX = 14,
    WINDOWS_BOOT_APPLICATION = 16,
};

enum class MachineType : std::uint16_t {
    UNKNOWN = 0x0,
    I386 = 0x014C,
    R3000 = 0x0162,
    R4000 = 0x0166,
    R10000 = 0x0168,
    WCEMIPSV2 = 0x0169,
    ALPHA = 0x0184,
    SH3 = 0x01A2,
    SH3DSP = 0x01A3,
    SH3E = 0x01A4,
    SH4 = 0x01A6,
    SH5 = 0x01A8,
    ARM = 0x01C0,
    THUMB = 0x01C2,
    ARMNT = 0x01C4,
    AM33 = 0x01D3,
    POWERPC = 0x01F0,
    POWERPCFP = 0x01F1,
    IA64 = 0x0200,
    MIPS16 = 0x0266,
    ALPHA64 = 0x0284,
    MIPSFPU = 0x0366,
    MIPSFPU16 = 0x0466,
    TRICORE = 0x0520,
    CEF = 0x0CEF,
    EBC = 0x0EBC,
    AMD64 = 0x8664,
    M32R = 0x9041,
    ARM64 = 0xAA64,
    CEE = 0xC0EE,
};

enum class RelocationType : std::uint32_t {
    HIGH = 0,
    LOW = 1,
    HIGHLOW = 2,
    HIGHADJ = 3,
    MIPS_JMPADDR = 4,
    SECTION = 5,
    REL32 = 6,
    HIGH1ADJ = 7,
    MIPS_JMPADDR16 = 8,
    DIR64 = 10,
};

enum class DllCharacteristic : std::uint16_t {
    HIGH_ENTROPY_VA = 0x0020,
    DYNAMIC_BASE = 0x0040,
    FORCE_INTEGRITY = 0x0080,
    NX_COMPAT = 0x0100,
    NO_ISOLATION = 0x0200,
    NO_SEH = 0x0400,
    NO_BIND = 0x0800,
    APPCONTAINER = 0x1000,
    WDM_DRIVER = 0x2000,
    GUARD_CF = 0x4000,
    TERMINAL_SERVER_AWARE = 0x8000,
};

enum class ResourceType : std::uint32_t {
    UNKNOWN = 0,
    CURSOR = 1,
    BITMAP = 2,
    ICON = 3,
    MENU = 4,
    DIALOG = 5,
    STRING = 6,
    FONTDIR = 7,
    FONT = 8,
    ACCELERATOR = 9,
    RCDATA = 10,
    MESSAGETABLE = 11,
    GROUP_CURSOR = 12,
    GROUP_ICON = 14,
    VERSION = 16,
    DLGINCLUDE = 17,
    PLUGPLAY = 19,
    VXD = 20,
    ANICURSOR = 21,
    ANIICON = 22,
    HTML = 23,
    MANIFEST = 24,
};

enum class ExDllCharacteristic : std::uint16_t {
    CONTROLFLOW_GUARD = 0x0040,
    FUNCTION_CALL_STRICT_CFG = 0x0100,
    FUNCTION_CALL_SUPPRESS_IBT = 0x0200,
    FUNCTION_CALL_SUPPRESS_CET_SHADOW_STACK = 0x0400,
    FUNCTION_CALL_SUPPRESS_CFG_EXPORT_SUPPRESSION = 0x0800,
};

inline std::uint32_t adjust_section_alignment(std::uint32_t val, std::uint32_t section_alignment, std::uint32_t file_alignment) {
    if (section_alignment < 0x1000) {
        section_alignment = file_alignment;
    }
    if (section_alignment != 0 && val % section_alignment != 0) {
        return (val / section_alignment) * section_alignment;
    }
    return val;
}

inline bool power_of_two(std::uint32_t val) {
    return val != 0 && (val & (val - 1)) == 0;
}

inline std::uint32_t count_zeroes(std::span<const std::uint8_t> data) {
    return static_cast<std::uint32_t>(std::count(data.begin(), data.end(), 0));
}

constexpr std::string_view allowed_filename =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./\\?%*\":<>|";

constexpr std::string_view allowed_function_name =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_?@";

inline bool is_valid_dos_filename(std::string_view s) {
    if (s.empty() || s.size() > 8) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return allowed_filename.find(c) != std::string_view::npos;
    });
}

inline bool is_valid_function_name(std::string_view s, bool /*relax_allowed_characters*/ = false) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return allowed_function_name.find(c) != std::string_view::npos;
    });
}

inline std::uint32_t dword_align(std::uint32_t offset, std::uint32_t base) {
    return ((offset + base + 3) & 0xFFFFFFFC) - (base & 0xFFFFFFFC);
}

inline std::string human_readable_size(std::uint64_t value) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double val = static_cast<double>(value);
    int unit = 0;
    while (val >= 1024.0 && unit < 4) {
        val /= 1024.0;
        unit++;
    }
    char buf[64];
    if (unit == 0) {
        std::snprintf(buf, sizeof(buf), "%llu %s", static_cast<unsigned long long>(value), units[unit]);
    } else {
        std::snprintf(buf, sizeof(buf), "%.1f %s", val, units[unit]);
    }
    return buf;
}

} // namespace pefile
