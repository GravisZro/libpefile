#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <span>
#include <string>
#include <vector>

#include "pefile.hpp"
#include "pe_constants.hpp"
#include "pe_containers.hpp"

using namespace pefile;
namespace fs = std::filesystem;

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::ostringstream _ss; \
            _ss << "  ASSERT_EQ failed: " #a " != " #b \
                << " at " << __FILE__ << ":" << __LINE__ \
                << "\n  got: " << (a) << " expected: " << (b); \
            throw std::runtime_error(_ss.str()); \
        } \
    } while(0)

#define ASSERT_TRUE(x) \
    do { \
        if (!(x)) { \
            std::ostringstream _ss; \
            _ss << "  ASSERT_TRUE failed: " #x \
                << " at " << __FILE__ << ":" << __LINE__; \
            throw std::runtime_error(_ss.str()); \
        } \
    } while(0)

static const char* resource_type_name(uint32_t id) {
    switch (static_cast<ResourceType>(id)) {
        case ResourceType::CURSOR:       return "CURSOR";
        case ResourceType::BITMAP:       return "BITMAP";
        case ResourceType::ICON:         return "ICON";
        case ResourceType::MENU:         return "MENU";
        case ResourceType::DIALOG:       return "DIALOG";
        case ResourceType::STRING:       return "STRING";
        case ResourceType::FONTDIR:      return "FONTDIR";
        case ResourceType::FONT:         return "FONT";
        case ResourceType::ACCELERATOR:  return "ACCELERATOR";
        case ResourceType::RCDATA:       return "RCDATA";
        case ResourceType::MESSAGETABLE: return "MESSAGETABLE";
        case ResourceType::GROUP_CURSOR: return "GROUP_CURSOR";
        case ResourceType::GROUP_ICON:   return "GROUP_ICON";
        case ResourceType::VERSION:      return "VERSION";
        case ResourceType::DLGINCLUDE:   return "DLGINCLUDE";
        case ResourceType::PLUGPLAY:     return "PLUGPLAY";
        case ResourceType::VXD:          return "VXD";
        case ResourceType::ANICURSOR:    return "ANICURSOR";
        case ResourceType::ANIICON:      return "ANIICON";
        case ResourceType::HTML:         return "HTML";
        case ResourceType::MANIFEST:     return "MANIFEST";
        default:                         return "UNKNOWN";
    }
}

struct ResourceInfo {
    std::string type_name;
    std::string id_or_name;
    uint32_t lang = 0;
    uint32_t sublang = 0;
    uint32_t data_rva = 0;
    uint32_t size = 0;
    std::vector<uint8_t> data;
};

static void collect_resources(const PE& pe, const ResourceDirData& dir, int depth,
                              std::vector<ResourceInfo>& out) {
    for (auto& entry : dir.entries) {
        if (entry.directory) {
            collect_resources(pe, *entry.directory, depth + 1, out);
        } else if (entry.data_entry) {
            ResourceInfo info;
            if (depth == 0) {
                info.type_name = resource_type_name(entry.id);
            } else {
                info.type_name = std::to_string(entry.id);
            }
            if (!entry.name.empty()) {
                info.id_or_name = "\"" + entry.name + "\"";
            } else {
                info.id_or_name = std::to_string(entry.id);
            }
            info.lang = entry.data_entry->lang;
            info.sublang = entry.data_entry->sublang;
            info.data_rva = entry.data_entry->data_rva;
            info.size = entry.data_entry->size;
            if (info.size > 0 && info.data_rva > 0) {
                auto span = pe.get_data(info.data_rva, info.size);
                info.data.assign(span.begin(), span.end());
            }
            out.push_back(std::move(info));
        }
    }
}

static std::string format_resource_path(const ResourceInfo& r) {
    return r.type_name + "/" + r.id_or_name + " (lang=" + std::to_string(r.lang)
         + " sublang=" + std::to_string(r.sublang) + ")";
}

// ============================================================================
// Test: Parse PEview.exe and export all resources
// ============================================================================
static void test_peview_resource_export() {
    fs::path pe_path = fs::path(PEFILE_TESTDATA_DIR) / "PEview.exe";
    ASSERT_TRUE(fs::exists(pe_path));

    PE pe(pe_path.string());
    auto& resources = pe.resources();
    ASSERT_TRUE(!resources.empty());

    std::cout << "  Resources in PEview.exe:\n";
    std::vector<ResourceInfo> all;
    for (auto& res_dir : resources) {
        collect_resources(pe, res_dir, 0, all);
    }

    ASSERT_TRUE(!all.empty());

    for (auto& r : all) {
        std::cout << "    " << format_resource_path(r)
                  << " rva=0x" << std::hex << r.data_rva << std::dec
                  << " size=" << r.size;
        if (!r.data.empty()) {
            std::cout << " data_loaded=" << r.data.size() << " bytes";
        }
        std::cout << "\n";
    }

    uint32_t total_loaded = 0;
    for (auto& r : all) {
        total_loaded += static_cast<uint32_t>(r.data.size());
    }
    std::cout << "  Total resources: " << all.size()
              << ", total data loaded: " << total_loaded << " bytes\n";
}

// ============================================================================
// Test: Export resources to /tmp/peview_resources/ directory
// ============================================================================
static void test_peview_resource_export_to_files() {
    fs::path pe_path = fs::path(PEFILE_TESTDATA_DIR) / "PEview.exe";
    ASSERT_TRUE(fs::exists(pe_path));

    PE pe(pe_path.string());
    auto& resources = pe.resources();
    ASSERT_TRUE(!resources.empty());

    fs::path out_dir = "/tmp/peview_resources";
    fs::create_directories(out_dir);

    std::vector<ResourceInfo> all;
    for (auto& res_dir : resources) {
        collect_resources(pe, res_dir, 0, all);
    }

    ASSERT_TRUE(!all.empty());

    int exported = 0;
    for (size_t i = 0; i < all.size(); i++) {
        auto& r = all[i];
        if (r.data.empty()) continue;

        std::string filename = r.type_name + "_" + r.id_or_name + "_"
            + std::to_string(r.lang) + "_" + std::to_string(r.sublang) + ".bin";
        std::replace(filename.begin(), filename.end(), '"', '_');
        std::replace(filename.begin(), filename.end(), '/', '_');

        fs::path out_path = out_dir / filename;
        std::ofstream ofs(out_path, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(r.data.data()), r.data.size());
        ofs.close();

        ASSERT_TRUE(fs::exists(out_path));
        ASSERT_TRUE(fs::file_size(out_path) == r.size);
        exported++;
    }

    std::cout << "  Exported " << exported << " resources to " << out_dir << "\n";
    ASSERT_TRUE(exported > 0);
}

// ============================================================================
// Test: Resource data integrity - re-read and verify consistency
// ============================================================================
static void test_resource_data_integrity() {
    fs::path pe_path = fs::path(PEFILE_TESTDATA_DIR) / "PEview.exe";
    ASSERT_TRUE(fs::exists(pe_path));

    PE pe(pe_path.string());
    auto& resources = pe.resources();
    ASSERT_TRUE(!resources.empty());

    std::vector<ResourceInfo> all;
    for (auto& res_dir : resources) {
        collect_resources(pe, res_dir, 0, all);
    }

    for (auto& r : all) {
        if (r.data.empty()) continue;

        auto span = pe.get_data(r.data_rva, r.size);
        ASSERT_EQ(static_cast<uint32_t>(span.size()), r.size);
        ASSERT_TRUE(std::memcmp(span.data(), r.data.data(), r.size) == 0);
    }

    std::cout << "  Verified data integrity for " << all.size() << " resources\n";
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "Running resource export tests...\n\n";

    auto run = [](const char* name, std::function<void()> fn) {
        tests_run++;
        try {
            fn();
            tests_passed++;
            std::cout << "  PASS: " << name << "\n";
        } catch (const std::exception& e) {
            tests_failed++;
            std::cout << "  FAIL: " << name << "\n  " << e.what() << "\n";
        }
    };

    run("PEview resource export", test_peview_resource_export);
    run("PEview resource export to files", test_peview_resource_export_to_files);
    run("Resource data integrity", test_resource_data_integrity);

    std::cout << "\n========================================\n";
    std::cout << "Tests run: " << tests_run << "\n";
    std::cout << "Passed:    " << tests_passed << "\n";
    std::cout << "Failed:    " << tests_failed << "\n";
    std::cout << "========================================\n";

    return tests_failed > 0 ? 1 : 0;
}
