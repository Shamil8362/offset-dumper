#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace OffsetDumper {

// Format a uintptr_t as hex string like "0x1A2B3C"
std::string to_hex(uintptr_t value);

// Format bytes as hex string "48 8B 05 ..."
std::string bytes_to_hex(const uint8_t* data, size_t len);

// Convert a wide string to UTF-8 narrow string
std::string wide_to_narrow(const std::wstring& wide);

// Convert narrow string to wide string  
std::wstring narrow_to_wide(const std::string& narrow);

// Get human-readable error message from GetLastError()
std::string get_last_error_string();

// Print error message with context
void print_error(const std::string& context);

// Represents a memory region
struct MemoryRegion {
    uintptr_t base;
    size_t size;
    DWORD protection;
    DWORD state;
    DWORD type;
};

// Represents a PE section
struct SectionInfo {
    std::string name;
    uintptr_t virtual_address; // RVA
    size_t virtual_size;
    uintptr_t raw_offset;      // file offset
    size_t raw_size;
    DWORD characteristics;
};

// Represents a scan result
struct ScanResult {
    uintptr_t offset;          // relative to module base
    std::string section_name;  // which section it was found in
    std::string context;       // optional context info
};

// Represents a pointer chain result
struct PointerChainResult {
    std::string module_name;
    uintptr_t base_offset;
    std::vector<uintptr_t> offsets;
    uintptr_t final_address;
    bool valid;
};

// Represents a named offset for output
struct NamedOffset {
    std::string name;
    uintptr_t offset;
    std::string comment;
};

} // namespace OffsetDumper
