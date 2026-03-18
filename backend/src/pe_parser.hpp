#pragma once
#include "utils.hpp"
#include <memory>

namespace OffsetDumper {

class PEParser {
public:
    // Load a PE file from disk
    bool load(const std::string& filepath);
    
    // Check if it's a valid PE64
    bool is_valid() const;
    bool is_64bit() const;
    
    // Get image base from optional header
    uintptr_t get_image_base() const;
    
    // Get all sections
    std::vector<SectionInfo> get_sections() const;
    
    // Get a specific section by name
    std::optional<SectionInfo> get_section(const std::string& name) const;
    
    // Read raw bytes from a section (file-based)
    std::vector<uint8_t> read_section_data(const SectionInfo& section) const;
    
    // Read raw bytes at a given file offset
    std::vector<uint8_t> read_bytes(uintptr_t file_offset, size_t size) const;
    
    // Convert RVA to file offset
    std::optional<uintptr_t> rva_to_file_offset(uintptr_t rva) const;
    
    // Get entry point RVA
    uintptr_t get_entry_point() const;
    
    const std::string& get_filepath() const { return filepath_; }

private:
    std::string filepath_;
    std::vector<uint8_t> file_data_;
    bool valid_ = false;
    bool is_64bit_ = false;
    
    IMAGE_DOS_HEADER dos_header_{};
    IMAGE_NT_HEADERS64 nt_headers_{};
    std::vector<IMAGE_SECTION_HEADER> section_headers_;
    
    bool parse_headers();
};

} // namespace OffsetDumper
