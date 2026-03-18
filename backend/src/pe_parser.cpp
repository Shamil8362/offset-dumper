#include "pe_parser.hpp"
#include <cstdio>
#include <cstring>

namespace OffsetDumper {

bool PEParser::load(const std::string& filepath) {
    filepath_ = filepath;
    valid_ = false;
    is_64bit_ = false;
    file_data_.clear();
    section_headers_.clear();
    dos_header_ = {};
    nt_headers_ = {};

    // Open the file in binary mode (C-style I/O for MinGW Release compatibility)
    FILE* fp = std::fopen(filepath.c_str(), "rb");
    if (!fp) {
        print_error("Failed to open file: " + filepath);
        return false;
    }

    // Get file size
    if (std::fseek(fp, 0, SEEK_END) != 0) {
        std::cerr << "[ERROR] Failed to seek in file: " << filepath << std::endl;
        std::fclose(fp);
        return false;
    }
    long file_size_long = std::ftell(fp);
    if (file_size_long <= 0) {
        std::cerr << "[ERROR] File is empty or unreadable: " << filepath << std::endl;
        std::fclose(fp);
        return false;
    }
    auto file_size = static_cast<size_t>(file_size_long);

    // Read entire file into memory
    file_data_.resize(file_size);
    std::rewind(fp);
    size_t bytes_read = std::fread(file_data_.data(), 1, file_size, fp);
    std::fclose(fp);
    if (bytes_read != file_size) {
        std::cerr << "[ERROR] Failed to read file contents: " << filepath << std::endl;
        file_data_.clear();
        return false;
    }

    // Parse PE headers
    if (!parse_headers()) {
        file_data_.clear();
        section_headers_.clear();
        return false;
    }

    valid_ = true;
    return true;
}

bool PEParser::parse_headers() {
    // Validate minimum size for DOS header
    if (file_data_.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "[ERROR] File too small for DOS header" << std::endl;
        return false;
    }

    // Parse DOS header
    std::memcpy(&dos_header_, file_data_.data(), sizeof(IMAGE_DOS_HEADER));

    // Validate DOS signature ("MZ")
    if (dos_header_.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[ERROR] Invalid DOS signature (expected MZ)" << std::endl;
        return false;
    }

    // Validate e_lfanew points within the file
    auto nt_offset = static_cast<size_t>(dos_header_.e_lfanew);
    if (nt_offset == 0 || nt_offset + sizeof(IMAGE_NT_HEADERS64) > file_data_.size()) {
        std::cerr << "[ERROR] Invalid or out-of-bounds e_lfanew offset" << std::endl;
        return false;
    }

    // Parse NT headers (read as 64-bit; we'll verify the magic below)
    std::memcpy(&nt_headers_, file_data_.data() + nt_offset, sizeof(IMAGE_NT_HEADERS64));

    // Validate NT signature ("PE\0\0")
    if (nt_headers_.Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[ERROR] Invalid NT signature (expected PE\\0\\0)" << std::endl;
        return false;
    }

    // Check if this is a 64-bit PE
    if (nt_headers_.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is_64bit_ = true;
    } else if (nt_headers_.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is_64bit_ = false;
        std::cerr << "[ERROR] PE file is 32-bit; only PE64 is supported" << std::endl;
        return false;
    } else {
        std::cerr << "[ERROR] Unknown optional header magic: " << to_hex(nt_headers_.OptionalHeader.Magic) << std::endl;
        return false;
    }

    // Validate machine type for x64
    if (nt_headers_.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "[ERROR] Unsupported machine type: " << to_hex(nt_headers_.FileHeader.Machine)
                  << " (expected AMD64)" << std::endl;
        return false;
    }

    // Parse section headers
    auto num_sections = nt_headers_.FileHeader.NumberOfSections;
    if (num_sections == 0) {
        std::cerr << "[ERROR] PE file has no sections" << std::endl;
        return false;
    }

    // Section headers start immediately after the optional header
    size_t section_headers_offset = nt_offset
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt_headers_.FileHeader.SizeOfOptionalHeader;

    size_t section_headers_size = static_cast<size_t>(num_sections) * sizeof(IMAGE_SECTION_HEADER);

    if (section_headers_offset + section_headers_size > file_data_.size()) {
        std::cerr << "[ERROR] Section headers extend beyond end of file" << std::endl;
        return false;
    }

    section_headers_.resize(num_sections);
    std::memcpy(
        section_headers_.data(),
        file_data_.data() + section_headers_offset,
        section_headers_size
    );

    return true;
}

bool PEParser::is_valid() const {
    return valid_;
}

bool PEParser::is_64bit() const {
    return is_64bit_;
}

uintptr_t PEParser::get_image_base() const {
    if (!valid_) return 0;
    return static_cast<uintptr_t>(nt_headers_.OptionalHeader.ImageBase);
}

uintptr_t PEParser::get_entry_point() const {
    if (!valid_) return 0;
    return static_cast<uintptr_t>(nt_headers_.OptionalHeader.AddressOfEntryPoint);
}

std::vector<SectionInfo> PEParser::get_sections() const {
    std::vector<SectionInfo> sections;
    if (!valid_) return sections;

    sections.reserve(section_headers_.size());
    for (const auto& hdr : section_headers_) {
        SectionInfo info;
        // Section name is up to 8 bytes, not necessarily null-terminated
        info.name = std::string(
            reinterpret_cast<const char*>(hdr.Name),
            strnlen(reinterpret_cast<const char*>(hdr.Name), IMAGE_SIZEOF_SHORT_NAME)
        );
        info.virtual_address = static_cast<uintptr_t>(hdr.VirtualAddress);
        info.virtual_size = static_cast<size_t>(hdr.Misc.VirtualSize);
        info.raw_offset = static_cast<uintptr_t>(hdr.PointerToRawData);
        info.raw_size = static_cast<size_t>(hdr.SizeOfRawData);
        info.characteristics = hdr.Characteristics;
        sections.push_back(std::move(info));
    }

    return sections;
}

std::optional<SectionInfo> PEParser::get_section(const std::string& name) const {
    auto sections = get_sections();
    for (const auto& section : sections) {
        if (section.name == name) {
            return section;
        }
    }
    return std::nullopt;
}

std::vector<uint8_t> PEParser::read_section_data(const SectionInfo& section) const {
    if (!valid_) return {};

    // Use raw_size for reading from file, but cap to file bounds
    size_t offset = static_cast<size_t>(section.raw_offset);
    size_t size = section.raw_size;

    if (offset >= file_data_.size()) {
        std::cerr << "[ERROR] Section '" << section.name << "' raw offset is beyond end of file" << std::endl;
        return {};
    }

    // Clamp size to not exceed file bounds
    if (offset + size > file_data_.size()) {
        size = file_data_.size() - offset;
    }

    return std::vector<uint8_t>(
        file_data_.begin() + offset,
        file_data_.begin() + offset + size
    );
}

std::vector<uint8_t> PEParser::read_bytes(uintptr_t file_offset, size_t size) const {
    if (!valid_) return {};

    auto offset = static_cast<size_t>(file_offset);
    if (offset >= file_data_.size()) {
        return {};
    }

    // Clamp size to file bounds
    if (offset + size > file_data_.size()) {
        size = file_data_.size() - offset;
    }

    return std::vector<uint8_t>(
        file_data_.begin() + offset,
        file_data_.begin() + offset + size
    );
}

std::optional<uintptr_t> PEParser::rva_to_file_offset(uintptr_t rva) const {
    if (!valid_) return std::nullopt;

    // Check if RVA falls within any section
    for (const auto& hdr : section_headers_) {
        auto section_rva = static_cast<uintptr_t>(hdr.VirtualAddress);
        auto section_vsize = static_cast<size_t>(hdr.Misc.VirtualSize);
        auto section_raw = static_cast<uintptr_t>(hdr.PointerToRawData);
        auto section_raw_size = static_cast<size_t>(hdr.SizeOfRawData);

        if (rva >= section_rva && rva < section_rva + section_vsize) {
            uintptr_t offset_within_section = rva - section_rva;

            // Make sure the offset is within the raw data on disk
            if (offset_within_section < section_raw_size) {
                return section_raw + offset_within_section;
            }

            // RVA is in virtual range but beyond raw data (e.g., BSS)
            return std::nullopt;
        }
    }

    // RVA might be in the headers (before first section)
    if (rva < nt_headers_.OptionalHeader.SizeOfHeaders) {
        return rva; // Headers are mapped 1:1
    }

    return std::nullopt;
}

} // namespace OffsetDumper
