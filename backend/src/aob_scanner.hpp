#pragma once
#include "utils.hpp"
#include <functional>

namespace OffsetDumper {

// Parsed pattern element: either a concrete byte or a wildcard
struct PatternByte {
    uint8_t value;
    bool is_wildcard;
};

class AOBScanner {
public:
    // Parse an IDA-style pattern string like "48 8B ? ? ? ? 48 89" or "48 8B ?? ?? ?? ?? 48 89"
    // Also supports "48 8B * * * * 48 89"
    static std::vector<PatternByte> parse_pattern(const std::string& pattern);

    // Scan a byte buffer for all occurrences of a pattern
    // Returns offsets relative to the start of the buffer
    static std::vector<size_t> scan_buffer(
        const uint8_t* data,
        size_t data_size,
        const std::vector<PatternByte>& pattern
    );

    // Scan with a string pattern (convenience)
    static std::vector<size_t> scan_buffer(
        const uint8_t* data,
        size_t data_size,
        const std::string& pattern
    );

    // Extract a RIP-relative offset from a matched location
    // Given the match position, reads the 4-byte displacement at match_offset + operand_offset
    // and calculates the absolute RVA: match_rva + instruction_length + displacement
    static std::optional<uintptr_t> extract_rip_relative(
        const uint8_t* data,
        size_t data_size,
        size_t match_offset,
        size_t operand_offset,    // offset within the matched pattern where the 4-byte disp starts
        size_t instruction_length // total length of the instruction
    );
};

} // namespace OffsetDumper
