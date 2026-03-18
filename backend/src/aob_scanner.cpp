#include "aob_scanner.hpp"
#include <cctype>
#include <cstring>
#include <stdexcept>

namespace OffsetDumper {

// ---------------------------------------------------------------------------
// parse_pattern
// ---------------------------------------------------------------------------
// Accepts IDA-style patterns:  "48 8B 05 ? ? ? ? 48 89"
//                               "48 8B 05 ?? ?? ?? ?? 48 89"
//                               "48 8B 05 * * * * 48 89"
// Tokens are separated by whitespace.  A token that is '?', '??', or '*'
// is treated as a wildcard; anything else is parsed as a two-character hex
// byte (case-insensitive).
// ---------------------------------------------------------------------------
std::vector<PatternByte> AOBScanner::parse_pattern(const std::string& pattern) {
    std::vector<PatternByte> result;

    if (pattern.empty()) {
        return result;
    }

    // Tokenise by spaces / tabs
    std::istringstream stream(pattern);
    std::string token;

    while (stream >> token) {
        if (token == "?" || token == "??" || token == "*") {
            result.push_back({ 0, true });
            continue;
        }

        // Must be exactly 2 hex characters
        if (token.size() != 2 ||
            !std::isxdigit(static_cast<unsigned char>(token[0])) ||
            !std::isxdigit(static_cast<unsigned char>(token[1]))) {
            throw std::invalid_argument(
                "Invalid pattern token: \"" + token + "\" -- expected a 2-char hex byte, ?, ?" "?, or *");
        }

        auto byte = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
        result.push_back({ byte, false });
    }

    return result;
}

// ---------------------------------------------------------------------------
// scan_buffer  (parsed pattern)
// ---------------------------------------------------------------------------
std::vector<size_t> AOBScanner::scan_buffer(
    const uint8_t* data,
    size_t data_size,
    const std::vector<PatternByte>& pattern)
{
    std::vector<size_t> matches;

    if (!data || pattern.empty() || data_size == 0) {
        return matches;
    }

    const size_t pat_len = pattern.size();

    // Pattern longer than data — no possible match
    if (pat_len > data_size) {
        return matches;
    }

    // All-wildcard pattern would match every position — warn and return empty
    bool all_wildcards = true;
    for (const auto& pb : pattern) {
        if (!pb.is_wildcard) { all_wildcards = false; break; }
    }
    if (all_wildcards) {
        std::cerr << "[AOBScanner] Warning: pattern consists entirely of wildcards — skipping scan\n";
        return matches;
    }

    const size_t scan_end = data_size - pat_len;

    // Pre-compute index of the first non-wildcard byte so we can use it for
    // a quick rejection test before entering the inner loop.
    size_t first_concrete = pat_len; // sentinel: means "all wildcards"
    for (size_t i = 0; i < pat_len; ++i) {
        if (!pattern[i].is_wildcard) {
            first_concrete = i;
            break;
        }
    }

    for (size_t i = 0; i <= scan_end; ++i) {
        // Quick reject on the first concrete byte (if any)
        if (first_concrete < pat_len && data[i + first_concrete] != pattern[first_concrete].value) {
            continue;
        }

        bool found = true;
        for (size_t j = 0; j < pat_len; ++j) {
            if (!pattern[j].is_wildcard && data[i + j] != pattern[j].value) {
                found = false;
                break;
            }
        }

        if (found) {
            matches.push_back(i);
        }
    }

    return matches;
}

// ---------------------------------------------------------------------------
// scan_buffer  (string convenience overload)
// ---------------------------------------------------------------------------
std::vector<size_t> AOBScanner::scan_buffer(
    const uint8_t* data,
    size_t data_size,
    const std::string& pattern)
{
    auto parsed = parse_pattern(pattern);
    return scan_buffer(data, data_size, parsed);
}

// ---------------------------------------------------------------------------
// extract_rip_relative
// ---------------------------------------------------------------------------
// x64 RIP-relative addressing:
//   The CPU resolves a RIP-relative operand as:
//       target = RIP_after_instruction + signed_32bit_displacement
//
//   When working with a raw buffer (file on disk / dumped image) the
//   "RIP after instruction" is simply  match_offset + instruction_length
//   (both relative to the buffer start, which corresponds to the module
//   base at runtime).
//
//   The displacement is a signed 32-bit integer located at
//       data + match_offset + operand_offset
//
//   So the result RVA is:
//       match_offset + instruction_length + displacement
// ---------------------------------------------------------------------------
std::optional<uintptr_t> AOBScanner::extract_rip_relative(
    const uint8_t* data,
    size_t data_size,
    size_t match_offset,
    size_t operand_offset,
    size_t instruction_length)
{
    if (!data || data_size == 0) {
        return std::nullopt;
    }

    const size_t disp_pos = match_offset + operand_offset;

    // Need 4 bytes for the displacement
    if (disp_pos + sizeof(int32_t) > data_size) {
        return std::nullopt;
    }

    // Read the signed 32-bit displacement (little-endian, which is native on x86/x64)
    int32_t displacement = 0;
    std::memcpy(&displacement, data + disp_pos, sizeof(int32_t));

    // Compute the target RVA
    // target = (match_offset + instruction_length) + displacement
    auto rip_after = static_cast<intptr_t>(match_offset + instruction_length);
    auto target    = rip_after + static_cast<intptr_t>(displacement);

    if (target < 0) {
        return std::nullopt; // would be before the module base
    }

    return static_cast<uintptr_t>(target);
}

} // namespace OffsetDumper
