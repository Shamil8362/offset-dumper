#pragma once
#include "utils.hpp"
#include "process.hpp"

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace OffsetDumper {

class PointerScanner {
public:
    explicit PointerScanner(const Process& process);

    // Resolve a pointer chain: base_address + offsets[0] -> deref -> +offsets[1] -> deref -> ...
    // For N offsets, the first N-1 are dereferenced and the last is added as a field offset.
    // Example: base -> 0x10 -> 0x5C means read qword at (base+0x10) = addr1, final = addr1 + 0x5C
    PointerChainResult resolve_chain(
        uintptr_t base_address,
        const std::vector<uintptr_t>& offsets
    ) const;

    // Resolve a chain starting from module_base + base_offset.
    // Looks up the module by name via the process, then delegates to resolve_chain.
    PointerChainResult resolve_chain_from_module(
        const std::string& module_name,
        uintptr_t base_offset,
        const std::vector<uintptr_t>& offsets
    ) const;

    // Read the final value at the end of a pointer chain as a specific type.
    template<typename T>
    std::optional<T> read_chain(
        uintptr_t base_address,
        const std::vector<uintptr_t>& offsets
    ) const {
        auto result = resolve_chain(base_address, offsets);
        if (!result.valid) return std::nullopt;
        return process_.read<T>(result.final_address);
    }

    // Set the maximum pointer chain depth for safety (default 6).
    void set_max_depth(size_t depth) { max_depth_ = depth; }
    size_t get_max_depth() const { return max_depth_; }

private:
    const Process& process_;
    size_t max_depth_ = 6;

    // Validate that an address is likely a valid user-mode pointer on x64 Windows.
    // Checks: non-null, above the reserved low range (0x10000), and within user-mode
    // address space limit (< 0x7FFFFFFFFFFF).
    bool is_valid_pointer(uintptr_t address) const;
};

} // namespace OffsetDumper
