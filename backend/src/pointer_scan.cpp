#include "pointer_scan.hpp"

#include <iostream>
#include <algorithm>

namespace OffsetDumper {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

PointerScanner::PointerScanner(const Process& process)
    : process_(process)
{
}

// ---------------------------------------------------------------------------
// Pointer validation
// ---------------------------------------------------------------------------

bool PointerScanner::is_valid_pointer(uintptr_t address) const
{
    // Null or very low addresses are reserved by the OS.
    if (address == 0) return false;
    if (address < 0x10000) return false;

    // On Windows x64 the user-mode virtual address space ends at
    // 0x00007FFFFFFFFFFF.  Anything above that is kernel-mode and
    // inaccessible from user-mode code.
    constexpr uintptr_t kUserModeLimit = 0x7FFFFFFFFFFF;
    if (address > kUserModeLimit) return false;

    return true;
}

// ---------------------------------------------------------------------------
// resolve_chain
// ---------------------------------------------------------------------------

PointerChainResult PointerScanner::resolve_chain(
    uintptr_t base_address,
    const std::vector<uintptr_t>& offsets) const
{
    PointerChainResult result{};
    result.base_offset = 0;
    result.final_address = 0;
    result.valid = false;

    // ---- pre-checks -------------------------------------------------------

    if (!process_.is_attached()) {
        std::cerr << "[PointerScanner] Process is not attached.\n";
        return result;
    }

    if (offsets.empty()) {
        // No offsets – the base address itself is the final address.
        result.final_address = base_address;
        result.valid = is_valid_pointer(base_address);
        return result;
    }

    // Determine how many offsets we will actually use.
    std::vector<uintptr_t> effective_offsets = offsets;

    if (effective_offsets.size() > max_depth_) {
        std::cerr << "[PointerScanner] Warning: offset chain length ("
                  << effective_offsets.size()
                  << ") exceeds max depth (" << max_depth_
                  << "). Truncating.\n";
        effective_offsets.resize(max_depth_);
    }

    result.offsets = effective_offsets;

    // ---- walk the chain ---------------------------------------------------
    //
    // Pattern (N offsets, 0-indexed):
    //   current = base_address
    //   for i in 0 .. N-2:
    //       current = read<uintptr_t>(current + offsets[i])   // dereference
    //   final   = current + offsets[N-1]                      // last offset is a field offset
    //

    uintptr_t current = base_address;

    for (size_t i = 0; i < effective_offsets.size(); ++i) {
        const bool is_last = (i == effective_offsets.size() - 1);

        if (is_last) {
            // Last offset: just add it, no dereference.
            current += effective_offsets[i];
        } else {
            // Intermediate offset: add and dereference.
            uintptr_t read_addr = current + effective_offsets[i];

            if (!is_valid_pointer(read_addr)) {
                std::cerr << "[PointerScanner] Invalid pointer at level "
                          << i << ": address " << to_hex(read_addr) << "\n";
                return result;
            }

            auto value = process_.read<uintptr_t>(read_addr);
            if (!value.has_value()) {
                std::cerr << "[PointerScanner] Failed to read memory at level "
                          << i << ": address " << to_hex(read_addr) << "\n";
                return result;
            }

            current = value.value();

            if (!is_valid_pointer(current)) {
                std::cerr << "[PointerScanner] Dereferenced pointer is invalid at level "
                          << i << ": value " << to_hex(current) << "\n";
                return result;
            }
        }
    }

    result.final_address = current;
    result.valid = true;
    return result;
}

// ---------------------------------------------------------------------------
// resolve_chain_from_module
// ---------------------------------------------------------------------------

PointerChainResult PointerScanner::resolve_chain_from_module(
    const std::string& module_name,
    uintptr_t base_offset,
    const std::vector<uintptr_t>& offsets) const
{
    PointerChainResult result{};
    result.module_name = module_name;
    result.base_offset = base_offset;
    result.final_address = 0;
    result.valid = false;

    if (!process_.is_attached()) {
        std::cerr << "[PointerScanner] Process is not attached.\n";
        return result;
    }

    // Look up the module by name (case-insensitive).
    auto mod = process_.get_module(module_name);
    if (!mod.has_value()) {
        std::cerr << "[PointerScanner] Module not found: \"" << module_name << "\"\n";
        return result;
    }

    uintptr_t start_address = mod->base + base_offset;

    // Walk the chain then patch module metadata back
    auto chain_result = resolve_chain(start_address, offsets);
    chain_result.module_name = module_name;
    chain_result.base_offset = base_offset;
    return chain_result;
}

} // namespace OffsetDumper
