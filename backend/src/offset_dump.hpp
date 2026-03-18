#pragma once
#include "utils.hpp"
#include <chrono>
#include <fstream>

namespace OffsetDumper {

class OffsetDump {
public:
    // Set metadata
    void set_target_name(const std::string& name);
    void set_module_base(uintptr_t base);

    // Add discovered offsets
    void add_offset(const std::string& name, uintptr_t offset, const std::string& comment = "");
    void add_offset(const NamedOffset& named);

    // Add pointer chain results
    void add_pointer_chain(const std::string& name, const PointerChainResult& chain);

    // Add raw scan results (pattern -> offsets found)
    void add_scan_results(const std::string& pattern, const std::vector<uintptr_t>& offsets);

    // Generate and write the header file
    bool write_header(const std::string& filepath) const;

    // Generate header content as string
    std::string generate_header() const;

    // Print summary to console
    void print_summary() const;

private:
    std::string target_name_ = "Unknown";
    uintptr_t module_base_ = 0;

    std::vector<NamedOffset> offsets_;
    std::vector<std::pair<std::string, PointerChainResult>> pointer_chains_;
    std::vector<std::pair<std::string, std::vector<uintptr_t>>> scan_results_;

    std::string get_timestamp() const;
};

} // namespace OffsetDumper
