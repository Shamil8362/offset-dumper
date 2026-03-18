#include "utils.hpp"
#include "pe_parser.hpp"
#include "aob_scanner.hpp"
#include "process.hpp"
#include "pointer_scan.hpp"
#include "offset_dump.hpp"

#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <sstream>

using namespace OffsetDumper;

// ── Forward declarations ───────────────────────────────────────────────────
static void print_banner();
static void print_usage(const char* program_name);
static std::vector<uintptr_t> parse_chain_arg(const std::string& arg);

// ── Banner ─────────────────────────────────────────────────────────────────
static void print_banner() {
    std::cout << "=== OffsetDumper v1.0 ===" << std::endl;
    std::cout << "Windows x64 Offset Analysis Tool" << std::endl;
    std::cout << std::endl;
}

// ── Usage ──────────────────────────────────────────────────────────────────
static void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "\n"
              << "Options:\n"
              << "  --process <name>       Attach to a running process by name and scan its memory\n"
              << "  --file <path>          Analyze a static PE binary on disk\n"
              << "  --pattern <AOB>        IDA-style byte pattern to scan for\n"
              << "                         Example: \"48 8B 05 ? ? ? ? 48 89\"\n"
              << "  --depth <N>            Pointer chain max depth (1-6, default: 4)\n"
              << "  --output <file>        Output header file path (default: offsets.hpp)\n"
              << "  --chain <offsets>      Resolve a pointer chain (colon-separated hex offsets)\n"
              << "                         Example: \"0x1234:0x10:0x5C\"\n"
              << "  --help                 Print this usage information\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --file game.exe --pattern \"48 8B 05 ? ? ? ?\"\n"
              << "  " << program_name << " --process game.exe --pattern \"48 89 5C 24 ? 57\" --output offsets.hpp\n"
              << "  " << program_name << " --process game.exe --chain 0x1A2B00:0x10:0x20:0x5C\n"
              << std::endl;
}

// ── Parse colon-separated hex chain ────────────────────────────────────────
static std::vector<uintptr_t> parse_chain_arg(const std::string& arg) {
    std::vector<uintptr_t> result;
    std::istringstream stream(arg);
    std::string token;

    while (std::getline(stream, token, ':')) {
        if (token.empty()) {
            continue;
        }

        try {
            // Handle 0x prefix and plain hex
            size_t pos = 0;
            uintptr_t value = std::stoull(token, &pos, 16);
            if (pos == 0) {
                std::cerr << "[ERROR] Invalid hex value in chain: \"" << token << "\"" << std::endl;
                return {};
            }
            result.push_back(value);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to parse chain offset \"" << token << "\": "
                      << e.what() << std::endl;
            return {};
        }
    }

    return result;
}

// ── Main ───────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    print_banner();

    // ── Argument parsing ───────────────────────────────────────────────────
    std::string process_name;
    std::string file_path;
    std::string pattern;
    std::string output_path = "offsets.hpp";
    std::string chain_arg;
    size_t depth = 4;
    bool has_output = false;
    bool show_help = false;

    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            show_help = true;
        } else if (arg == "--process") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] --process requires an argument" << std::endl;
                return 1;
            }
            process_name = argv[++i];
        } else if (arg == "--file") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] --file requires an argument" << std::endl;
                return 1;
            }
            file_path = argv[++i];
        } else if (arg == "--pattern") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] --pattern requires an argument" << std::endl;
                return 1;
            }
            pattern = argv[++i];
        } else if (arg == "--depth") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] --depth requires an argument" << std::endl;
                return 1;
            }
            try {
                int d = std::stoi(argv[++i]);
                if (d < 1 || d > 6) {
                    std::cerr << "[ERROR] --depth must be between 1 and 6" << std::endl;
                    return 1;
                }
                depth = static_cast<size_t>(d);
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Invalid depth value: " << e.what() << std::endl;
                return 1;
            }
        } else if (arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] --output requires an argument" << std::endl;
                return 1;
            }
            output_path = argv[++i];
            has_output = true;
        } else if (arg == "--chain") {
            if (i + 1 >= argc) {
                std::cerr << "[ERROR] --chain requires an argument" << std::endl;
                return 1;
            }
            chain_arg = argv[++i];
        } else {
            std::cerr << "[ERROR] Unknown argument: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (show_help) {
        print_usage(argv[0]);
        return 0;
    }

    // ── Validate argument combinations ─────────────────────────────────────
    if (process_name.empty() && file_path.empty()) {
        std::cerr << "[ERROR] Must specify either --process or --file" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    if (!process_name.empty() && !file_path.empty()) {
        std::cerr << "[ERROR] Cannot use both --process and --file simultaneously" << std::endl;
        return 1;
    }

    if (!chain_arg.empty() && process_name.empty()) {
        std::cerr << "[ERROR] --chain requires --process mode" << std::endl;
        return 1;
    }

    // ── Prepare OffsetDump ─────────────────────────────────────────────────
    OffsetDump dump;

    // ── FILE mode ──────────────────────────────────────────────────────────
    if (!file_path.empty()) {
        std::cout << "[*] Analyzing PE file: " << file_path << std::endl;

        PEParser parser;
        if (!parser.load(file_path)) {
            std::cerr << "[ERROR] Failed to load PE file: " << file_path << std::endl;
            return 1;
        }

        if (!parser.is_valid()) {
            std::cerr << "[ERROR] File is not a valid PE: " << file_path << std::endl;
            return 1;
        }

        std::cout << "[+] PE loaded successfully" << std::endl;
        std::cout << "    Architecture: " << (parser.is_64bit() ? "x64" : "x86") << std::endl;
        std::cout << "    Image Base:   " << to_hex(parser.get_image_base()) << std::endl;
        std::cout << std::endl;

        dump.set_target_name(file_path);
        dump.set_module_base(parser.get_image_base());

        // Print section information
        auto sections = parser.get_sections();
        std::cout << "[*] Sections (" << sections.size() << "):" << std::endl;
        std::cout << "    "
                  << std::left << std::setw(12) << "Name"
                  << std::right << std::setw(16) << "VirtAddr"
                  << std::setw(12) << "VirtSize"
                  << std::setw(16) << "RawOffset"
                  << std::setw(12) << "RawSize"
                  << std::endl;
        std::cout << "    " << std::string(68, '-') << std::endl;

        for (const auto& sec : sections) {
            std::cout << "    "
                      << std::left << std::setw(12) << sec.name
                      << std::right << std::setw(16) << to_hex(sec.virtual_address)
                      << std::setw(12) << to_hex(sec.virtual_size)
                      << std::setw(16) << to_hex(sec.raw_offset)
                      << std::setw(12) << to_hex(sec.raw_size)
                      << std::endl;
        }
        std::cout << std::endl;

        // Scan sections if pattern is specified
        if (!pattern.empty()) {
            std::cout << "[*] Scanning for pattern: " << pattern << std::endl;

            try {
                AOBScanner::parse_pattern(pattern);
            } catch (const std::invalid_argument& e) {
                std::cerr << "[ERROR] Invalid pattern: " << e.what() << std::endl;
                return 1;
            }

            size_t total_matches = 0;
            std::vector<uintptr_t> all_offsets;

            for (const auto& sec : sections) {
                auto data = parser.read_section_data(sec);
                if (data.empty()) {
                    continue;
                }

                auto matches = AOBScanner::scan_buffer(data.data(), data.size(), pattern);
                if (!matches.empty()) {
                    std::cout << "    [+] " << sec.name << ": "
                              << matches.size() << " match(es)" << std::endl;

                    for (size_t match_offset : matches) {
                        // Compute RVA-relative offset: section VA + offset within section
                        uintptr_t rva = sec.virtual_address + match_offset;
                        std::cout << "        Offset " << to_hex(rva)
                                  << " (section+" << to_hex(match_offset) << ")";

                        // Try to extract RIP-relative address for common instruction patterns
                        // Typical: 3-byte opcode + 4-byte displacement + rest = 7 bytes
                        if (data.size() >= match_offset + 7) {
                            auto rip_result = AOBScanner::extract_rip_relative(
                                data.data(), data.size(), match_offset, 3, 7
                            );
                            if (rip_result.has_value()) {
                                uintptr_t target_rva = sec.virtual_address + rip_result.value();
                                std::cout << "  -> RIP target: " << to_hex(target_rva);

                                dump.add_offset(
                                    "rip_target_" + std::to_string(total_matches),
                                    target_rva,
                                    "RIP-relative from " + to_hex(rva) + " in " + sec.name
                                );
                            }
                        }

                        std::cout << std::endl;

                        all_offsets.push_back(rva);
                        dump.add_offset(
                            "pattern_match_" + std::to_string(total_matches),
                            rva,
                            "Found in section " + sec.name
                        );
                        ++total_matches;
                    }
                }
            }

            dump.add_scan_results(pattern, all_offsets);

            std::cout << std::endl;
            std::cout << "[*] Total matches: " << total_matches << std::endl;
            std::cout << std::endl;
        }
    }

    // ── PROCESS mode ───────────────────────────────────────────────────────
    if (!process_name.empty()) {
        std::cout << "[*] Attaching to process: " << process_name << std::endl;

        Process proc;
        if (!proc.attach(process_name)) {
            std::cerr << "[ERROR] Failed to attach to process: " << process_name << std::endl;
            return 1;
        }

        std::cout << "[+] Attached successfully" << std::endl;
        std::cout << std::endl;

        // Print module info
        auto modules = proc.get_modules();
        std::cout << "[*] Loaded modules (" << modules.size() << "):" << std::endl;
        std::cout << "    "
                  << std::left << std::setw(32) << "Name"
                  << std::right << std::setw(18) << "Base"
                  << std::setw(14) << "Size"
                  << std::endl;
        std::cout << "    " << std::string(64, '-') << std::endl;

        for (const auto& mod : modules) {
            std::cout << "    "
                      << std::left << std::setw(32) << mod.name
                      << std::right << std::setw(18) << to_hex(mod.base)
                      << std::setw(14) << to_hex(mod.size)
                      << std::endl;
        }
        std::cout << std::endl;

        // Get main module for offset calculations
        auto main_mod = proc.get_main_module();
        if (main_mod.has_value()) {
            dump.set_target_name(main_mod->name);
            dump.set_module_base(main_mod->base);
            std::cout << "[*] Main module: " << main_mod->name
                      << " @ " << to_hex(main_mod->base)
                      << " (size: " << to_hex(main_mod->size) << ")" << std::endl;
            std::cout << std::endl;
        } else {
            std::cerr << "[WARN] Could not determine main module" << std::endl;
            dump.set_target_name(process_name);
        }

        // Scan readable regions if pattern is specified
        if (!pattern.empty()) {
            std::cout << "[*] Scanning process memory for pattern: " << pattern << std::endl;

            try {
                AOBScanner::parse_pattern(pattern);
            } catch (const std::invalid_argument& e) {
                std::cerr << "[ERROR] Invalid pattern: " << e.what() << std::endl;
                proc.detach();
                return 1;
            }

            auto regions = proc.get_memory_regions(true /* readable_only */);
            std::cout << "    Scanning " << regions.size() << " readable region(s)..." << std::endl;

            size_t total_matches = 0;
            std::vector<uintptr_t> all_offsets;

            for (const auto& region : regions) {
                auto data = proc.read_memory_vec(region.base, region.size);
                if (data.empty()) {
                    continue;
                }

                auto matches = AOBScanner::scan_buffer(data.data(), data.size(), pattern);
                for (size_t match_offset : matches) {
                    uintptr_t absolute_addr = region.base + match_offset;

                    // Calculate module-relative offset if possible
                    uintptr_t display_offset = absolute_addr;
                    std::string comment = "Address: " + to_hex(absolute_addr);
                    if (main_mod.has_value() &&
                        absolute_addr >= main_mod->base &&
                        absolute_addr < main_mod->base + main_mod->size) {
                        display_offset = absolute_addr - main_mod->base;
                        comment = "RVA in " + main_mod->name;
                    }

                    std::cout << "    [+] Match at " << to_hex(absolute_addr);
                    if (main_mod.has_value() &&
                        absolute_addr >= main_mod->base &&
                        absolute_addr < main_mod->base + main_mod->size) {
                        std::cout << " (base+" << to_hex(display_offset) << ")";
                    }

                    // Try RIP-relative extraction
                    if (data.size() >= match_offset + 7) {
                        auto rip_result = AOBScanner::extract_rip_relative(
                            data.data(), data.size(), match_offset, 3, 7
                        );
                        if (rip_result.has_value()) {
                            uintptr_t target_addr = region.base + rip_result.value();
                            std::cout << "  -> RIP target: " << to_hex(target_addr);

                            if (main_mod.has_value()) {
                                uintptr_t target_rva = target_addr - main_mod->base;
                                dump.add_offset(
                                    "rip_target_" + std::to_string(total_matches),
                                    target_rva,
                                    "RIP-relative target from " + to_hex(display_offset)
                                );
                            }
                        }
                    }

                    std::cout << std::endl;

                    all_offsets.push_back(display_offset);
                    dump.add_offset(
                        "pattern_match_" + std::to_string(total_matches),
                        display_offset,
                        comment
                    );
                    ++total_matches;
                }
            }

            dump.add_scan_results(pattern, all_offsets);

            std::cout << std::endl;
            std::cout << "[*] Total matches: " << total_matches << std::endl;
            std::cout << std::endl;
        }

        // Resolve pointer chain if specified
        if (!chain_arg.empty()) {
            auto chain_values = parse_chain_arg(chain_arg);
            if (chain_values.size() < 1) {
                std::cerr << "[ERROR] Invalid chain argument — need at least a base offset" << std::endl;
                proc.detach();
                return 1;
            }

            uintptr_t base_offset = chain_values[0];
            std::vector<uintptr_t> offsets(chain_values.begin() + 1, chain_values.end());

            std::cout << "[*] Resolving pointer chain:" << std::endl;
            std::cout << "    Base offset: " << to_hex(base_offset) << std::endl;
            std::cout << "    Offsets:     ";
            for (size_t i = 0; i < offsets.size(); ++i) {
                if (i > 0) std::cout << " -> ";
                std::cout << to_hex(offsets[i]);
            }
            std::cout << std::endl;
            std::cout << "    Max depth:   " << depth << std::endl;
            std::cout << std::endl;

            PointerScanner scanner(proc);
            scanner.set_max_depth(depth);

            std::string module_for_chain = main_mod.has_value() ? main_mod->name : process_name;
            auto chain_result = scanner.resolve_chain_from_module(module_for_chain, base_offset, offsets);

            if (chain_result.valid) {
                std::cout << "[+] Chain resolved successfully!" << std::endl;
                std::cout << "    Final address: " << to_hex(chain_result.final_address) << std::endl;

                dump.add_pointer_chain("pointer_chain_0", chain_result);
            } else {
                std::cerr << "[ERROR] Failed to resolve pointer chain" << std::endl;
            }
            std::cout << std::endl;
        }

        proc.detach();
        std::cout << "[*] Detached from process" << std::endl;
        std::cout << std::endl;
    }

    // ── Output results ─────────────────────────────────────────────────────
    dump.print_summary();

    if (has_output) {
        std::cout << "[*] Writing header file: " << output_path << std::endl;
        if (dump.write_header(output_path)) {
            std::cout << "[+] Header written successfully: " << output_path << std::endl;
        } else {
            std::cerr << "[ERROR] Failed to write header file: " << output_path << std::endl;
            return 1;
        }
    }

    return 0;
}
