#include "process.hpp"
#include <algorithm>
#include <cctype>

#pragma comment(lib, "psapi.lib")

namespace OffsetDumper {

// --------------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------------

Process::~Process() {
    detach();
}

Process::Process(Process&& other) noexcept
    : handle_(other.handle_)
    , pid_(other.pid_)
{
    other.handle_ = nullptr;
    other.pid_ = 0;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        detach();
        handle_ = other.handle_;
        pid_ = other.pid_;
        other.handle_ = nullptr;
        other.pid_ = 0;
    }
    return *this;
}

// --------------------------------------------------------------------------
// Attach / Detach
// --------------------------------------------------------------------------

bool Process::attach(const std::string& process_name) {
    auto pid = find_pid(process_name);
    if (!pid.has_value()) {
        std::cerr << "[Process] Could not find process: " << process_name << std::endl;
        return false;
    }
    return attach_pid(pid.value());
}

bool Process::attach_pid(DWORD pid) {
    // Detach from any currently attached process first
    detach();

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (h == nullptr) {
        print_error("OpenProcess failed for PID " + std::to_string(pid));
        return false;
    }

    handle_ = h;
    pid_ = pid;
    std::cout << "[Process] Attached to PID " << pid_ << std::endl;
    return true;
}

void Process::detach() {
    if (handle_ != nullptr) {
        CloseHandle(handle_);
        handle_ = nullptr;
        pid_ = 0;
    }
}

bool Process::is_attached() const {
    return handle_ != nullptr;
}

// --------------------------------------------------------------------------
// find_pid  (static, private)
// --------------------------------------------------------------------------

std::optional<DWORD> Process::find_pid(const std::string& name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        print_error("CreateToolhelp32Snapshot failed");
        return std::nullopt;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    // Prepare a lower-case copy of the target name for case-insensitive compare
    std::string target = name;
    std::transform(target.begin(), target.end(), target.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::optional<DWORD> result = std::nullopt;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::string exe_name = wide_to_narrow(entry.szExeFile);
            std::string exe_lower = exe_name;
            std::transform(exe_lower.begin(), exe_lower.end(), exe_lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (exe_lower == target) {
                result = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    } else {
        print_error("Process32FirstW failed");
    }

    CloseHandle(snapshot);
    return result;
}

// --------------------------------------------------------------------------
// Module enumeration
// --------------------------------------------------------------------------

std::vector<ModuleInfo> Process::get_modules() const {
    std::vector<ModuleInfo> modules;

    if (!is_attached()) {
        std::cerr << "[Process] Not attached — cannot enumerate modules." << std::endl;
        return modules;
    }

    // First pass: determine how many modules there are
    DWORD bytes_needed = 0;
    if (!EnumProcessModulesEx(handle_, nullptr, 0, &bytes_needed, LIST_MODULES_ALL)) {
        print_error("EnumProcessModulesEx (size query) failed");
        return modules;
    }

    const DWORD module_count = bytes_needed / sizeof(HMODULE);
    if (module_count == 0) {
        return modules;
    }

    std::vector<HMODULE> hmodules(module_count);
    if (!EnumProcessModulesEx(handle_, hmodules.data(),
                              static_cast<DWORD>(hmodules.size() * sizeof(HMODULE)),
                              &bytes_needed, LIST_MODULES_ALL)) {
        print_error("EnumProcessModulesEx failed");
        return modules;
    }

    // Resize in case fewer modules were returned the second time
    const DWORD actual_count = bytes_needed / sizeof(HMODULE);
    hmodules.resize(actual_count);

    modules.reserve(actual_count);

    for (HMODULE hmod : hmodules) {
        char name_buf[MAX_PATH]{};
        if (GetModuleFileNameExA(handle_, hmod, name_buf, MAX_PATH) == 0) {
            print_error("GetModuleFileNameExA failed");
            continue;
        }

        MODULEINFO mi{};
        if (!GetModuleInformation(handle_, hmod, &mi, sizeof(mi))) {
            print_error("GetModuleInformation failed");
            continue;
        }

        // Extract just the filename from the full path
        std::string full_path(name_buf);
        std::string short_name = full_path;
        auto last_sep = full_path.find_last_of("\\/");
        if (last_sep != std::string::npos) {
            short_name = full_path.substr(last_sep + 1);
        }

        ModuleInfo info;
        info.name = short_name;
        info.base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        info.size = mi.SizeOfImage;
        modules.push_back(std::move(info));
    }

    return modules;
}

std::optional<ModuleInfo> Process::get_main_module() const {
    auto modules = get_modules();
    if (modules.empty()) {
        return std::nullopt;
    }
    // The first module returned by EnumProcessModulesEx is the exe itself
    return modules.front();
}

std::optional<ModuleInfo> Process::get_module(const std::string& name) const {
    // Prepare a lower-case copy of the target name for case-insensitive compare
    std::string target = name;
    std::transform(target.begin(), target.end(), target.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Enumerate once and search — avoids double enumeration
    auto modules = get_modules();
    for (auto& mod : modules) {
        std::string mod_lower = mod.name;
        std::transform(mod_lower.begin(), mod_lower.end(), mod_lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (mod_lower == target) {
            return mod;
        }
    }
    return std::nullopt;
}

// --------------------------------------------------------------------------
// Memory region enumeration
// --------------------------------------------------------------------------

std::vector<MemoryRegion> Process::get_memory_regions(bool readable_only) const {
    std::vector<MemoryRegion> regions;

    if (!is_attached()) {
        std::cerr << "[Process] Not attached — cannot enumerate memory regions." << std::endl;
        return regions;
    }

    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != 0) {
        // Only include committed pages
        if (mbi.State == MEM_COMMIT) {
            bool include = true;

            if (readable_only) {
                // Filter to regions that have at least readable protection
                const DWORD prot = mbi.Protect;
                const bool is_readable =
                    (prot & PAGE_READONLY) ||
                    (prot & PAGE_READWRITE) ||
                    (prot & PAGE_WRITECOPY) ||
                    (prot & PAGE_EXECUTE_READ) ||
                    (prot & PAGE_EXECUTE_READWRITE) ||
                    (prot & PAGE_EXECUTE_WRITECOPY);

                // Exclude guard/noaccess pages
                const bool is_guarded =
                    (prot & PAGE_GUARD) ||
                    (prot & PAGE_NOACCESS);

                include = is_readable && !is_guarded;
            }

            if (include) {
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.protection = mbi.Protect;
                region.state = mbi.State;
                region.type = mbi.Type;
                regions.push_back(region);
            }
        }

        // Advance to the next region
        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) {
            // Overflow or no progress — stop
            break;
        }
        address = next;
    }

    return regions;
}

// --------------------------------------------------------------------------
// Memory reading
// --------------------------------------------------------------------------

bool Process::read_memory(uintptr_t address, void* buffer, size_t size) const {
    if (!is_attached()) {
        std::cerr << "[Process] Not attached — cannot read memory." << std::endl;
        return false;
    }

    if (buffer == nullptr || size == 0) {
        return false;
    }

    SIZE_T bytes_read = 0;
    BOOL ok = ReadProcessMemory(
        handle_,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &bytes_read
    );

    if (!ok) {
        print_error("ReadProcessMemory failed at " + to_hex(address));
        return false;
    }

    if (bytes_read != size) {
        std::cerr << "[Process] Partial read at " << to_hex(address)
                  << ": requested " << size
                  << " bytes, got " << bytes_read << std::endl;
        return false;
    }

    return true;
}

std::vector<uint8_t> Process::read_memory_vec(uintptr_t address, size_t size) const {
    std::vector<uint8_t> buffer(size, 0);
    if (!read_memory(address, buffer.data(), size)) {
        buffer.clear();
    }
    return buffer;
}

} // namespace OffsetDumper
