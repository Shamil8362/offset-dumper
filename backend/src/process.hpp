#pragma once
#include "utils.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>

namespace OffsetDumper {

struct ModuleInfo {
    std::string name;
    uintptr_t base;
    size_t size;
};

class Process {
public:
    Process() = default;
    ~Process();
    
    // Non-copyable
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    
    // Move constructible
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;
    
    // Attach to a process by name (e.g., "notepad.exe")
    bool attach(const std::string& process_name);
    
    // Attach to a process by PID
    bool attach_pid(DWORD pid);
    
    // Detach (close handle)
    void detach();
    
    bool is_attached() const;
    DWORD get_pid() const { return pid_; }
    HANDLE get_handle() const { return handle_; }
    
    // Get all loaded modules
    std::vector<ModuleInfo> get_modules() const;
    
    // Get main module (first module = exe itself)
    std::optional<ModuleInfo> get_main_module() const;
    
    // Get a specific module by name
    std::optional<ModuleInfo> get_module(const std::string& name) const;
    
    // Enumerate all memory regions
    std::vector<MemoryRegion> get_memory_regions(bool readable_only = true) const;
    
    // Read memory from the process
    bool read_memory(uintptr_t address, void* buffer, size_t size) const;
    
    // Read memory into a vector
    std::vector<uint8_t> read_memory_vec(uintptr_t address, size_t size) const;
    
    // Read a single value
    template<typename T>
    std::optional<T> read(uintptr_t address) const {
        T value{};
        if (read_memory(address, &value, sizeof(T))) {
            return value;
        }
        return std::nullopt;
    }

private:
    HANDLE handle_ = nullptr;
    DWORD pid_ = 0;
    
    // Find PID by process name using snapshot
    static std::optional<DWORD> find_pid(const std::string& name);
};

} // namespace OffsetDumper
