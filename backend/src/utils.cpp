#include "utils.hpp"

namespace OffsetDumper {

std::string to_hex(uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << value;
    return oss.str();
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return {};
    }

    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');

    for (size_t i = 0; i < len; ++i) {
        if (i > 0) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }

    return oss.str();
}

std::string wide_to_narrow(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }

    // First call: determine required buffer size
    int size_needed = ::WideCharToMultiByte(
        CP_UTF8,            // code page
        0,                  // flags
        wide.data(),        // source wide string
        static_cast<int>(wide.size()), // source length
        nullptr,            // dest buffer (nullptr to query size)
        0,                  // dest buffer size
        nullptr,            // default char
        nullptr             // used default char flag
    );

    if (size_needed <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(size_needed), '\0');

    // Second call: perform the actual conversion
    int bytes_written = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        wide.data(),
        static_cast<int>(wide.size()),
        result.data(),
        size_needed,
        nullptr,
        nullptr
    );

    if (bytes_written <= 0) {
        return {};
    }

    return result;
}

std::wstring narrow_to_wide(const std::string& narrow) {
    if (narrow.empty()) {
        return {};
    }

    // First call: determine required buffer size
    int size_needed = ::MultiByteToWideChar(
        CP_UTF8,            // code page
        0,                  // flags
        narrow.data(),      // source narrow string
        static_cast<int>(narrow.size()), // source length
        nullptr,            // dest buffer (nullptr to query size)
        0                   // dest buffer size
    );

    if (size_needed <= 0) {
        return {};
    }

    std::wstring result(static_cast<size_t>(size_needed), L'\0');

    // Second call: perform the actual conversion
    int chars_written = ::MultiByteToWideChar(
        CP_UTF8,
        0,
        narrow.data(),
        static_cast<int>(narrow.size()),
        result.data(),
        size_needed
    );

    if (chars_written <= 0) {
        return {};
    }

    return result;
}

std::string get_last_error_string() {
    DWORD error_code = ::GetLastError();

    if (error_code == 0) {
        return "No error";
    }

    LPSTR message_buffer = nullptr;

    DWORD size = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,            // source
        error_code,         // message id
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // language id
        reinterpret_cast<LPSTR>(&message_buffer),  // output buffer
        0,                  // minimum allocation size
        nullptr             // arguments
    );

    if (size == 0 || !message_buffer) {
        return "Unknown error (code " + std::to_string(error_code) + ")";
    }

    // Trim trailing whitespace/newlines from the system message
    std::string message(message_buffer, size);
    ::LocalFree(message_buffer);

    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r' || message.back() == ' ')) {
        message.pop_back();
    }

    return message + " (code " + std::to_string(error_code) + ")";
}

void print_error(const std::string& context) {
    std::cerr << "[ERROR] " << context << ": " << get_last_error_string() << std::endl;
}

} // namespace OffsetDumper
