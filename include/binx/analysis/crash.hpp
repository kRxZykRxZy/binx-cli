#pragma once
#include "binx/core/binary.hpp"
#include <cstdint>
#include <string>
#include <vector>
namespace binx {
enum class CrashDumpFormat { Unknown, WindowsMinidump, ELFCore };
struct CrashModule {
    std::uint64_t base=0;
    std::uint64_t size=0;
    std::string name;
};
struct CrashThread {
    std::uint32_t id=0;
    std::uint64_t stack_start=0;
    std::uint64_t stack_size=0;
};
struct CrashReport {
    CrashDumpFormat format=CrashDumpFormat::Unknown;
    Architecture architecture=Architecture::Unknown;
    std::string architecture_name;
    std::uint32_t thread_count=0;
    std::uint32_t module_count=0;
    std::uint32_t exception_code=0;
    std::uint32_t signal=0;
    std::uint64_t fault_address=0;
    std::uint32_t crashing_thread=0;
    std::vector<CrashThread> threads;
    std::vector<CrashModule> modules;
};
Result<CrashReport> analyze_crash_dump(const BinaryFile& file);
std::string format_crash_report(const CrashReport& report, const BinaryFile& file, bool json);
const char* crash_dump_format_name(CrashDumpFormat format);
}
