#include "binx/analysis/crash.hpp"
#include "binx/core/text.hpp"
#include "binx/formats/detect.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <utility>

namespace binx {
namespace {

using Bytes = std::span<const std::byte>;

bool range_valid(Bytes data, std::uint64_t offset, std::uint64_t length) {
    return offset <= data.size() && length <= data.size() - offset;
}

std::uint16_t read_u16(Bytes data, std::uint64_t offset, bool big_endian) {
    if (!range_valid(data, offset, 2)) return 0;
    const auto a = std::to_integer<std::uint8_t>(data[static_cast<std::size_t>(offset)]);
    const auto b = std::to_integer<std::uint8_t>(
        data[static_cast<std::size_t>(offset + 1)]);
    return big_endian
        ? static_cast<std::uint16_t>((std::uint16_t(a) << 8) | b)
        : static_cast<std::uint16_t>(a | (std::uint16_t(b) << 8));
}

std::uint32_t read_u32(Bytes data, std::uint64_t offset, bool big_endian) {
    if (!range_valid(data, offset, 4)) return 0;
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const auto byte = std::to_integer<std::uint8_t>(
            data[static_cast<std::size_t>(offset + i)]);
        const auto shift = big_endian ? static_cast<unsigned>(8 * (3 - i))
                                      : static_cast<unsigned>(8 * i);
        value |= std::uint32_t(byte) << shift;
    }
    return value;
}

std::uint64_t read_u64(Bytes data, std::uint64_t offset, bool big_endian) {
    if (!range_valid(data, offset, 8)) return 0;
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        const auto byte = std::to_integer<std::uint8_t>(
            data[static_cast<std::size_t>(offset + i)]);
        const auto shift = big_endian ? static_cast<unsigned>(8 * (7 - i))
                                      : static_cast<unsigned>(8 * i);
        value |= std::uint64_t(byte) << shift;
    }
    return value;
}

std::string minidump_string(Bytes data, std::uint32_t rva) {
    if (!range_valid(data, rva, 4)) return {};
    const auto characters = read_u32(data, rva, false);
    if (characters > std::numeric_limits<std::size_t>::max() / 2) return {};
    const auto byte_count = std::uint64_t(characters) * 2;
    if (!range_valid(data, std::uint64_t(rva) + 4, byte_count)) return {};

    std::string text;
    text.reserve(characters);
    for (std::uint32_t i = 0; i < characters; ++i) {
        const auto code_unit = read_u16(data, std::uint64_t(rva) + 4 + std::uint64_t(i) * 2, false);
        text.push_back(code_unit < 128 ? static_cast<char>(code_unit) : '?');
    }
    return text;
}

Architecture elf_architecture(std::uint16_t machine) {
    switch (machine) {
    case 3: return Architecture::X86;
    case 62: return Architecture::X86_64;
    case 40: return Architecture::ARM;
    case 183: return Architecture::ARM64;
    case 243: return Architecture::RISCV64;
    default: return Architecture::Unknown;
    }
}

bool parse_minidump(Bytes data, CrashReport& report) {
    if (data.size() < 32) return false;
    const auto stream_count = read_u32(data, 8, false);
    const auto directory_rva = read_u32(data, 12, false);
    if (stream_count > 4096 || !range_valid(data, directory_rva, std::uint64_t(stream_count) * 12)) {
        return false;
    }

    bool saw_stream = false;
    for (std::uint32_t i = 0; i < stream_count; ++i) {
        const auto entry = std::uint64_t(directory_rva) + std::uint64_t(i) * 12;
        const auto type = read_u32(data, entry, false);
        const auto size = read_u32(data, entry + 4, false);
        const auto rva = read_u32(data, entry + 8, false);
        if (!range_valid(data, rva, size)) continue;

        if (type == 4 && size >= 4) {
            const auto declared = read_u32(data, rva, false);
            const auto count = std::min<std::uint32_t>(declared, 4096);
            std::uint64_t cursor = std::uint64_t(rva) + 4;
            report.modules.clear();
            report.modules.reserve(count);
            for (std::uint32_t j = 0; j < count; ++j) {
                if (!range_valid(data, cursor, 108)) break;
                CrashModule module;
                module.base = read_u64(data, cursor, false);
                module.size = read_u32(data, cursor + 8, false);
                module.name = minidump_string(data, read_u32(data, cursor + 20, false));
                report.modules.push_back(std::move(module));
                cursor += 108;
            }
            report.module_count = static_cast<std::uint32_t>(report.modules.size());
            saw_stream = true;
        } else if (type == 3 && size >= 4) {
            const auto declared = read_u32(data, rva, false);
            const auto count = std::min<std::uint32_t>(declared, 4096);
            std::uint64_t cursor = std::uint64_t(rva) + 4;
            report.threads.clear();
            report.threads.reserve(count);
            for (std::uint32_t j = 0; j < count; ++j) {
                if (!range_valid(data, cursor, 48)) break;
                CrashThread thread;
                thread.id = read_u32(data, cursor, false);
                thread.stack_start = read_u64(data, cursor + 24, false);
                thread.stack_size = read_u32(data, cursor + 32, false);
                report.threads.push_back(thread);
                cursor += 48;
            }
            report.thread_count = static_cast<std::uint32_t>(report.threads.size());
            saw_stream = true;
        } else if (type == 6 && size >= 168) {
            report.crashing_thread = read_u32(data, rva, false);
            report.exception_code = read_u32(data, rva + 8, false);
            report.fault_address = read_u64(data, rva + 24, false);
            saw_stream = true;
        } else if (type == 7 && size >= 2) {
            switch (read_u16(data, rva, false)) {
            case 0: report.architecture = Architecture::X86; break;
            case 9: report.architecture = Architecture::X86_64; break;
            case 5: report.architecture = Architecture::ARM; break;
            case 12: report.architecture = Architecture::ARM64; break;
            default: report.architecture = Architecture::Unknown; break;
            }
            saw_stream = true;
        }
    }
    return saw_stream;
}

bool parse_elf_core(Bytes data, CrashReport& report) {
    if (data.size() < 20 || data[0] != std::byte{0x7f} ||
        data[1] != std::byte{'E'} || data[2] != std::byte{'L'} ||
        data[3] != std::byte{'F'}) {
        return false;
    }

    const bool is64 = data[4] == std::byte{2};
    const bool big_endian = data[5] == std::byte{2};
    if (!is64 && data[4] != std::byte{1}) return false;
    if (data[5] != std::byte{1} && !big_endian) return false;
    if (read_u16(data, 16, big_endian) != 4) return false;

    report.architecture = elf_architecture(read_u16(data, 18, big_endian));

    const auto phoff = is64 ? read_u64(data, 32, big_endian)
                            : read_u32(data, 28, big_endian);
    const auto phentsize = read_u16(data, is64 ? 54 : 42, big_endian);
    const auto phnum = read_u16(data, is64 ? 56 : 44, big_endian);
    const auto minimum_phentsize = is64 ? 56u : 32u;
    if (phnum > 4096 || phentsize < minimum_phentsize ||
        !range_valid(data, phoff, std::uint64_t(phentsize) * phnum)) {
        return false;
    }

    bool saw_note = false;
    for (std::uint16_t i = 0; i < phnum; ++i) {
        const auto program = phoff + std::uint64_t(i) * phentsize;
        const auto type = read_u32(data, program, big_endian);
        if (type != 4) continue;

        const auto file_offset = is64 ? read_u64(data, program + 8, big_endian)
                                      : read_u32(data, program + 4, big_endian);
        const auto file_size = is64 ? read_u64(data, program + 32, big_endian)
                                    : read_u32(data, program + 16, big_endian);
        if (file_size < 12 || !range_valid(data, file_offset, file_size)) continue;

        std::uint64_t cursor = file_offset;
        const auto end = file_offset + file_size;
        while (cursor <= end && end - cursor >= 12) {
            const auto namesize = read_u32(data, cursor, big_endian);
            const auto descsize = read_u32(data, cursor + 4, big_endian);
            const auto note_type = read_u32(data, cursor + 8, big_endian);
            if (namesize > 0x10000000u || descsize > 0x10000000u) break;

            const auto name_padded = (std::uint64_t(namesize) + 3) & ~std::uint64_t(3);
            const auto desc_padded = (std::uint64_t(descsize) + 3) & ~std::uint64_t(3);
            if (end - cursor < 12 || name_padded > end - cursor - 12) break;
            const auto after_name = cursor + 12 + name_padded;
            if (desc_padded > end - after_name) break;
            const auto descriptor = after_name;

            if (note_type == 1) {
                ++report.thread_count;
            } else if (note_type == 0x53494749 && descsize >= 4) {
                report.signal = read_u32(data, descriptor, big_endian);
            }
            saw_note = true;
            cursor = descriptor + desc_padded;
        }
    }
    return saw_note;
}

} // namespace

const char* crash_dump_format_name(CrashDumpFormat format) {
    switch (format) {
    case CrashDumpFormat::WindowsMinidump: return "Windows minidump";
    case CrashDumpFormat::ELFCore: return "ELF core dump";
    default: return "unknown";
    }
}

Result<CrashReport> analyze_crash_dump(const BinaryFile& file) {
    CrashReport report;
    const auto data = file.bytes();

    if (data.size() >= 4 && data[0] == std::byte{'M'} &&
        data[1] == std::byte{'D'} && data[2] == std::byte{'M'} &&
        data[3] == std::byte{'P'}) {
        report.format = CrashDumpFormat::WindowsMinidump;
        if (!parse_minidump(data, report)) {
            return Error{ErrorCode::InvalidBinary, "minidump header or stream directory is invalid"};
        }
    } else if (data.size() >= 20 && data[0] == std::byte{0x7f} &&
               data[1] == std::byte{'E'} && data[2] == std::byte{'L'} &&
               data[3] == std::byte{'F'} &&
               (data[4] == std::byte{1} || data[4] == std::byte{2})) {
        report.format = CrashDumpFormat::ELFCore;
        if (!parse_elf_core(data, report)) {
            return Error{ErrorCode::InvalidBinary, "ELF core program-note data is invalid"};
        }
    } else {
        return Error{ErrorCode::UnsupportedFormat,
                     "input is not a supported Windows minidump or ELF core dump"};
    }

    report.architecture_name = architecture_name(report.architecture);
    return report;
}

std::string format_crash_report(const CrashReport& report,
                                const BinaryFile& file,
                                bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\n"
            << "  \"schema_version\":7,\n"
            << "  \"file\":\"" << json_escape(file.path().filename().string()) << "\",\n"
            << "  \"format\":\"" << json_escape(crash_dump_format_name(report.format)) << "\",\n"
            << "  \"architecture\":\"" << json_escape(report.architecture_name) << "\",\n"
            << "  \"threads\":" << report.thread_count << ",\n"
            << "  \"modules\":" << report.module_count << ",\n"
            << "  \"exception_code\":" << report.exception_code << ",\n"
            << "  \"signal\":" << report.signal << ",\n"
            << "  \"fault_address\":\"" << hex_u64(report.fault_address) << "\",\n"
            << "  \"crashing_thread\":" << report.crashing_thread << ",\n"
            << "  \"module_list\":[";
        for (std::size_t i = 0; i < report.modules.size(); ++i) {
            if (i) out << ',';
            const auto& module = report.modules[i];
            out << "{\"base\":\"" << hex_u64(module.base) << "\",\"size\":"
                << module.size << ",\"name\":\"" << json_escape(module.name) << "\"}";
        }
        out << "]\n}\n";
        return out.str();
    }

    out << "BINX CRASH ANALYSIS\n\nFILE\n  "
        << file.path().filename().string()
        << "\n  Format:          " << crash_dump_format_name(report.format)
        << "\n  Architecture:   " << report.architecture_name
        << "\n\nCRASH\n";
    if (report.exception_code) {
        out << "  Exception code:  0x" << std::hex << report.exception_code << "\n";
    }
    if (report.signal) {
        out << "  Signal:          " << std::dec << report.signal << "\n";
    }
    out << "  Fault address:   " << hex_u64(report.fault_address) << "\n"
        << "  Crashing thread: " << report.crashing_thread
        << "\n\nSUMMARY\n  Threads:         " << report.thread_count
        << "\n  Modules:         " << report.module_count << "\n";

    if (!report.modules.empty()) {
        out << "\nMODULES\n";
        for (const auto& module : report.modules) {
            out << "  " << hex_u64(module.base) << " + " << hex_u64(module.size)
                << "  " << module.name << "\n";
        }
    }
    return out.str();
}

} // namespace binx
