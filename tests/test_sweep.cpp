#include "binx/cli/options.hpp"
#include "binx/cli/runner.hpp"
#include "binx/core/binary.hpp"
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Every command the CLI supports. The sweep runs each against every fixture.
const char* const kCommands[] = {
    "info",      "inspect",   "sections", "imports",  "exports",     "resources",
    "relocations", "segments", "symbols", "dynamic", "notes",
    "strings",   "hexdump",   "search",   "regions",  "size",        "deps",
    "graph",     "disasm",    "debug",    "crash",    "report",      "hash",
};

struct Fixture {
    const char* name;
    const char* file;
};

static const char* kFixtureDir =
    "tests/fixtures/executables/";

const Fixture kFixtures[] = {
    {"linux-x86_64", "linux-x86_64"},
    {"linux-i386", "linux-i386"},
    {"linux-arm", "linux-arm"},
    {"linux-aarch64", "linux-aarch64"},
    {"linux-riscv64", "linux-riscv64"},
    {"win32-i386", "win32-i386.exe"},
    {"win64-x86_64", "win64-x86_64.exe"},
    {"macho64-x86_64", "macho64-x86_64"},
    {"elf32-arm-be", "elf32-arm-be.elf"},
};

bool is_pe_like(std::string_view name) {
    return name.rfind("win", 0) == 0;
}
bool is_elf_like(std::string_view name) {
    return name.rfind("linux", 0) == 0 || name.rfind("elf", 0) == 0;
}

// Commands that are PE-only and must fail cleanly on non-PE inputs.
bool is_pe_only(std::string_view cmd) {
    return cmd == "imports" || cmd == "exports" || cmd == "resources";
}
// ELF-only commands.
bool is_elf_only(std::string_view cmd) {
    return cmd == "segments" || cmd == "dynamic" || cmd == "notes";
}

binx::Options make_options(const char* command, const fs::path& file) {
    const std::string file_string = file.string();
    const char* argv[] = {"binx", command, file_string.c_str(),
                          "--pattern", "90 90"};
    auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                      const_cast<char**>(argv));
    if (!parsed) {
        throw std::runtime_error("parse_options failed for " +
                                 std::string(command) + " " + file_string);
    }
    return parsed.value();
}

// Returns true when the command is expected to succeed on this fixture.
bool expected_success(std::string_view command, std::string_view name) {
    if (command == "crash")
        return false;  // no real dumps are included in the sweep
    if (is_pe_only(command))
        return is_pe_like(name);
    if (command == "sections" || command == "relocations")
        return is_pe_like(name) || is_elf_like(name);
    if (command == "symbols" || command == "debug")
        return is_pe_like(name) || is_elf_like(name);
    if (command == "disasm")
        return true;  // x86 decode of any bytes is valid output
    if (is_elf_only(command))
        return is_elf_like(name);
    return true;  // info/inspect/analysis/hash/report etc.
}

void run_sweep() {
    int pass = 0;
    int fail = 0;
    for (const auto& fixture : kFixtures) {
        const fs::path file = fs::path(kFixtureDir) / fixture.file;
        std::printf("== fixture: %s (%s) ==\n", fixture.name, file.string().c_str());
        if (!fs::exists(file)) {
            throw std::runtime_error("fixture file does not exist: " + file.string());
        }
        for (const char* command : kCommands) {
            auto options = make_options(command, file);
            auto result = binx::run_command(options);
            const bool want = expected_success(command, fixture.name);
            if ((static_cast<bool>(result) == want)) {
                ++pass;
            } else {
                ++fail;
                std::printf("  MISMATCH: %-12s file=%-14s rc=%s want=%s\n",
                            command, fixture.name,
                            result ? "success" : "error", want ? "success" : "format-error");
            }
        }
    }
    std::printf("SWEEP pass=%d fail=%d\n", pass, fail);
    if (fail != 0) {
        throw std::runtime_error("command × fixture sweep failed");
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc > 1) {
            kFixtureDir = argv[1];
        }
        run_sweep();
        std::printf("CLI SWEEP PASS\n");
        return 0;
    } catch (const std::exception& e) {
        std::printf("CLI SWEEP FAIL: %s\n", e.what());
        return 1;
    }
}