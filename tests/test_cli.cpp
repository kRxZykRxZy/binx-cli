#include "binx/cli/options.hpp"
#include "binx/cli/commands.hpp"
#include "binx/core/text.hpp"
#include <cassert>
#include <string>

int main() {
    {
        const char* argv[] = {"binx", "strings", "sample.bin", "--json",
                              "--encoding", "all", "--min-length", "8",
                              "--max-results", "12"};
        auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                           const_cast<char**>(argv));
        assert(parsed);
        assert(parsed.value().command == "strings");
        assert(parsed.value().json);
        assert(parsed.value().encoding == "all");
        assert(parsed.value().min_length == 8);
        assert(parsed.value().max_results == 12);
    }

    {
        const char* argv[] = {"binx", "diff", "old.bin", "new.bin", "--output", "out.json"};
        auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                           const_cast<char**>(argv));
        assert(parsed);
        assert(parsed.value().has_second_input);
        assert(parsed.value().input == "old.bin");
        assert(parsed.value().second_input == "new.bin");
        assert(parsed.value().has_output);
    }

    {
        const char* argv[] = {"binx", "graph", "app.exe", "--dot", "--json"};
        auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                           const_cast<char**>(argv));
        assert(parsed);
        assert(parsed.value().dot);
        assert(!parsed.value().json);
    }

    {
        const char* argv[] = {"binx", "disasm", "app.exe", "--syntax", "att",
                              "--count", "32", "--from-entry"};
        auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                           const_cast<char**>(argv));
        assert(parsed);
        assert(parsed.value().syntax == binx::DisassemblySyntax::Att);
        assert(parsed.value().count == 32);
        assert(parsed.value().from_entry);
    }

    {
        const char* argv[] = {"binx", "--help"};
        auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                           const_cast<char**>(argv));
        assert(parsed && parsed.value().command == "help");
    }

    {
        const char* argv[] = {"binx", "strings", "x", "--width", "0"};
        auto parsed = binx::parse_options(static_cast<int>(std::size(argv)),
                                           const_cast<char**>(argv));
        assert(!parsed && parsed.error().code == binx::ErrorCode::InvalidArguments);
    }

    assert(binx::is_supported_command("report"));
    assert(binx::is_supported_command("analyze"));
    assert(binx::is_diff_command("compare"));
    assert(binx::is_disassembly_command("disasm"));
    assert(!binx::is_supported_command("not-a-command"));

    assert(binx::json_escape("\"") == "\\\"");
    assert(binx::json_escape("\\") == "\\\\");
    assert(binx::json_escape("\n") == "\\n");
    assert(binx::hex_u64(0x1234) == "0x1234");
    assert(binx::hex_u64(0xABCD, false) == "0xabcd");
    return 0;
}
