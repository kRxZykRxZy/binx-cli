#include "binx/cli/output.hpp"
#include "binx/cli/options.hpp"
#include "binx/cli/runner.hpp"
#include <iostream>

int main(int argc, char** argv) {
    auto options = binx::parse_options(argc, argv);
    if (!options) {
        std::cerr << "binx: " << options.error().message << "\n";
        std::cerr << binx::format_help();
        return static_cast<int>(options.error().code);
    }

    auto result = binx::run_command(options.value());
    if (!result) {
        std::cerr << "binx: " << result.error().message << "\n";
        return static_cast<int>(result.error().code);
    }
    return result.value();
}
