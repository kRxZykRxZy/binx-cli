#include "binx/cli/io.hpp"
#include <fstream>
#include <iostream>

namespace binx {

Result<bool> write_command_output(const std::string& text,
                                  bool quiet,
                                  bool has_output,
                                  const std::filesystem::path& output_path) {
    if (quiet) return true;

    if (!has_output) {
        std::cout << text;
        if (!std::cout) {
            return Error{ErrorCode::FileAccess, "failed while writing standard output"};
        }
        return true;
    }

    std::ofstream file(output_path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return Error{ErrorCode::FileAccess,
                     "unable to open output file '" + output_path.string() + "'"};
    }
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!file) {
        return Error{ErrorCode::FileAccess,
                     "failed while writing output file '" + output_path.string() + "'"};
    }
    return true;
}

} // namespace binx
