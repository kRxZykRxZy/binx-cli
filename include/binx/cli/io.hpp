#pragma once
#include <filesystem>
#include <string>
#include "binx/error.hpp"

namespace binx {

Result<bool> write_command_output(const std::string& text,
                                  bool quiet,
                                  bool has_output,
                                  const std::filesystem::path& output_path);

} // namespace binx
