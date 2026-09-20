#pragma once
#include "binx/cli/options.hpp"

namespace binx {

Result<int> run_command(const Options& options);

} // namespace binx
