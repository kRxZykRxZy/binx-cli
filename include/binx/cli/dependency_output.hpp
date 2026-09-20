#pragma once
#include <string>
#include "binx/analysis/dependencies.hpp"
namespace binx { std::string format_dependencies(const std::vector<Dependency>&,bool); std::string format_dependency_graph(const DependencyGraph&,bool); }
