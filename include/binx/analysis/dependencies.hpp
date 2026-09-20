#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "binx/core/binary.hpp"
#include "binx/formats/pe.hpp"
namespace binx {
enum class DependencyKind { PEImport, ELFNeeded, MachODylib };
struct Dependency { std::string name; DependencyKind kind{}; bool weak=false; bool reexport=false; };
struct DependencyNode { std::size_t id=0; std::filesystem::path path; BinaryFormat format=BinaryFormat::Unknown; Architecture architecture=Architecture::Unknown; std::uint64_t file_size=0; bool resolved=false; };
struct DependencyEdge { std::size_t from=0,to=0; Dependency dependency; };
struct DependencyGraph { std::vector<DependencyNode> nodes; std::vector<DependencyEdge> edges; std::vector<std::string> unresolved; std::vector<std::vector<std::size_t>> cycles; };
std::vector<Dependency> extract_dependencies(const BinaryFile&);
Result<DependencyGraph> build_dependency_graph(const std::filesystem::path& root,
                                               const std::vector<std::filesystem::path>& search_paths,
                                               std::size_t max_depth=8, std::size_t max_nodes=256);
std::string dependency_kind_name(DependencyKind);
std::string dependency_graph_dot(const DependencyGraph&);
std::string normalize_library_name(const std::string&);
}
