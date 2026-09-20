#include "binx/cli/dependency_output.hpp"
#include "binx/core/text.hpp"
#include "binx/formats/detect.hpp"
#include <sstream>

namespace binx {

std::string format_dependencies(const std::vector<Dependency>& values, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\"schema_version\":5,\"dependencies\":[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i) out << ",";
            const auto& dep = values[i];
            out << "{\"name\":\"" << json_escape(dep.name)
                << "\",\"kind\":\"" << json_escape(dependency_kind_name(dep.kind))
                << "\",\"weak\":" << (dep.weak ? "true" : "false")
                << ",\"reexport\":" << (dep.reexport ? "true" : "false") << "}";
        }
        out << "]}\n";
        return out.str();
    }

    out << "DEPENDENCIES\n";
    for (const auto& dep : values) {
        out << "  " << dep.name << " [" << dependency_kind_name(dep.kind) << "]";
        if (dep.weak) out << " weak";
        if (dep.reexport) out << " reexport";
        out << "\n";
    }
    return out.str();
}

std::string format_dependency_graph(const DependencyGraph& graph, bool json) {
    std::ostringstream out;
    if (json) {
        out << "{\"schema_version\":5,\"nodes\":[";
        for (std::size_t i = 0; i < graph.nodes.size(); ++i) {
            if (i) out << ",";
            const auto& node = graph.nodes[i];
            out << "{\"id\":" << node.id
                << ",\"path\":\"" << json_escape(node.path.string())
                << "\",\"format\":\"" << json_escape(format_name(node.format))
                << "\",\"architecture\":\"" << json_escape(architecture_name(node.architecture))
                << "\",\"file_size\":" << node.file_size
                << ",\"resolved\":" << (node.resolved ? "true" : "false") << "}";
        }
        out << "],\"edges\":[";
        for (std::size_t i = 0; i < graph.edges.size(); ++i) {
            if (i) out << ",";
            const auto& edge = graph.edges[i];
            out << "{\"from\":" << edge.from << ",\"to\":" << edge.to
                << ",\"dependency\":\"" << json_escape(edge.dependency.name)
                << "\",\"kind\":\"" << json_escape(dependency_kind_name(edge.dependency.kind))
                << "\"}";
        }
        out << "],\"unresolved\":[";
        for (std::size_t i = 0; i < graph.unresolved.size(); ++i) {
            if (i) out << ",";
            out << "\"" << json_escape(graph.unresolved[i]) << "\"";
        }
        out << "],\"cycles\":[";
        for (std::size_t i = 0; i < graph.cycles.size(); ++i) {
            if (i) out << ",";
            out << "[";
            for (std::size_t j = 0; j < graph.cycles[i].size(); ++j) {
                if (j) out << ",";
                out << graph.cycles[i][j];
            }
            out << "]";
        }
        out << "]}\n";
        return out.str();
    }

    out << "DEPENDENCY GRAPH\n\nNODES\n";
    for (const auto& node : graph.nodes) {
        out << "  [" << node.id << "] " << node.path.string()
            << " (" << format_name(node.format) << ", "
            << architecture_name(node.architecture) << ")\n";
    }

    out << "\nEDGES\n";
    for (const auto& edge : graph.edges) {
        out << "  [" << edge.from << "] -> [" << edge.to << "] "
            << edge.dependency.name << " [" << dependency_kind_name(edge.dependency.kind) << "]\n";
    }

    if (!graph.unresolved.empty()) {
        out << "\nUNRESOLVED\n";
        for (const auto& value : graph.unresolved) out << "  " << value << "\n";
    }

    if (!graph.cycles.empty()) {
        out << "\nCYCLES\n";
        for (const auto& cycle : graph.cycles) {
            out << "  ";
            for (std::size_t i = 0; i < cycle.size(); ++i) {
                if (i) out << " -> ";
                out << "[" << cycle[i] << "]";
            }
            out << "\n";
        }
    }
    return out.str();
}

} // namespace binx
