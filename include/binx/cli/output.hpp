#pragma once
#include <string>
#include "binx/core/binary.hpp"
#include "binx/formats/pe.hpp"
#include "binx/formats/elf.hpp"
#include "binx/hashing/hasher.hpp"
namespace binx {
std::string format_help();
std::string format_version();
std::string format_info(const BinaryFile&, bool json, bool detailed);
std::string format_pe_command(const PEImage&, const std::string& command, bool json, bool detailed);
std::string format_elf_command(const ELFImage&, const std::string& command, bool json, bool detailed);
std::string format_hashes(const Hashes&, bool json);
}
