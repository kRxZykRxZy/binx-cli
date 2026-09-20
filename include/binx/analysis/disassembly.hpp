#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "binx/core/binary.hpp"
#include "binx/error.hpp"
namespace binx {
enum class DisassemblySyntax { Intel, Att };
struct DisassemblyOptions { std::uint64_t offset=0; std::size_t count=100; std::size_t max_bytes=0; bool from_entry=false; DisassemblySyntax syntax=DisassemblySyntax::Intel; };
struct Instruction { std::uint64_t address=0,file_offset=0; std::vector<std::byte> bytes; std::string mnemonic,operands; bool valid=true,branch=false; std::optional<std::uint64_t> branch_target; };
struct DisassemblyBlock { std::string section; std::uint64_t file_offset=0,virtual_address=0,size=0; std::vector<Instruction> instructions; };
Result<std::vector<Instruction>> disassemble_x86(std::span<const std::byte>,std::uint64_t,std::uint64_t,std::size_t,DisassemblySyntax=DisassemblySyntax::Intel);
Result<std::vector<DisassemblyBlock>> disassemble_file(const BinaryFile&,const DisassemblyOptions&);
std::string format_disassembly(const std::vector<DisassemblyBlock>&,bool,DisassemblySyntax);
}