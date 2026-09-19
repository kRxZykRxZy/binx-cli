#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "binx/error.hpp"

namespace binx {

enum class BinaryFormat { Unknown, Raw, PE32, PE64, ELF32, ELF64, MachO32, MachO64, MachOFat };
enum class Architecture { Unknown, X86, X86_64, ARM, ARM64, RISCV32, RISCV64 };
enum class Endianness { Unknown, Little, Big };

struct Metadata {
    BinaryFormat format = BinaryFormat::Unknown;
    Architecture architecture = Architecture::Unknown;
    Endianness endianness = Endianness::Unknown;
    std::uint64_t file_size = 0;
    std::optional<std::uint64_t> entry_point;
    std::optional<std::uint64_t> image_base;
    std::optional<std::uint32_t> raw_machine;
    std::optional<std::uint32_t> section_count;
    std::string platform;
};

class BinaryFile {
public:
    static Result<BinaryFile> open(const std::filesystem::path& path);

    const std::filesystem::path& path() const noexcept { return path_; }
    std::span<const std::byte> bytes() const noexcept { return bytes_; }
    std::uint64_t size() const noexcept { return bytes_.size(); }
    const Metadata& metadata() const noexcept { return metadata_; }

private:
    std::filesystem::path path_;
    std::vector<std::byte> storage_;
    std::span<const std::byte> bytes_;
    Metadata metadata_;
};

}
