#include "binx/core/binary.hpp"
#include "binx/formats/detect.hpp"
#include <fstream>
#include <limits>

namespace binx {
Result<BinaryFile> BinaryFile::open(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        if (!std::filesystem::exists(path)) return Error{ErrorCode::FileNotFound, "file does not exist"};
        return Error{ErrorCode::FileAccess, "unable to open file"};
    }
    const auto end = f.tellg();
    if (end < 0) return Error{ErrorCode::FileAccess, "unable to determine file size"};
    const auto n = static_cast<std::uint64_t>(end);
    if (n > std::numeric_limits<std::size_t>::max()) return Error{ErrorCode::FileAccess, "file is too large for this build"};
    BinaryFile out;
    out.path_ = path;
    out.storage_.resize(static_cast<std::size_t>(n));
    f.seekg(0);
    if (n && !f.read(reinterpret_cast<char*>(out.storage_.data()), static_cast<std::streamsize>(n)))
        return Error{ErrorCode::FileAccess, "failed while reading file"};
    out.bytes_ = std::span<const std::byte>(out.storage_.data(), out.storage_.size());
    out.metadata_ = detect_metadata(out.bytes_);
    out.metadata_.file_size = n;
    return out;
}
}
