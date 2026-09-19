#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace binx {

class ByteReader {
public:
    explicit ByteReader(std::span<const std::byte> data) : data_(data) {}

    std::size_t position() const noexcept { return pos_; }
    std::size_t size() const noexcept { return data_.size(); }
    bool can_read(std::size_t n) const noexcept { return n <= data_.size() - pos_; }
    void seek(std::size_t offset);

    std::uint8_t u8();
    std::uint16_t u16_le();
    std::uint32_t u32_le();
    std::uint64_t u64_le();
    std::uint16_t u16_be();
    std::uint32_t u32_be();
    std::uint64_t u64_be();

private:
    void require(std::size_t n) const;
    std::span<const std::byte> data_;
    std::size_t pos_ = 0;
};

}
