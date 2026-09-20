#include "binx/core/byte_reader.hpp"

namespace binx {
void ByteReader::require(std::size_t n) const {
    if (!can_read(n)) throw std::out_of_range("binary read exceeds file bounds");
}
void ByteReader::seek(std::size_t offset) {
    if (offset > data_.size()) throw std::out_of_range("seek exceeds file bounds");
    pos_ = offset;
}
std::uint8_t ByteReader::u8() {
    require(1); return std::to_integer<std::uint8_t>(data_[pos_++]);
}
std::uint16_t ByteReader::u16_le() {
    require(2); auto a=u8(); auto b=u8(); return static_cast<std::uint16_t>(std::uint32_t(a) | (std::uint32_t(b) << 8));
}
std::uint32_t ByteReader::u32_le() {
    require(4); auto a=u16_le(); auto b=u16_le(); return std::uint32_t(a)|(std::uint32_t(b)<<16);
}
std::uint64_t ByteReader::u64_le() {
    require(8); auto a=u32_le(); auto b=u32_le(); return std::uint64_t(a)|(std::uint64_t(b)<<32);
}
std::uint16_t ByteReader::u16_be() {
    require(2); auto a=u8(); auto b=u8(); return static_cast<std::uint16_t>((std::uint32_t(a) << 8) | std::uint32_t(b));
}
std::uint32_t ByteReader::u32_be() {
    require(4); auto a=u16_be(); auto b=u16_be(); return (std::uint32_t(a)<<16)|b;
}
std::uint64_t ByteReader::u64_be() {
    require(8); auto a=u32_be(); auto b=u32_be(); return (std::uint64_t(a)<<32)|b;
}
}
