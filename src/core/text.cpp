#include "binx/core/text.hpp"
#include <iomanip>
#include <sstream>

namespace binx {

std::string json_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value) {
        switch (c) {
        case '"': out += "\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                std::ostringstream escaped;
                escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned int>(c);
                out += escaped.str();
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return out;
}

std::string hex_u64(std::uint64_t value, bool uppercase) {
    std::ostringstream out;
    out << "0x";
    if (uppercase) out << std::uppercase;
    out << std::hex << value;
    return out.str();
}

} // namespace binx
