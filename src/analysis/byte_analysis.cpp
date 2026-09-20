#include "binx/analysis/byte_analysis.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <limits>
namespace binx {
namespace {
bool printable(unsigned char c){return c>=0x20&&c<=0x7e;}
std::string utf8_from_codepoint(std::uint32_t cp){std::string s;if(cp<=0x7f)s.push_back(char(cp));else if(cp<=0x7ff){s.push_back(char(0xc0|(cp>>6)));s.push_back(char(0x80|(cp&63)));}else if(cp<=0xffff){s.push_back(char(0xe0|(cp>>12)));s.push_back(char(0x80|((cp>>6)&63)));s.push_back(char(0x80|(cp&63)));}else{s.push_back(char(0xf0|(cp>>18)));s.push_back(char(0x80|((cp>>12)&63)));s.push_back(char(0x80|((cp>>6)&63)));s.push_back(char(0x80|(cp&63)));}return s;}
}
const char* string_encoding_name(StringEncoding e){switch(e){case StringEncoding::ASCII:return "ascii";case StringEncoding::UTF8:return "utf8";case StringEncoding::UTF16LE:return "utf16le";default:return "utf16be";}}
const char* region_kind_name(RegionKind k){switch(k){case RegionKind::Zero:return "zero";case RegionKind::Printable:return "printable";default:return "binary";}}
std::vector<ExtractedString> extract_strings(std::span<const std::byte>d,StringEncoding e,std::size_t min,std::size_t max){
 std::vector<ExtractedString> out;
 auto add=[&](std::uint64_t off,StringEncoding enc,std::string s){if(s.size()>=min&&(max==0||out.size()<max))out.push_back({off,enc,std::move(s)});};
 if(e==StringEncoding::ASCII||e==StringEncoding::UTF8){std::size_t i=0;while(i<d.size()&&(max==0||out.size()<max)){if(!printable(std::to_integer<unsigned char>(d[i]))){++i;continue;}auto start=i;std::string s;while(i<d.size()&&printable(std::to_integer<unsigned char>(d[i])))s.push_back(char(std::to_integer<unsigned char>(d[i++] )));add(start,e,std::move(s));}}
 else {const bool le=e==StringEncoding::UTF16LE;for(std::size_t i=0;i+1<d.size()&&(max==0||out.size()<max);){auto a=std::to_integer<unsigned char>(d[i]),b=std::to_integer<unsigned char>(d[i+1]);std::uint16_t cp=le?std::uint16_t(a|b<<8):std::uint16_t(b|a<<8);if(cp<0x20||cp>0x7e){i+=2;continue;}auto start=i;std::string s;while(i+1<d.size()){a=std::to_integer<unsigned char>(d[i]);b=std::to_integer<unsigned char>(d[i+1]);cp=le?std::uint16_t(a|b<<8):std::uint16_t(b|a<<8);if(cp<0x20||cp>0x7e)break;s.push_back(char(cp));i+=2;}add(start,e,std::move(s));if(i==start)i+=2;}}
 return out;
}
std::vector<HexdumpLine> make_hexdump(std::span<const std::byte>d,std::uint64_t off,std::uint64_t len,std::size_t width){
 std::vector<HexdumpLine> out;if(width==0)return out;if(off>d.size())return out;auto n=std::min<std::uint64_t>(len,d.size()-off);for(std::uint64_t p=off;p<off+n;p+=width){auto count=static_cast<std::size_t>(std::min<std::uint64_t>(width,off+n-p));HexdumpLine l;l.offset=p;l.bytes.reserve(count);for(std::size_t j=0;j<count;++j)l.bytes.push_back(std::to_integer<std::uint8_t>(d[static_cast<std::size_t>(p+j)]));out.push_back(std::move(l));}return out;
}
std::vector<SearchMatch> search_bytes(std::span<const std::byte>d,std::span<const std::byte>p,std::size_t max){
 std::vector<SearchMatch>out;if(p.empty()||p.size()>d.size())return out;for(std::size_t i=0;i+p.size()<=d.size()&&(max==0||out.size()<max);++i)if(std::equal(p.begin(),p.end(),d.begin()+static_cast<std::ptrdiff_t>(i)))out.push_back({i,p.size()});return out;
}
std::vector<SearchMatch> search_text(std::span<const std::byte>d,const std::string&s,StringEncoding e,std::size_t max){
 std::vector<std::byte> p;if(e==StringEncoding::ASCII||e==StringEncoding::UTF8){for(unsigned char c:s)p.push_back(std::byte{c});}else for(unsigned char c:s){auto cp=static_cast<std::uint16_t>(c);if(e==StringEncoding::UTF16LE){p.push_back(std::byte{static_cast<unsigned char>(cp&255)});p.push_back(std::byte{static_cast<unsigned char>(cp>>8)});}else{p.push_back(std::byte{static_cast<unsigned char>(cp>>8)});p.push_back(std::byte{static_cast<unsigned char>(cp&255)});}}return search_bytes(d,p,max);
}
bool parse_hex_pattern(const std::string&in,std::vector<int>&out){out.clear();std::string tok;std::istringstream ss(in);while(ss>>tok){if(tok=="??"||tok=="?"){out.push_back(-1);continue;}if(tok.size()!=2)return false;auto hex=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};int a=hex(tok[0]),b=hex(tok[1]);if(a<0||b<0)return false;out.push_back(a*16+b);}return !out.empty();}
std::vector<BinaryRegion> classify_regions(std::span<const std::byte>d,std::size_t min){
 std::vector<BinaryRegion>out;if(d.empty())return out;auto kind=[](unsigned char c){if(c==0)return RegionKind::Zero;if(printable(c)||c=='\n'||c=='\r'||c=='\t')return RegionKind::Printable;return RegionKind::Binary;};std::size_t start=0;auto k=kind(std::to_integer<unsigned char>(d[0]));for(std::size_t i=1;i<d.size();++i){auto nk=kind(std::to_integer<unsigned char>(d[i]));if(nk!=k){if(i-start>=min)out.push_back({start,i-start,k});start=i;k=nk;}}if(d.size()-start>=min)out.push_back({start,d.size()-start,k});return out;
}
}
