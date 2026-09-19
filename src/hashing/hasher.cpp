#include "binx/hashing/hasher.hpp"
#include <iomanip>
#include <sstream>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace binx {
#ifdef _WIN32
static std::string hex(const std::vector<unsigned char>& v) {
    std::ostringstream s; s<<std::hex<<std::setfill('0');
    for(auto b:v) s<<std::setw(2)<<unsigned(b);
    return s.str();
}
static Result<std::string> cng(std::span<const std::byte> data, LPCWSTR alg, ULONG digest_len) {
    BCRYPT_ALG_HANDLE h=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    NTSTATUS st=BCryptOpenAlgorithmProvider(&h,alg,nullptr,0);
    if(st<0) return Error{ErrorCode::Analysis,"failed to open Windows CNG hash provider"};
    std::vector<unsigned char> out(digest_len);
    st=BCryptCreateHash(h,&hash,nullptr,0,nullptr,0,0);
    if(st>=0) st=BCryptHashData(hash,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())),static_cast<ULONG>(data.size()),0);
    if(st>=0) st=BCryptFinishHash(hash,out.data(),digest_len,0);
    if(hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(h,0);
    if(st<0) return Error{ErrorCode::Analysis,"Windows CNG hash operation failed"};
    return hex(out);
}
Result<Hashes> hash_all(std::span<const std::byte> data) {
    auto md5=cng(data,BCRYPT_MD5_ALGORITHM,16); if(!md5) return md5.error();
    auto sha1=cng(data,BCRYPT_SHA1_ALGORITHM,20); if(!sha1) return sha1.error();
    auto sha256=cng(data,BCRYPT_SHA256_ALGORITHM,32); if(!sha256) return sha256.error();
    return Hashes{md5.value(),sha1.value(),sha256.value()};
}
#else
Result<Hashes> hash_all(std::span<const std::byte>) {
    return Error{ErrorCode::Analysis,"v0.1 hashing backend currently requires Windows CNG"};
}
#endif
}
