#include "binx/hashing/hasher.hpp"
#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <vector>
#ifdef _WIN32
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif
namespace binx {
namespace {
std::string hex(const unsigned char*p,std::size_t n){std::ostringstream s;s<<std::hex<<std::setfill('0');for(std::size_t i=0;i<n;++i)s<<std::setw(2)<<static_cast<unsigned int>(p[i]);return s.str();}
#ifdef _WIN32
Result<std::string> cng_hash(std::span<const std::byte>d,LPCWSTR alg,std::size_t digest_size){
 BCRYPT_ALG_HANDLE provider=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
 NTSTATUS status=BCryptOpenAlgorithmProvider(&provider,alg,nullptr,0);
 if(status<0)return Error{ErrorCode::Analysis,"failed to open Windows CNG hash provider"};
 status=BCryptCreateHash(provider,&hash,nullptr,0,nullptr,0,0);
 if(status<0){BCryptCloseAlgorithmProvider(provider,0);return Error{ErrorCode::Analysis,"failed to create Windows CNG hash state"};}
 std::size_t off=0;
 while(off<d.size()){const auto chunk=std::min<std::size_t>(d.size()-off,static_cast<std::size_t>(std::numeric_limits<ULONG>::max()));
  status=BCryptHashData(hash,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(d.data()+off)),static_cast<ULONG>(chunk),0);
  if(status<0){BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(provider,0);return Error{ErrorCode::Analysis,"Windows CNG hash operation failed"};}off+=chunk;}
 std::vector<unsigned char>out(digest_size);status=BCryptFinishHash(hash,out.data(),static_cast<ULONG>(out.size()),0);
 BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(provider,0);
 if(status<0)return Error{ErrorCode::Analysis,"Windows CNG hash finalization failed"};return hex(out.data(),out.size());
}
#else
Result<std::string> evp_hash(std::span<const std::byte>d,const EVP_MD*alg){
 EVP_MD_CTX*ctx=EVP_MD_CTX_new();if(!ctx)return Error{ErrorCode::Analysis,"failed to create OpenSSL digest context"};
 unsigned char out[EVP_MAX_MD_SIZE];unsigned int n=0;
 const bool ok=EVP_DigestInit_ex(ctx,alg,nullptr)==1&&EVP_DigestUpdate(ctx,reinterpret_cast<const unsigned char*>(d.data()),d.size())==1&&EVP_DigestFinal_ex(ctx,out,&n)==1;
 EVP_MD_CTX_free(ctx);if(!ok)return Error{ErrorCode::Analysis,"OpenSSL digest operation failed"};return hex(out,n);
}
#endif
}
Result<Hashes> hash_all(std::span<const std::byte>d){
#ifdef _WIN32
 auto md5=cng_hash(d,BCRYPT_MD5_ALGORITHM,16);if(!md5)return md5.error();auto sha1=cng_hash(d,BCRYPT_SHA1_ALGORITHM,20);if(!sha1)return sha1.error();auto sha256=cng_hash(d,BCRYPT_SHA256_ALGORITHM,32);if(!sha256)return sha256.error();
#else
 auto md5=evp_hash(d,EVP_md5());if(!md5)return md5.error();auto sha1=evp_hash(d,EVP_sha1());if(!sha1)return sha1.error();auto sha256=evp_hash(d,EVP_sha256());if(!sha256)return sha256.error();
#endif
 return Hashes{md5.value(),sha1.value(),sha256.value()};
}
}
