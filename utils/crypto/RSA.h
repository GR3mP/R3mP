// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license 
// (you can find the license file in the root folder).

#pragma once

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <vector>
#include <memory>
#include <stdexcept>

namespace r3mp {
namespace crypto {

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

class RSA {
public:
    static constexpr int DEFAULT_RSA_BITS = 4096;

    RSA() : pkey_(nullptr, EVP_PKEY_free) {}

    // key gen (4096)
    void generate(int bits = DEFAULT_RSA_BITS) {
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) 
            throw std::runtime_error("RSA init failed");

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
            throw std::runtime_error("RSA bits setting failed");

        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0)
            throw std::runtime_error("RSA generation failed");

        pkey_.reset(raw_pkey);
    }

    // create RSA_PSS
    std::vector<uint8_t> sign(const std::vector<uint8_t>& digest) {
        size_t sig_len = 0;
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr), EVP_PKEY_CTX_free);

        if (EVP_PKEY_sign_init(ctx.get()) <= 0) throw std::runtime_error("Sign init failed");

        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), RSA_PSS_SALTLEN_DIGEST);

        EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, digest.data(), digest.size());
        std::vector<uint8_t> signature(sig_len);

        if (EVP_PKEY_sign(ctx.get(), signature.data(), &sig_len, digest.data(), digest.size()) <= 0)
            throw std::runtime_error("Signing failed");

        return signature;
    }

    // verify RSA-PSS
    bool verify(const std::vector<uint8_t>& digest, const std::vector<uint8_t>& signature) {
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr), EVP_PKEY_CTX_free);

        if (EVP_PKEY_verify_init(ctx.get()) <= 0) return false;

        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), RSA_PSS_SALTLEN_DIGEST);

        return EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(), digest.data(), digest.size()) == 1;
    }

private:
    EVP_PKEY_ptr pkey_;
};

} // namespace crypto
} // namespace r3mp

