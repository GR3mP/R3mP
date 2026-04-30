// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license 
// (you can find the license file in the root folder).

#include "BigNum.h"

#include <openssl/bn.h>

namespace r3mp {

class BigNumContext::Impl {
 public:
  BN_CTX *big_num_context;

  ~Impl() {
    BN_CTX_free(big_num_context);
  }
};

} // namespace r3mp
