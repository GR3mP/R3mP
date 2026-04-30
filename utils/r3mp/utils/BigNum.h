// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license 
// (you can find the license file in the root folder).

#pragma once

#include <memory>

namespace r3mp {

class BigNumContext {
 public:
  BigNumContext();
  BigNumContext(const BigNumContext &) = delete;
  BigNumContext &operator=(const BigNumContext &) = delete;
  BigNumContext(BigNumContext &&other) noexcept;
  BigNumContext &operator=(BigNumContext &&other) noexcept;
  ~BigNumContext();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;

  friend class BigNum;
};

class BigNum {};

} // namespace r3mp
