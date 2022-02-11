// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "sharing_randomness_generator.h"

namespace MOTION::Crypto {

SharingRandomnessGenerator::SharingRandomnessGenerator(std::size_t party_id)
    : party_id_(party_id), ctx_arithmetic_(MakeCipherCtx()), ctx_boolean_(MakeCipherCtx()) {
  if (!ctx_arithmetic_ || !ctx_boolean_) {
    throw(std::runtime_error(fmt::format("Could not initialize EVP context")));
  }
  initialized_condition_ =
      std::make_unique<ENCRYPTO::FiberCondition>([this]() { return initialized_; });
      std::cout<<"inside sharing randomness generator.cpp"<<std::endl;
      //std::fstream << &initialized_condition_.get()<<std::endl;
      std::cout << &initialized_condition_<<std::endl;
}

void SharingRandomnessGenerator::Initialize(
    const std::byte seed[SharingRandomnessGenerator::MASTER_SEED_BYTE_LENGTH]) {
  std::copy(seed, seed + MASTER_SEED_BYTE_LENGTH, std::begin(master_seed_));

  {
    auto digest = HashKey(master_seed_, KeyType::ArithmeticGMWKey);
    std::copy(digest.data(), digest.data() + AES_KEY_SIZE, raw_key_arithmetic_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::ArithmeticGMWNonce);
    std::copy(digest.data(), digest.data() + AES_BLOCK_SIZE / 2, aes_ctr_nonce_arithmetic_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::BooleanGMWKey);
    std::copy(digest.data(), digest.data() + AES_KEY_SIZE, raw_key_boolean_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::BooleanGMWNonce);
    std::copy(digest.data(), digest.data() + AES_BLOCK_SIZE / 2, aes_ctr_nonce_boolean_);
  }

  prg_a.SetKey(raw_key_arithmetic_);
  prg_b.SetKey(raw_key_boolean_);

  {
    std::scoped_lock lock(initialized_condition_->GetMutex());
    initialized_ = true;
  }
  initialized_condition_->NotifyAll();
}

ENCRYPTO::BitVector<> SharingRandomnessGenerator::GetBits(const std::size_t gate_id,
                                                          const std::size_t num_of_bits) {
  std::scoped_lock lock(random_bits_mutex_);

  if (num_of_bits == 0) {
    return {};  // return an empty vector if num_of_gates is zero
  }

  while (!initialized_) {
    initialized_condition_->Wait();
  }

  constexpr std::size_t BITS_IN_CIPHERTEXT = AES_BLOCK_SIZE * 8;
  constexpr std::size_t CIPHERTEXTS_IN_BATCH = 100;
  // initialization for the encryption is costly, so perform random bit generation in a batch
  constexpr std::size_t BITS_IN_BATCH = BITS_IN_CIPHERTEXT * CIPHERTEXTS_IN_BATCH;
  constexpr std::size_t BYTES_IN_BATCH = BITS_IN_BATCH / 8;

  while (random_bits_.GetSize() < (gate_id - random_bits_offset_ + num_of_bits)) {
    std::vector<std::byte> input(BYTES_IN_BATCH + AES_BLOCK_SIZE),
        output(BYTES_IN_BATCH + AES_BLOCK_SIZE);
    for (auto offset = random_bits_.GetSize() / AES_BLOCK_SIZE_; offset < CIPHERTEXTS_IN_BATCH;
         ++offset) {
      auto ptr = input.data() + offset * AES_BLOCK_SIZE_;
      // copy nonce
      std::copy(std::begin(aes_ctr_nonce_boolean_), std::end(aes_ctr_nonce_boolean_), ptr);
      // copy counter value
      *reinterpret_cast<uint64_t *>(ptr + AES_BLOCK_SIZE_ / 2) = offset;
    }

    // encrypt as in CTR mode, but without sequentially incrementing the counter
    // after each encryption
    std::vector<std::byte> output_bytes =
        prg_b.Encrypt(input.data(), CIPHERTEXTS_IN_BATCH * AES_BLOCK_SIZE);

    for (auto i = 0ull; i < BYTES_IN_BATCH; ++i) {
      output_bytes.push_back(std::byte(output.at(i)));
    }
    auto randomness = ENCRYPTO::BitVector(std::move(output_bytes), BITS_IN_BATCH);
    random_bits_.Append(randomness);
  }

  const auto requested = gate_id - random_bits_offset_ + num_of_bits;
  if (requested > random_bits_used_) {
    random_bits_used_ = requested;
  }

  assert(gate_id >= random_bits_offset_);
  return random_bits_.Subset(gate_id - random_bits_offset_,
                             gate_id + num_of_bits - random_bits_offset_);
}

std::vector<std::byte> SharingRandomnessGenerator::HashKey(
    const std::byte seed[MASTER_SEED_BYTE_LENGTH], const KeyType key_type) {
  std::uint32_t key_type32 = key_type;
  std::vector<std::byte> seed_padded(sizeof(key_type32) + MASTER_SEED_BYTE_LENGTH);
  std::copy_n(reinterpret_cast<const std::byte *>(&key_type32), sizeof(key_type32),
              std::begin(seed_padded));
  std::copy_n(seed, MASTER_SEED_BYTE_LENGTH, &seed_padded[sizeof(key_type32)]);
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  std::byte digest[EVP_MAX_MD_SIZE];
  unsigned int md_len;

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL)
  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
#else
  EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL);
#endif

  EVP_DigestUpdate(mdctx, seed_padded.data(), seed_padded.size());
  EVP_DigestFinal_ex(mdctx, reinterpret_cast<unsigned char *>(digest), &md_len);
  EVP_MD_CTX_free(mdctx);

  return std::vector<std::byte>(digest, digest + AES_KEY_SIZE);
}

std::vector<std::byte> SharingRandomnessGenerator::GetSeed() {
  return std::vector<std::byte>(master_seed_, master_seed_ + sizeof(master_seed_));
}

void SharingRandomnessGenerator::ClearBitPool() { random_bits_ = ENCRYPTO::BitVector<>(); }

void SharingRandomnessGenerator::ResetBitPool() {
  if (random_bits_used_ == random_bits_.GetSize()) {
    random_bits_.Clear();
  } else {
    random_bits_ = random_bits_.Subset(random_bits_used_, random_bits_.GetSize() - 1);
  }
  random_bits_offset_ += random_bits_used_;
  random_bits_used_ = 0;
}
}
