//in accorance with the interpretation of Ajith's Thesis
// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#include <openssl/bn.h>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include "gate.h"

#include "base/gate_factory.h"
#include "beavy_provider.h"
#include "crypto/arithmetic_provider.h"
#include "crypto/motion_base_provider.h"
#include "crypto/oblivious_transfer/ot_flavors.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/sharing_randomness_generator.h"
#include "utility/fiber_condition.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "wire.h"
#include "openssl/sha.h"
#include <sstream>
#include <string>
#include <iomanip>


#include <vector>
#include <type_traits>
#include <iostream>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h> //z_2^k[x]
#include <NTL/ZZ_pE.h> // z_2^k[x] / f[x]
#include <NTL/GF2.h>  //F_2
#include <NTL/GF2X.h>
#include <NTL/vec_GF2.h>
#define MAX64 std::numeric_limits<uint64_t>::max()


namespace MOTION::proto::beavy {

// Determine the total number of bits in a collection of wires.
static std::size_t count_bits(const BooleanBEAVYWireVector& wires) {
  return std::transform_reduce(std::begin(wires), std::end(wires), 0, std::plus<>(),
                               [](const auto& a) { return a->get_num_simd(); });
}

namespace detail {

BasicBooleanBEAVYBinaryGate::BasicBooleanBEAVYBinaryGate(std::size_t gate_id,
                                                         BooleanBEAVYWireVector&& in_b,
                                                         BooleanBEAVYWireVector&& in_a)
    : NewGate(gate_id),
      num_wires_(in_a.size()),
      inputs_a_(std::move(in_a)),
      inputs_b_(std::move(in_b)) {
  if (num_wires_ == 0) {
    throw std::logic_error("number of wires need to be positive");
  }
  if (num_wires_ != inputs_b_.size()) {
    throw std::logic_error("number of wires need to be the same for both inputs");
  }
  auto num_simd = inputs_a_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    if (inputs_a_[wire_i]->get_num_simd() != num_simd ||
        inputs_b_[wire_i]->get_num_simd() != num_simd) {
      throw std::logic_error("number of SIMD values need to be the same for all wires");
    }
  }
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanBEAVYWire>(num_simd); });
}

BasicBooleanBEAVYUnaryGate::BasicBooleanBEAVYUnaryGate(std::size_t gate_id,
                                                       BooleanBEAVYWireVector&& in, bool forward)
    : NewGate(gate_id), num_wires_(in.size()), inputs_(std::move(in)) {
  if (num_wires_ == 0) {
    throw std::logic_error("number of wires need to be positive");
  }
  auto num_simd = inputs_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    if (inputs_[wire_i]->get_num_simd() != num_simd) {
      throw std::logic_error("number of SIMD values need to be the same for all wires");
    }
  }
  if (forward) {
    outputs_ = inputs_;
  } else {
    outputs_.reserve(num_wires_);
    std::generate_n(std::back_inserter(outputs_), num_wires_,
                    [num_simd] { return std::make_shared<BooleanBEAVYWire>(num_simd); });
  }
}

}  // namespace detail

BooleanBEAVYInputGateSender::BooleanBEAVYInputGateSender(
    std::size_t gate_id, BEAVYProvider& beavy_provider, std::size_t num_wires, std::size_t num_simd,
    ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>>&& input_future)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      num_wires_(num_wires),
      num_simd_(num_simd),
      input_id_(beavy_provider.get_next_input_id(num_wires)),
      input_future_(std::move(input_future)) {
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanBEAVYWire>(num_simd); });
}

void BooleanBEAVYInputGateSender::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateSender::evaluate_setup start", gate_id_));
    }
  }

  auto my_id = beavy_provider_.get_my_id();
  auto num_parties = beavy_provider_.get_num_parties();
  auto& mbp = beavy_provider_.get_motion_base_provider();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire = outputs_[wire_i];
    wire->get_secret_share() = ENCRYPTO::BitVector<>::Random(num_simd_);
    wire->set_setup_ready();
    wire->get_public_share() = wire->get_secret_share();
    for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
      if (party_id == my_id) {
        continue;
      }
      auto& rng = mbp.get_my_randomness_generator(party_id);
      wire->get_public_share() ^= rng.GetBits(input_id_ + wire_i, num_simd_);
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateSender::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanBEAVYInputGateSender::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateSender::evaluate_online start", gate_id_));
    }
  }

  // wait for input value
  const auto inputs = input_future_.get();

  ENCRYPTO::BitVector<> public_shares;
  public_shares.Reserve(Helpers::Convert::BitsToBytes(num_wires_ * num_simd_));

  // compute my share
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& w_o = outputs_[wire_i];
    auto& public_share = w_o->get_public_share();
    const auto& input_bits = inputs.at(wire_i);
    if (input_bits.GetSize() != num_simd_) {
      throw std::runtime_error("size of input bit vector != num_simd_");
    }
    public_share ^= input_bits;
    w_o->set_online_ready();
    public_shares.Append(public_share);
  }
  beavy_provider_.broadcast_bits_message(gate_id_, public_shares);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateSender::evaluate_online end", gate_id_));
    }
  }
}

BooleanBEAVYInputGateReceiver::BooleanBEAVYInputGateReceiver(std::size_t gate_id,
                                                             BEAVYProvider& beavy_provider,
                                                             std::size_t num_wires,
                                                             std::size_t num_simd,
                                                             std::size_t input_owner)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      num_wires_(num_wires),
      num_simd_(num_simd),
      input_owner_(input_owner),
      input_id_(beavy_provider.get_next_input_id(num_wires)) {
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanBEAVYWire>(num_simd); });
  public_share_future_ =
      beavy_provider_.register_for_bits_message(input_owner_, gate_id_, num_wires * num_simd);
}

void BooleanBEAVYInputGateReceiver::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateReceiver::evaluate_setup start", gate_id_));
    }
  }

  auto& mbp = beavy_provider_.get_motion_base_provider();
  auto& rng = mbp.get_their_randomness_generator(input_owner_);
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire = outputs_[wire_i];
    wire->get_secret_share() = rng.GetBits(input_id_ + wire_i, num_simd_);
    wire->set_setup_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateReceiver::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanBEAVYInputGateReceiver::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateReceiver::evaluate_online start", gate_id_));
    }
  }

  auto public_shares = public_share_future_.get();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire = outputs_[wire_i];
    wire->get_public_share() = public_shares.Subset(wire_i * num_simd_, (wire_i + 1) * num_simd_);
    wire->set_online_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYInputGateReceiver::evaluate_online end", gate_id_));
    }
  }
}

BooleanBEAVYOutputGate::BooleanBEAVYOutputGate(std::size_t gate_id, BEAVYProvider& beavy_provider,
                                               BooleanBEAVYWireVector&& inputs,
                                               std::size_t output_owner)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      num_wires_(inputs.size()),
      output_owner_(output_owner),
      inputs_(std::move(inputs)) {
  std::size_t my_id = beavy_provider_.get_my_id();
  auto num_bits = count_bits(inputs_);
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    share_futures_ = beavy_provider_.register_for_bits_messages(gate_id_, num_bits);
  }
  my_secret_share_.Reserve(Helpers::Convert::BitsToBytes(num_bits));
}

ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>>
BooleanBEAVYOutputGate::get_output_future() {
  std::size_t my_id = beavy_provider_.get_my_id();
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    return output_promise_.get_future();
  } else {
    throw std::logic_error("not this parties output");
  }
}

void BooleanBEAVYOutputGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYOutputGate::evaluate_setup start", gate_id_));
    }
  }

  for (const auto& wire : inputs_) {
    wire->wait_setup();
    my_secret_share_.Append(wire->get_secret_share());
  }
  std::size_t my_id = beavy_provider_.get_my_id();
  if (output_owner_ != my_id) {
    if (output_owner_ == ALL_PARTIES) {
      beavy_provider_.broadcast_bits_message(gate_id_, my_secret_share_);
    } else {
      beavy_provider_.send_bits_message(output_owner_, gate_id_, my_secret_share_);
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYOutputGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanBEAVYOutputGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYOutputGate::evaluate_online start", gate_id_));
    }
  }

  std::size_t my_id = beavy_provider_.get_my_id();
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    std::size_t num_parties = beavy_provider_.get_num_parties();
    for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
      if (party_id == my_id) {
        continue;
      }
      const auto other_share = share_futures_[party_id].get();
      my_secret_share_ ^= other_share;
    }
    std::vector<ENCRYPTO::BitVector<>> outputs;
    outputs.reserve(num_wires_);
    std::size_t bit_offset = 0;
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto num_simd = inputs_[wire_i]->get_num_simd();
      auto& output =
          outputs.emplace_back(my_secret_share_.Subset(bit_offset, bit_offset + num_simd));
      inputs_[wire_i]->wait_online();
      output ^= inputs_[wire_i]->get_public_share();
      bit_offset += num_simd;
    }
    output_promise_.set_value(std::move(outputs));
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYOutputGate::evaluate_online end", gate_id_));
    }
  }
}

BooleanBEAVYINVGate::BooleanBEAVYINVGate(std::size_t gate_id, const BEAVYProvider& beavy_provider,
                                         BooleanBEAVYWireVector&& in)
    : detail::BasicBooleanBEAVYUnaryGate(gate_id, std::move(in),
                                         !beavy_provider.is_my_job(gate_id)),
      is_my_job_(beavy_provider.is_my_job(gate_id)) {}

void BooleanBEAVYINVGate::evaluate_setup() {
  if (!is_my_job_) {
    return;
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
    auto& w_o = outputs_[wire_i];
    w_o->get_secret_share() = ~w_in->get_secret_share();
    w_o->set_setup_ready();
  }
}

void BooleanBEAVYINVGate::evaluate_online() {
  if (!is_my_job_) {
    return;
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_online();
    auto& w_o = outputs_[wire_i];
    w_o->get_public_share() = w_in->get_public_share();
    w_o->set_online_ready();
  }
}

BooleanBEAVYXORGate::BooleanBEAVYXORGate(std::size_t gate_id, BEAVYProvider&,
                                         BooleanBEAVYWireVector&& in_a,
                                         BooleanBEAVYWireVector&& in_b)
    : detail::BasicBooleanBEAVYBinaryGate(gate_id, std::move(in_a), std::move(in_b)) {}

void BooleanBEAVYXORGate::evaluate_setup() {
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_a = inputs_a_[wire_i];
    const auto& w_b = inputs_b_[wire_i];
    w_a->wait_setup();
    w_b->wait_setup();
    auto& w_o = outputs_[wire_i];
    w_o->get_secret_share() = w_a->get_secret_share() ^ w_b->get_secret_share();
    w_o->set_setup_ready();
  }
}

void BooleanBEAVYXORGate::evaluate_online() {
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_a = inputs_a_[wire_i];
    const auto& w_b = inputs_b_[wire_i];
    w_a->wait_online();
    w_b->wait_online();
    auto& w_o = outputs_[wire_i];
    w_o->get_public_share() = w_a->get_public_share() ^ w_b->get_public_share();
    w_o->set_online_ready();
  }
}

BooleanBEAVYANDGate::BooleanBEAVYANDGate(std::size_t gate_id, BEAVYProvider& beavy_provider,
                                         BooleanBEAVYWireVector&& in_a,
                                         BooleanBEAVYWireVector&& in_b)
    : detail::BasicBooleanBEAVYBinaryGate(gate_id, std::move(in_a), std::move(in_b)),
      beavy_provider_(beavy_provider),
      ot_sender_(nullptr),
      ot_receiver_(nullptr) {
  auto num_bits = count_bits(inputs_a_);
  auto my_id = beavy_provider_.get_my_id();
  share_future_ = beavy_provider_.register_for_bits_message(1 - my_id, gate_id_, num_bits);
  auto& otp = beavy_provider_.get_ot_manager().get_provider(1 - my_id);
  ot_sender_ = otp.RegisterSendXCOTBit(num_bits);
  ot_receiver_ = otp.RegisterReceiveXCOTBit(num_bits);
}

BooleanBEAVYANDGate::~BooleanBEAVYANDGate() = default;

void BooleanBEAVYANDGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanBEAVYANDGate::evaluate_setup start", gate_id_));
    }
  }

  for (auto& wire_o : outputs_) {
    wire_o->get_secret_share() = ENCRYPTO::BitVector<>::Random(wire_o->get_num_simd());
    wire_o->set_setup_ready();
  }

  auto num_simd = inputs_a_[0]->get_num_simd();
  auto num_bytes = Helpers::Convert::BitsToBytes(num_wires_ * num_simd);
  delta_a_share_.Reserve(num_bytes);
  delta_b_share_.Reserve(num_bytes);
  Delta_y_share_.Reserve(num_bytes);

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_a = inputs_a_[wire_i];
    const auto& wire_b = inputs_b_[wire_i];
    const auto& wire_o = outputs_[wire_i];
    wire_a->wait_setup();
    wire_b->wait_setup();
    delta_a_share_.Append(wire_a->get_secret_share());
    delta_b_share_.Append(wire_b->get_secret_share());
    Delta_y_share_.Append(wire_o->get_secret_share());
  }

  auto delta_ab_share = delta_a_share_ & delta_b_share_;

  ot_receiver_->SetChoices(delta_a_share_);
  ot_receiver_->SendCorrections();
  ot_sender_->SetCorrelations(delta_b_share_);
  ot_sender_->SendMessages();
  ot_receiver_->ComputeOutputs();
  ot_sender_->ComputeOutputs();
  delta_ab_share ^= ot_sender_->GetOutputs();
  delta_ab_share ^= ot_receiver_->GetOutputs();
  Delta_y_share_ ^= delta_ab_share;

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanBEAVYANDGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanBEAVYANDGate::evaluate_online() {
  auto num_simd = inputs_a_[0]->get_num_simd();
  auto num_bits = num_wires_ * num_simd;
  ENCRYPTO::BitVector<> Delta_a;
  ENCRYPTO::BitVector<> Delta_b;
  Delta_a.Reserve(Helpers::Convert::BitsToBytes(num_bits));
  Delta_b.Reserve(Helpers::Convert::BitsToBytes(num_bits));

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_a = inputs_a_[wire_i];
    wire_a->wait_online();
    Delta_a.Append(wire_a->get_public_share());
    const auto& wire_b = inputs_b_[wire_i];
    wire_b->wait_online();
    Delta_b.Append(wire_b->get_public_share());
  }

  Delta_y_share_ ^= (Delta_a & delta_b_share_);
  Delta_y_share_ ^= (Delta_b & delta_a_share_);

  if (beavy_provider_.is_my_job(gate_id_)) {
    Delta_y_share_ ^= (Delta_a & Delta_b);
  }

  beavy_provider_.broadcast_bits_message(gate_id_, Delta_y_share_);
  Delta_y_share_ ^= share_future_.get();

  // distribute data among wires
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire_o = outputs_[wire_i];
    wire_o->get_public_share() = Delta_y_share_.Subset(wire_i * num_simd, (wire_i + 1) * num_simd);
    wire_o->set_online_ready();
  }
}

using namespace std;
using namespace NTL;

template <typename T>
ArithmeticBEAVYInputGateSender<T>::ArithmeticBEAVYInputGateSender(
        std::size_t gate_id, BEAVYProvider& beavy_provider, std::size_t num_simd,
        ENCRYPTO::ReusableFiberFuture<std::vector<T>>&& input_future)

    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      num_simd_(num_simd),
      input_id_(beavy_provider.get_next_input_id(1)),
      input_future_(std::move(input_future)),
      output_(std::make_shared<ArithmeticBEAVYWire<T>>(num_simd)) {
  output_->get_public_share().resize(num_simd, 0);  // SUVI
  // share_future_ = beavy_provider_.register_for_ints_message<T>(0, gate_id_,
                                                           // num_simd);
  std::cout << "_____________________________________________________________________________________________________GID " << gate_id << std::endl;
}

template <typename T>
void ArithmeticBEAVYInputGateSender<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYInputGateSender<T>::evaluate_setup start", gate_id_));
    }
  }
  std::cout <<" INVOKED ArithmeticBEAVYInputGateSender<T>::evaluate_setup() "<< gate_id_ <<std::endl;
  auto my_id = beavy_provider_.get_my_id();
  // std::cout<< "\n===========MAX value of uint64_t -----------\n"<<std::numeric_limits<uint64_t>::max()<<std::endl;

  auto num_parties = beavy_provider_.get_num_parties();
  auto& mbp = beavy_provider_.get_motion_base_provider();
  auto& my_secret_share = output_->get_secret_share(); //lambda_x1  //lambda_y2
  auto& my_public_share = output_->get_public_share(); //lambda_x2 //lambda_y1
  if (my_id==2){
      return;}

    auto& rng3 = mbp.get_my_randomness_generator(2);
    my_secret_share=rng3.GetUnsigned<T>(input_id_, num_simd_);   //x0 //y1
    //keep a copy to be needed in Mult
    output_->get_secret_share_0()= my_secret_share;
    output_->get_secret_share()=my_secret_share;

    std::cout<<" \n --------------data type my_secret_share --------------------"<< typeid(my_secret_share).name() <<std::endl;
    if(my_id==0){
      for(int i = 0; i < my_secret_share.size(); i++) {
        std::cout <<"my_id="<< my_id << " SENDER FUNCTION:: lambda_x0 "<< my_secret_share[i]<<" " <<std::endl;
      }
    }else if(my_id ==1){
        for(int i = 0; i < my_secret_share.size(); i++) {
          std::cout <<"my_id="<< my_id << " SENDER FUNCTION:: lambda_y1  "<< my_secret_share[i]<<" " <<std::endl;
      }
    }




 // "________________________________________________________________________________________________________________________" << std::endl;
  output_->set_setup_ready();
  std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
  my_public_share = my_secret_share;

    auto& rng = mbp.get_my_randomness_generator(my_id); //all of P0, p1, p2 are gonna sample the 2nd share.

    std::transform(std::begin(my_public_share), std::end(my_public_share),
                   std::begin(rng.GetUnsigned<T>(input_id_, num_simd_)),
                   std::begin(my_public_share), std::plus{});
    output_->get_secret_share_1()=rng.GetUnsigned<T>(input_id_, num_simd_);
    if(my_id==0){
      for(int i = 0; i < output_->get_secret_share_1().size(); i++) {
        std::cout <<"my_id="<< my_id << " SENDER Fucntion:: my public share= lambda_x1 "<< output_->get_secret_share_1()[i]<<" " <<std::endl;
      }
    }else if(my_id==1){
      for(int i = 0; i < output_->get_secret_share_1().size(); i++) {
        std::cout <<"my_id="<< my_id << " SENDER Fucntion:: my public share= lambda_y0 "<< output_->get_secret_share_1()[i]<<" " <<std::endl;
      }
    }


  // auto temp=rng.GetUnsigned<T>(input_id_, num_simd_);
  // std::cout<<"In the end of InputGateSender Evaluate Setup, size of Ranomness Generator = " << "\t .size() = " << temp.size() << "\t sizeof()\ = " << sizeof(temp) << std::endl;


    //invoking the 3rd seed to for p1 and P2 to hold
    auto& rngExtra = mbp.get_my_randomness_generator(1-my_id); //just to invoke the 3rd seed
    output_->get_public_share_2()=rngExtra.GetUnsigned<T>(input_id_, num_simd_);

    if(my_id==0){
      for(int i = 0; i < output_->get_public_share_2().size(); i++) {
        std::cout <<"my_id="<< my_id << " SENDER Fucntion:: lambda_x2 "<< output_->get_public_share_2()[i]<<" " <<std::endl;
      }
    }else if(my_id==1){
      for(int i = 0; i < output_->get_public_share_2().size(); i++) {
        std::cout <<"my_id="<< my_id << " SENDER Fucntion:: lambda_y2 "<< output_->get_public_share_2()[i]<<" " <<std::endl;
      }
    }
    std::transform(std::begin(my_public_share), std::end(my_public_share),
                   std::begin(rngExtra.GetUnsigned<T>(input_id_, num_simd_)),
                   std::begin(my_public_share), std::plus{});
    //full mask = lambda_x = lambda_x0 + lambda_x1 + lambda_x2
    //dont add the extra share since does not add to the computation or communication complexity
    //ASSUMing honest Verifier

  std::cout <<" ArithmeticBEAVYInputGateSArithmeticBEAVYInputGateSenderender<T>::evaluate_setup() - THE END"<<"\n" <<std::endl;
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYInputGateSender<T>::evaluate_setup end", gate_id_));
    }
  }
}
//------------------------added-----------------
template <typename T>
std::string ArithmeticBEAVYInputGateSender<T>::sha256(std::string st)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, st.c_str(), st.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}
//---------------------added------------------------

template <typename T>
void ArithmeticBEAVYInputGateSender<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYInputGateSender<T>::evaluate_online start", gate_id_));
    }
  }

  // wait for input value
  // output_->wait_setup();
  auto my_id = beavy_provider_.get_my_id();

  // wait for input value
  const auto input = input_future_.get(); //x or y got
  if (input.size() != num_simd_) {
    throw std::runtime_error("size of input bit vector != num_simd_");
  }
  std::cout <<" void ArithmeticBEAVYInputGateSender<T>::evaluate_online()"<<" " <<std::endl;

  if (my_id==2){
  //   std::cout << "GATE ID ++++++++++++++++++++++++++++++++++++++++ " << gate_id_ << std::endl;
  //   beavy_provider_.joint_send_verify_ints_message(0,1,2, input_id_, input, num_simd_, 1);
    output_->set_online_ready();
    return;
  }

    // compute my share
    auto& my_public_share = output_->get_public_share(); //output.my_public_share = lambda_x0 or
    std::transform(std::begin(my_public_share), std::end(my_public_share), std::begin(input), //masked x= x + masking of x //Big Delta x= x + Lambda_x
                   std::begin(my_public_share), std::plus{}); //

      //public_share = secret share = lambdax0; public share= public share + public share = lambdax0 + lambda x1 = lambdax.
      //public share + input = lambdax + x  = mx
     for(int i = 0; i < my_public_share.size(); i++) {
       std::cout <<"my_id="<< my_id << " my_public_share= bigDelta0 bigDelta1 MASKEDx MASKEDy"<< my_public_share[i]<<" " <<std::endl;
     }


    // beavy_provider_.broadcast_ints_message(gate_id_, my_public_share);

    beavy_provider_.send_ints_message(1-my_id, gate_id_, my_public_share); //send m_v to the other party
    beavy_provider_.send_ints_message(2, gate_id_, my_public_share);

    // if (my_id == 0) {
    //   std::cout << "GATE_ID " << gate_id_ << std::endl;
    //   std::cout << "GATE ID ++++++++++++++++++++++++++++++++++++++++ " << gate_id_ << std::endl;
    //     beavy_provider_.joint_send_verify_ints_message(0,1,2, input_id_, my_public_share, num_simd_, 1);
    // } else if (my_id == 1) {
    //     std::cout << "GATE ID ++++++++++++++++++++++++++++++++++++++++ " << gate_id_ << std::endl;
    //     beavy_provider_.joint_send_verify_ints_message(0,1,2, input_id_, my_public_share, num_simd_, 2);
    // }
    // }else if (my_id==2){
    //   beavy_provider_.joint_send_verify_ints_message(0,1,2, gate_id_-1, my_public_share, num_simd_, 1);
    //   // return;
    //   output_->set_online_ready();
    //
    // }
    // beavy_provider_.DIZK( output_->get_public_share(), output_->get_public_share());
    //

    output_->set_online_ready();

    std::cout <<" 1st time back to ArithmeticBEAVYInputGateSender<T>::evaluate_online()"<<" " <<std::endl;

    for(int i = 0; i < my_public_share.size(); i++) {
      std::cout <<"my_id="<< my_id << " BROADCAST my_public_share= bigDelta0 bigDelta1 MASKEDx MASKEDy"<< my_public_share[i]<<" " <<std::endl;
    }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYInputGateSender<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYInputGateSender<std::uint8_t>;
template class ArithmeticBEAVYInputGateSender<std::uint16_t>;
template class ArithmeticBEAVYInputGateSender<std::uint32_t>;
template class ArithmeticBEAVYInputGateSender<std::uint64_t>;

template <typename T>
ArithmeticBEAVYInputGateReceiver<T>::ArithmeticBEAVYInputGateReceiver(std::size_t gate_id,
                                                                      BEAVYProvider& beavy_provider,
                                                                      std::size_t num_simd,
                                                                      std::size_t input_owner)  //input owner in the receiver function = id with which in the application layer e Other gate has been invoked
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      num_simd_(num_simd),
      input_owner_(input_owner),
      input_id_(beavy_provider.get_next_input_id(1)),
      output_(std::make_shared<ArithmeticBEAVYWire<T>>(num_simd))  {
        // if(beavy_provider_.get_my_id()==2){
        if(beavy_provider_.get_my_id()==2){
          // share_futures_ = beavy_provider_.register_for_ints_messages<T>( input_id_, num_simd);
          public_share_future2_ =
              beavy_provider_.register_for_ints_message<T>(input_owner_, input_id_, num_simd); //this is a vector

        }else if (beavy_provider_.get_my_id()==0 || beavy_provider_.get_my_id()==1){
          public_share_future_ =
              beavy_provider_.register_for_ints_message<T>(input_owner_, input_id_, num_simd);
        }
        // public_share_future_ =
            // beavy_provider_.register_for_ints_message<T>(input_owner_, gate_id_, num_simd);

      // if(beavy_provider_.get_my_id()!=2){
      //   share_futures_ = beavy_provider_.register_for_ints_messages<T>(input_id_+1, num_simd); //this is a vector
      //
      // }

}

template <typename T>
void ArithmeticBEAVYInputGateReceiver<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYInputGateReceiver<T>::evaluate_setup start", gate_id_));
    }
  }
  std::cout <<" INVOKED ArithmeticBEAVYInputGateReceiver<T>::evaluate_setup()"<<" " <<std::endl;
  auto my_id=beavy_provider_.get_my_id();
  auto& mbp = beavy_provider_.get_motion_base_provider();

  if (my_id!=2) { //p0 and p1
  auto num_parties = beavy_provider_.get_num_parties();
    std::cout <<" INSIDE <>2 Party:: void ArithmeticBEAVYInputGateReceiver<T>::evaluate_setup()"<<" " <<std::endl;
    auto& rng = mbp.get_our_randomness_generator(input_owner_);
    output_->get_secret_share() = rng.GetUnsigned<T>(input_id_, num_simd_); //lambda_x1

    auto& rng4 = mbp.get_their_randomness_generator(input_owner_);
    output_->get_secret_share_2() = rng4.GetUnsigned<T>(input_id_, num_simd_); //gamma_x OR gamma_y

    if (input_owner_==0){

        for(int i = 0; i < output_->get_secret_share().size(); i++) {
          std::cout <<" Receiver Fucntion:: my_id= "<< my_id <<" input_owner_= "<<input_owner_<< " lambda_x1 received == "<< output_->get_secret_share()[i]<<" " <<std::endl;
        }
        for(int i = 0; i < output_->get_secret_share_2().size(); i++) {
          std::cout <<" Receiver Fucntion:: my_id= "<< my_id <<" input_owner_= "<<input_owner_<< " p1 received lambda_x2 == "<< output_->get_secret_share_2()[i]<<" " <<std::endl;
        }
    }else if(input_owner_==1)
    {
        if(my_id==0){
          for(int i = 0; i < output_->get_secret_share().size(); i++) {
            // beavy_provider_.broadcast_ints_message(input_id_+1, output_->get_secret_share());
            std::cout <<" Receiver Fucntion:: my_id="<< my_id <<" input_owner_="<<input_owner_<< " lambda_y0 received == "<< output_->get_secret_share()[i]<<" " <<std::endl;
          }
          for(int i = 0; i < output_->get_secret_share_2().size(); i++) {
            // beavy_provider_.broadcast_ints_message(input_id_+1, output_->get_secret_share());
            std::cout <<" Receiver Fucntion:: my_id="<< my_id <<" input_owner_="<<input_owner_<< " lambda_y2 received == "<< output_->get_secret_share_2()[i]<<" " <<std::endl;
          }
        }
    }
    // output_->set_setup_ready();
}
else{ //p2
          if(input_owner_==0){
                std::cout <<" INSIDE  Party 2:: ArithmeticBEAVYInputGateReceiver<T>::evaluate_setup()"<<" " <<std::endl;
                // auto& mbp = beavy_provider_.get_motion_base_provider();
                auto& rng = mbp.get_their_randomness_generator(input_owner_);
                output_->get_secret_share_0() = rng.GetUnsigned<T>(input_id_, num_simd_); //lambdax_1

                // std::cout<<"output_->get_public_share_0().size() "<< output_->get_public_share_0().size()<<std::endl;
                for(int i = 0; i < output_->get_secret_share_0().size(); i++) {
                    std::cout <<"\n my_id="<< my_id << " output_->get_secret_share_0()  //lambdax0 received = "<< output_->get_secret_share_0()[i]<<" " <<std::endl;
                }
                // SleepForSeconds(1.00);
                auto& rng3 = mbp.get_our_randomness_generator(input_owner_);
                output_->get_public_share_0()=rng3.GetUnsigned<T>(input_id_, num_simd_); //yo yo
                for(int i = 0; i < output_->get_public_share_0().size(); i++) {
                    std::cout <<"\n my_id="<< my_id << " RECIEVED PUBLIC SHARE:: output_->get_public_share_0()()  //lambdax1 received = "<< output_->get_public_share_0()[i]<<" " <<std::endl;
                }
                // output_->get_public_share()=output_->get_public_share_0();

        }
        if(input_owner_==1){
              // auto& mbp = beavy_provider_.get_motion_base_provider();
              auto& rng2 = mbp.get_their_randomness_generator(input_owner_);
              output_->get_secret_share_1() = rng2.GetUnsigned<T>(input_id_, num_simd_); //lambda_y0
              for(int i = 0; i < output_->get_secret_share_1().size(); i++) {
              std::cout <<"\n my_id="<< my_id << " output_->get_secret_share_1()  //lambday1 received = "<< output_->get_secret_share_1()[i]<<" " <<std::endl;
              }
              // SleepForSeconds(1.00);
              auto& rng4 = mbp.get_our_randomness_generator(input_owner_);
              output_->get_public_share_1()=rng4.GetUnsigned<T>(input_id_, num_simd_); //YO YO
              // output_->get_public_share_1()=public_share_future_2.get();
              // output_->get_public_share_1()=public_share_future_.get();

              for(int i = 0; i < output_->get_public_share_1().size(); i++) {
              std::cout <<"\n my_id="<< my_id << " RECIEVED PUBLIC SHARE:: output_->get_public_share_1()()  //lambday0 received = "<< output_->get_public_share_1()[i]<<" " <<std::endl;
              }
              // output_->get_public_share()=output_->get_public_share_1();

      }
      output_->set_setup_ready();
      // output_->set_online_ready();
}
output_->set_setup_ready();


  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYInputGateReceiver<T>::evaluate_setup end", gate_id_));
    }
  }

}
template <typename T>
void ArithmeticBEAVYInputGateReceiver<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYInputGateReceiver<T>::evaluate_online start", gate_id_));
    }
  }

  std::size_t my_id = beavy_provider_.get_my_id();
  if (my_id==2){
    if(input_owner_==0){
      output_->get_public_share_3() = public_share_future2_.get();
      std::cout<<" p2 receives public share "<<output_->get_public_share_3()[0]<<std::endl;}
    else if (input_owner_==1){
      output_->get_public_share() = public_share_future2_.get();
      std::cout<<" p2 receives public share "<<output_->get_public_share()[0]<<std::endl;}

    output_->set_online_ready();
    return;
  }

  std::cout<<"----------------------------------ONLINE phases starts----------------------------------------------"<<std::endl;
  std::cout<<"----------------------------------ONLINE phases starts----------------------------------------------"<<std::endl;
  // auto my_id=beavy_provider_.get_my_id();
  output_->get_public_share() = public_share_future_.get();
  for(int i = 0; i < output_->get_public_share().size(); i++) {
    std::cout <<"my_id="<< my_id << " output_->get_public_share() bigDEltax bigDeltay  == "<< output_->get_public_share()[i]<<" " <<std::endl;
  }
  output_->set_online_ready();
  std::cout<<"-----ArithmeticBEAVYInputGateReceiver<T>::evaluate_online()--output_->set_online_ready();---"<<std::endl;

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYInputGateReceiver<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYInputGateReceiver<std::uint8_t>;
template class ArithmeticBEAVYInputGateReceiver<std::uint16_t>;
template class ArithmeticBEAVYInputGateReceiver<std::uint32_t>;
template class ArithmeticBEAVYInputGateReceiver<std::uint64_t>;


template <typename T>
ArithmeticBEAVYOutputGate<T>::ArithmeticBEAVYOutputGate(std::size_t gate_id,
                                                        BEAVYProvider& beavy_provider,
                                                        ArithmeticBEAVYWireP<T>&& input,
                                                        std::size_t output_owner)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      output_owner_(output_owner),
      input_(std::move(input)) {
  std::size_t my_id = beavy_provider_.get_my_id();

  if (my_id==0){
      share_future0_=beavy_provider_.register_for_ints_message<T>(1, gate_id_, input_->get_num_simd(),1);
  }
  else if(my_id==1){
    share_future1_=beavy_provider_.register_for_ints_message<T>(0, gate_id_, input_->get_num_simd(),1);
  }
  else if(my_id==2){
    share_future2_=beavy_provider_.register_for_ints_message<T>(0, gate_id_, input_->get_num_simd(),1);
  }
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticBEAVYOutputGate<T>::get_output_future() {
  std::size_t my_id = beavy_provider_.get_my_id();
  //if (my_id==2){
    //return;
  //}
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    return output_promise_.get_future();
  } else {
    throw std::logic_error("not this parties output");
  }
}

template <typename T>
void ArithmeticBEAVYOutputGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYOutputGate<T>::evaluate_setup start", gate_id_));
    }
  }

  std::size_t my_id = beavy_provider_.get_my_id();
    std::cout<<"inside ArithmeticBEAVYOutputGate<T>::evaluate_setup()" <<std::endl;



  if (output_owner_ != my_id) {
    input_->wait_setup();
    std::cout<<"---------------------waiting on input setup-----------------"<<std::endl;
    auto my_secret_share = input_->get_secret_share();
    //================================test========================================
    if(my_id==0){
      std::cout<< " O/p gate:: lambda_z0 input_->get_secret_share_3() " <<input_->get_secret_share_3()[0]<<std::endl;
      std::cout<< " O/p gate:: lambda_z2 input_->get_public_share_3() " <<input_->get_public_share_3()[0]<<std::endl;
      beavy_provider_.send_ints_message(1, gate_id_, input_->get_secret_share_3() , 1);
      beavy_provider_.send_ints_message(2, gate_id_, input_->get_public_share_3() , 1);

    }
    else if(my_id==1){
      std::cout<< " O/p gate:: lambda_z1 input_->get_secret_share_3() " <<input_->get_secret_share_3()[0]<<std::endl;
      std::cout<< " O/p gate:: lambda_z2 input_->get_public_share_3() " <<input_->get_public_share_3()[0]<<std::endl;

      beavy_provider_.send_ints_message(0, gate_id_, input_->get_secret_share_3() , 1);


    }
    else if(my_id ==2){
      std::cout<< " O/p gate:: lambda_z0 input_->get_secret_share_3() " <<input_->get_secret_share_3()[0]<<std::endl;
      std::cout<< " O/p gate:: lambda_z1 input_->get_public_share_3()" <<input_->get_public_share_3()[0]<<std::endl;

    }
    // //======================================test======================================
    //   if (output_owner_ == ALL_PARTIES) {
    //       beavy_provider_.broadcast_ints_message(gate_id_, my_secret_share); //if reconstruction is sending to all parties, broadcast your secret share to everyone
    //       for(int i=0; i<my_secret_share.size(); i++){
    //             std::cout<< "inside output gate, my_secret_share value=  "<<my_secret_share[i]  <<std::endl;
    //       }
    //
    //   } else {
    //     beavy_provider_.joint_send_verify_ints_message(0,2,1, gate_id_, my_secret_share,1, 1 );
    //     std::cout<<"inside output gate, JSend" <<std::endl;
    //     beavy_provider_.joint_send_verify_ints_message(0,2,1, gate_id_, my_secret_share,1, 1 );
    //     beavy_provider_.joint_send_verify_ints_message(0,1,2, gate_id_, my_secret_share,1, 1 );
    //     //beavy_provider_.send_ints_message(output_owner_, gate_id_, my_secret_share); //if reconstruction is being done by 1 party, send to that party
    //   }
    //   for(int i = 0; i < my_secret_share.size(); i++) {
    //     std::cout <<"my_id="<< my_id << " my_secret_share= lambdaz0 lambdaz1"<< my_secret_share[i]<<" " <<std::endl;
    //   }
    //   std::cout<<"\n"<<std::endl;
  }


  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYOutputGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYOutputGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYOutputGate<T>::evaluate_online start", gate_id_));
    }
  }


  std::size_t my_id = beavy_provider_.get_my_id();

  std::cout<<"inside ArithmeticBEAVYOutputGate<T>::evaluate_online()" <<std::endl;
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    input_->wait_setup();
    std::vector<T> total_mask(1);
    std::vector<T> og_val(1);
    if(my_id==0){
       auto lambda_z1=share_future0_.get();
       std::cout<<" O/P online:: lambda_z0 "<<input_->get_secret_share_3()[0]<<std::endl;
       std::cout<<" O/P Online:: lambda_z1 "<<lambda_z1[0]<<std::endl;
       std::cout<<" O/P online:: lambda_z2 "<<input_->get_public_share_3()[0]<<std::endl;
       std::transform(std::begin(input_->get_secret_share_3()), std::end(input_->get_secret_share_3()),
                      std::begin(lambda_z1), std::begin(total_mask), std::plus{});
      std::transform(std::begin(total_mask), std::end(total_mask),
                     std::begin(input_->get_public_share_3()), std::begin(total_mask), std::plus{});
    }else if(my_id==1){
      auto lambda_z0=share_future1_.get();
      std::cout<<" O/P online:: lambda_z0 "<<lambda_z0[0]<<std::endl;
      std::cout<<" O/P Online:: lambda_z1 "<<input_->get_secret_share_3()[0]<<std::endl;
      std::cout<<" O/P online:: lambda_z2 "<<input_->get_public_share_3()[0]<<std::endl;
      std::transform(std::begin(input_->get_secret_share_3()), std::end(input_->get_secret_share_3()),
                     std::begin(lambda_z0), std::begin(total_mask), std::plus{});
     std::transform(std::begin(total_mask), std::end(total_mask),
                    std::begin(input_->get_public_share_3()), std::begin(total_mask), std::plus{});
    }else if(my_id==2){
      return;
      auto lambda_z2=share_future1_.get();
      std::cout<<" O/P online:: lambda_z0 "<<input_->get_secret_share_3()[0]<<std::endl;
      std::cout<<" O/P Online:: lambda_z1 "<<input_->get_public_share_3()[0]<<std::endl;
      std::cout<<" O/P online:: lambda_z2 "<<lambda_z2[0]<<std::endl;
      std::transform(std::begin(input_->get_secret_share_3()), std::end(input_->get_secret_share_3()),
                     std::begin(lambda_z2), std::begin(total_mask), std::plus{});
     std::transform(std::begin(total_mask), std::end(total_mask),
                    std::begin(input_->get_public_share_3()), std::begin(total_mask), std::plus{});
                    return;
    }
    input_->wait_online();
    std::transform(std::begin(input_->get_public_share()), std::end(input_->get_public_share()),
                   std::begin(total_mask), std::begin(og_val), std::minus{});
    std::cout<< " O/P gate:: og_val"<<og_val[0]<<std::endl;
    output_promise_.set_value(std::move(og_val));
    // for(int i = 0; i < my_secret_share.size(); i++) {
    //   std::cout <<"my_id="<< my_id << " input_->get_public_share my_secret_share= "<< my_secret_share[i]<<" " <<std::endl;
    // }
    // for(int i = 0; i < my_secret_share.size(); i++) {
    //   std::cout <<"my_id="<< my_id << " my_secret_share= "<< my_secret_share[i]<<" " <<std::endl;
    // }
    //
    // std::cout<<"value set in output promise"<<"\n"<<std::endl;
  }


  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYOutputGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYOutputGate<std::uint8_t>;
template class ArithmeticBEAVYOutputGate<std::uint16_t>;
template class ArithmeticBEAVYOutputGate<std::uint32_t>;
template class ArithmeticBEAVYOutputGate<std::uint64_t>;

template <typename T>
ArithmeticBEAVYOutputShareGate<T>::ArithmeticBEAVYOutputShareGate(std::size_t gate_id,
                                                    ArithmeticBEAVYWireP<T>&& input)
    : NewGate(gate_id),
      input_(std::move(input)) {
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticBEAVYOutputShareGate<T>::get_public_share_future() {
  return public_share_promise_.get_future();
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticBEAVYOutputShareGate<T>::get_secret_share_future() {
  return secret_share_promise_.get_future();
}

template <typename T>
void ArithmeticBEAVYOutputShareGate<T>::evaluate_setup() {
  input_->wait_setup();
  secret_share_promise_.set_value(input_->get_secret_share());
}

template <typename T>
void ArithmeticBEAVYOutputShareGate<T>::evaluate_online() {
  input_->wait_online();
  public_share_promise_.set_value(input_->get_public_share());
}

template class ArithmeticBEAVYOutputShareGate<std::uint8_t>;
template class ArithmeticBEAVYOutputShareGate<std::uint16_t>;
template class ArithmeticBEAVYOutputShareGate<std::uint32_t>;
template class ArithmeticBEAVYOutputShareGate<std::uint64_t>;

namespace detail {

template <typename T>
BasicArithmeticBEAVYBinaryGate<T>::BasicArithmeticBEAVYBinaryGate(std::size_t gate_id,
                                                                  BEAVYProvider& ,
                                                                  ArithmeticBEAVYWireP<T>&& in_a,
                                                                  ArithmeticBEAVYWireP<T>&& in_b)
    : NewGate(gate_id),
      // beavy_provider_(beavy_provider),
      input_a_(std::move(in_a)),
      input_b_(std::move(in_b)),
      output_(std::make_shared<ArithmeticBEAVYWire<T>>(input_a_->get_num_simd())) { // ALANNN
  if (input_a_->get_num_simd() != input_b_->get_num_simd()) {
    throw std::logic_error("number of SIMD values need to be the same for all wires");
  }
  auto num_simd = this->input_a_->get_num_simd();
}

template class BasicArithmeticBEAVYBinaryGate<std::uint8_t>;
template class BasicArithmeticBEAVYBinaryGate<std::uint16_t>;
template class BasicArithmeticBEAVYBinaryGate<std::uint32_t>;
template class BasicArithmeticBEAVYBinaryGate<std::uint64_t>;

template <typename T>
BasicArithmeticBEAVYUnaryGate<T>::BasicArithmeticBEAVYUnaryGate(std::size_t gate_id, BEAVYProvider&,
                                                                ArithmeticBEAVYWireP<T>&& in)
    : NewGate(gate_id),
      input_(std::move(in)),
      output_(std::make_shared<ArithmeticBEAVYWire<T>>(input_->get_num_simd())) {}

template class BasicArithmeticBEAVYUnaryGate<std::uint8_t>;
template class BasicArithmeticBEAVYUnaryGate<std::uint16_t>;
template class BasicArithmeticBEAVYUnaryGate<std::uint32_t>;
template class BasicArithmeticBEAVYUnaryGate<std::uint64_t>;

template <typename T>
BasicBooleanXArithmeticBEAVYBinaryGate<T>::BasicBooleanXArithmeticBEAVYBinaryGate(
    std::size_t gate_id, BEAVYProvider&, BooleanBEAVYWireP&& in_a, ArithmeticBEAVYWireP<T>&& in_b)
    : NewGate(gate_id),
      input_bool_(std::move(in_a)),
      input_arith_(std::move(in_b)),

      output_(std::make_shared<ArithmeticBEAVYWire<T>>(input_arith_->get_num_simd())) {
  if (input_arith_->get_num_simd() != input_bool_->get_num_simd()) {
    throw std::logic_error("number of SIMD values need to be the same for all wires");
  }
}

template class BasicBooleanXArithmeticBEAVYBinaryGate<std::uint8_t>;
template class BasicBooleanXArithmeticBEAVYBinaryGate<std::uint16_t>;
template class BasicBooleanXArithmeticBEAVYBinaryGate<std::uint32_t>;
template class BasicBooleanXArithmeticBEAVYBinaryGate<std::uint64_t>;

}  // namespace detail

template <typename T>
ArithmeticBEAVYNEGGate<T>::ArithmeticBEAVYNEGGate(std::size_t gate_id,
                                                  BEAVYProvider& beavy_provider,
                                                  ArithmeticBEAVYWireP<T>&& in)
    : detail::BasicArithmeticBEAVYUnaryGate<T>(gate_id, beavy_provider, std::move(in)) {
  this->output_->get_public_share().resize(this->input_->get_num_simd());
  this->output_->get_secret_share().resize(this->input_->get_num_simd());
}

template <typename T>
void ArithmeticBEAVYNEGGate<T>::evaluate_setup() {
  this->input_->wait_setup();
  assert(this->output_->get_secret_share().size() == this->input_->get_num_simd());
  std::transform(std::begin(this->input_->get_secret_share()),
                 std::end(this->input_->get_secret_share()),
                 std::begin(this->output_->get_secret_share()), std::negate{});
  this->output_->set_setup_ready();
}

template <typename T>
void ArithmeticBEAVYNEGGate<T>::evaluate_online() {
  this->input_->wait_online();
  assert(this->output_->get_public_share().size() == this->input_->get_num_simd());
  std::transform(std::begin(this->input_->get_public_share()),
                 std::end(this->input_->get_public_share()),
                 std::begin(this->output_->get_public_share()), std::negate{});
  this->output_->set_online_ready();
}

template class ArithmeticBEAVYNEGGate<std::uint8_t>;
template class ArithmeticBEAVYNEGGate<std::uint16_t>;
template class ArithmeticBEAVYNEGGate<std::uint32_t>;
template class ArithmeticBEAVYNEGGate<std::uint64_t>;

template <typename T>
ArithmeticBEAVYADDGate<T>::ArithmeticBEAVYADDGate(std::size_t gate_id,
                                                  BEAVYProvider& beavy_provider,
                                                  ArithmeticBEAVYWireP<T>&& in_a,
                                                  ArithmeticBEAVYWireP<T>&& in_b)
    : detail::BasicArithmeticBEAVYBinaryGate<T>(gate_id, beavy_provider, std::move(in_a),
                                                std::move(in_b)),
      beavy_provider_(beavy_provider) {
        /*
  this->output_->get_public_share().resize(this->input_a_->get_num_simd());
  this->output_->get_secret_share().resize(this->input_a_->get_num_simd());
  //suvi

  this->output_->get_public_share().resize(this->input_b_->get_num_simd());
  this->output_->get_secret_share().resize(this->input_b_->get_num_simd());
  //--------------------------------------------------------------------------------insert
  //
  //const Base *base = this;
*/
  //suvi for p2
  this->output_->get_public_share_0().resize(this->input_b_->get_num_simd());
  this->output_->get_secret_share_0().resize(this->input_b_->get_num_simd());

  // this->output_->get_public_share_1().resize(this->input_a_->get_num_simd());
  this->output_->get_secret_share_1().resize(this->input_a_->get_num_simd());
  // this->output_->get_public_share().resize(this->input_b_->get_num_simd());
  // this->output_->get_secret_share().resize(this->input_b_->get_num_simd());

}

template <typename T>
void ArithmeticBEAVYADDGate<T>::evaluate_setup() {
  auto my_id = this->beavy_provider_.get_my_id();
  //std::cout<<"the my_id of beavy provider "<<my_id<<std::endl;Moving shared_state


  this->input_a_->wait_setup();
  std::cout<<"waiting of ADD gate reached "<< "my_id" << my_id <<std::endl;
  this->input_b_->wait_setup();
  std::cout<<"waiting of ADD gate reached "<< "my_id" << my_id <<std::endl;
  //assert(this->output_->get_secret_share().size() == this->input_a_->get_num_simd());
  //assert(this->output_->get_secret_share().size() == this->input_b_->get_num_simd());

  if(my_id!=2){
  std::transform(std::begin(this->input_a_->get_secret_share()),
                 std::end(this->input_a_->get_secret_share()),
                 std::begin(this->input_b_->get_secret_share()),
                 std::begin(this->output_->get_secret_share()), std::plus{});



//DEBUG
  std::cout<<"\n"<<" TEST inside void ArithmeticBEAVYADDGate<T>::evaluate_setup() {" <<std::endl;

  for(int i = 0; i < this->input_a_->get_secret_share().size(); i++) {
    std::cout << " this->input_a_->get_secret_share() lambdax0 for party 0, lambdax1 for party 1  = "<< this->input_a_->get_secret_share()[i]<<" " <<std::endl;
  }
  std::cout<<"\n"<<std::endl;
  for(int i = 0; i < this->input_b_->get_secret_share().size(); i++) {
    std::cout << " this->input_b_->get_secret_share() lambday0 for party 0, lambday1 for party 1 = "<< this->input_b_->get_secret_share()[i]<<" " <<std::endl;
  }
  std::cout<<"\n"<<std::endl;
  for(int i = 0; i < this->output_->get_secret_share().size(); i++) {
    std::cout << " this->output_->get_secret_share() lambdaz0 for party 0, lambdaz1 for party1 = lambda_zi=lambdaxi+lambdayi  = "<< this->output_->get_secret_share()[i]<<" " <<std::endl;
  }
  this->output_->set_setup_ready();

}else if(my_id ==2) //suvi
  {
    //debug-----------------------------
    std::cout<<"\n"<<std::endl;
    for(int i = 0; i < this->input_a_->get_secret_share_0().size(); i++) {
      std::cout << " lambdax0  = "<< this->input_a_->get_secret_share_0()[i]<<" " <<std::endl;
    }
    for(int i = 0; i < this->input_b_->get_public_share_1().size(); i++) {
      std::cout << " lambday0  = "<< this->input_b_->get_public_share_1()[i]<<" " <<std::endl;
    }
    for(int i = 0; i < this->input_a_->get_public_share_0().size(); i++) {
      std::cout << " lambdax1  = "<< this->input_a_->get_public_share_0()[i]<<" " <<std::endl;
    }
    for(int i = 0; i < this->input_b_->get_secret_share_1().size(); i++) {
      std::cout << " lambday1  = "<< this->input_b_->get_secret_share_1()[i]<<" " <<std::endl;
    }
std::cout<<"\n"<<std::endl;




    //debug------------------------------



    //Lambda_x0  + Lambda_y0 = Lambda_z0Moving shared_state

    std::transform(std::begin(this->input_a_->get_secret_share_0()),
                   std::end(this->input_a_->get_secret_share_0()),
                   std::begin(this->input_b_->get_public_share_1()),
                   std::begin(this->output_->get_secret_share_0()), std::plus{});

                   //Lambda_x1 + Lambda_y1 = Lambda_z1
                   std::transform(std::begin(this->input_a_->get_public_share_0()),
                                  std::end(this->input_a_->get_public_share_0()),
                                  std::begin(this->input_b_->get_secret_share_1()),
                                  std::begin(this->output_->get_secret_share_1()), std::plus{});


                                  std::transform(std::begin(this->output_->get_secret_share_0()), //lambdax
                                                 std::end(this->output_->get_secret_share_0()),
                                                 std::begin(this->output_->get_secret_share_1()), //lambday
                                                 std::begin(this->output_->get_secret_share()), std::plus{}); //lambdax + lambday



  //Debug---------------------------------------------------
                   std::cout<<"\n"<<"inside void ArithmeticBEAVYADDGate<T>::evaluate_setup() --- PARTY P2{" <<std::endl;

                   for(int i = 0; i < this->output_->get_secret_share_0().size(); i++) {
                     std::cout << " lambdaz0  = "<< this->output_->get_secret_share_0()[i]<<" " <<std::endl;
                   }
                   std::cout<<"\n"<<std::endl;
                   for(int i = 0; i < this->output_->get_secret_share_1().size(); i++) {
                     std::cout << " lambdaz1  = "<< this->output_->get_secret_share_1()[i]<<" " <<std::endl;
                   }
                   std::cout<<"\n"<<std::endl;
                   for(int i = 0; i < this->output_->get_secret_share().size(); i++) {
                     std::cout << " lambdaz  = "<< this->output_->get_secret_share()[i]<<" " <<std::endl;
                   }

                   std::cout<<"\n"<<std::endl;
//Debug----------------------------------------------------------------

   }
   this->output_->set_setup_ready();
}

template <typename T>
void ArithmeticBEAVYADDGate<T>::evaluate_online() {
  auto my_id = this->beavy_provider_.get_my_id();
  if (my_id==2){
      std::cout<<"\n no ADD gate online phase for p2 \n "<<std::endl;
      return;}
  this->input_a_->wait_online();
  this->input_b_->wait_online();
  assert(this->output_->get_public_share().size() == this->input_a_->get_num_simd());
  std::transform(std::begin(this->input_a_->get_public_share()), //mxMoving shared_state

                 std::end(this->input_a_->get_public_share()),
                 std::begin(this->input_b_->get_public_share()), //my
                 std::begin(this->output_->get_public_share()), std::plus{});
                 std::cout<<"inside void ArithmeticBEAVYADDGate<T>::evaluate_online() { \n" <<std::endl;
                 for(int i = 0; i < this->input_a_->get_secret_share().size(); i++) {
                   std::cout <<" this->input_a_->get_secret_share() bigDeltax ="<< this->input_a_->get_secret_share()[i]<<" " <<std::endl;
                 }
                 std::cout<<"\n"<<std::endl;
                 for(int i = 0; i < this->input_b_->get_secret_share().size(); i++) {
                   std::cout <<" this->input_b_->get_secret_share() bigDeltay ="<< this->input_b_->get_secret_share()[i]<<" " <<std::endl;
                 }
                 std::cout<<"\n"<<std::endl;
                 for(int i = 0; i < this->output_->get_secret_share().size(); i++) {
                   std::cout <<" this->output_->get_secret_share() bigDeltaz= bigDeltax+bigDeltay = "<< this->output_->get_secret_share()[i]<<" " <<std::endl;
                 }
                 std::cout<<"\n"<<std::endl;
  this->output_->set_online_ready();
}

template class ArithmeticBEAVYADDGate<std::uint8_t>;
template class ArithmeticBEAVYADDGate<std::uint16_t>;
template class ArithmeticBEAVYADDGate<std::uint32_t>;
template class ArithmeticBEAVYADDGate<std::uint64_t>;


template <typename T>
ArithmeticBEAVYMULGate<T>::ArithmeticBEAVYMULGate(std::size_t gate_id,
                                                  BEAVYProvider& beavy_provider,
                                                  ArithmeticBEAVYWireP<T>&& in_a,
                                                  ArithmeticBEAVYWireP<T>&& in_b)
    : detail::BasicArithmeticBEAVYBinaryGate<T>(gate_id, beavy_provider, std::move(in_a),
                                                std::move(in_b)),
  beavy_provider_(beavy_provider) {
  auto my_id = beavy_provider_.get_my_id();
  auto num_simd = this->input_a_->get_num_simd();
  if (my_id==0){
    std::cout << "ALANNNNNNNNNN REG " << this->gate_id_ << std::endl;
      share_future0_=beavy_provider_.register_for_ints_message<T>(1, this->gate_id_, this->input_a_->get_num_simd(),1);
      share_future00_=beavy_provider_.register_for_ints_message<T>(1, this->gate_id_, this->input_a_->get_num_simd(),2);
      share_future01_=beavy_provider_.register_for_ints_message<T>(1, this->gate_id_, this->input_a_->get_num_simd(),3);


  }
  else if(my_id==1){
    std::cout << "ALANNNNNNNNNN REG " << this->gate_id_ << std::endl;
    share_future1_=beavy_provider_.register_for_ints_message<T>(2, this->gate_id_, this->input_a_->get_num_simd(),1);
    share_future11_=beavy_provider_.register_for_ints_message<T>(0, this->gate_id_, this->input_a_->get_num_simd(),2);
    share_future10_=beavy_provider_.register_for_ints_message<T>(0, this->gate_id_, this->input_a_->get_num_simd(),3);
  }
  else if(my_id==2){
    std::cout << "ALANNNNNNNNNN REG " << this->gate_id_ << std::endl;
    share_future2_=beavy_provider_.register_for_ints_message<T>(0, this->gate_id_ - 1, this->input_a_->get_num_simd(),1);

  }




}


template <typename T>
ArithmeticBEAVYMULGate<T>::~ArithmeticBEAVYMULGate() = default;

template <typename T>
void ArithmeticBEAVYMULGate<T>::evaluate_setup() { // SUVI
        if constexpr (MOTION_VERBOSE_DEBUG) { //Without Truncation
          auto logger = beavy_provider_.get_logger();
          if (logger) {
            logger->LogTrace(
                fmt::format("Gate {}: ArithmeticBEAVYMULGate<T>::evaluate_setup start", this->gate_id_));
          }
        }
    std::cout<<"\n TEST inside ArithmeticBEAVYMULGate<T>::evaluate_setup"<<std::endl;
    num_simd_ = this->input_a_->get_num_simd();
    this->input_a_->wait_setup();
    this->input_b_->wait_setup();
    auto my_id = beavy_provider_.get_my_id();
    auto& mbp = beavy_provider_.get_motion_base_provider();
    std::vector<T> MAX64v;
    MAX64v.push_back(MAX64);
    if(my_id==0){
      //===============================TEST===================================
      lambda_x0.push_back(this->input_a_->get_secret_share()[0]);
      std::cout <<"my_id="<< my_id << " MULT Lambda_x0 = v1 "<< this->input_a_->get_secret_share()[0]<< " Lambda_x0 "<< lambda_x0[0] <<std::endl;
      lambda_y0.push_back(this->input_b_->get_secret_share()[0]);
      std::cout <<"my_id="<< my_id << " MULT Lambda_y0 = u1 "<< this->input_b_->get_secret_share()[0]<< " lambda_y0 "<< lambda_y0[0] <<std::endl;
      lambda_x2.push_back(this->input_a_->get_public_share_2()[0]);
      std::cout <<"my_id="<< my_id << "MULT lambda_x2 = v2 "<< this->input_a_->get_public_share_2()[0]<<" lambda_x2 "<<lambda_x2[0] <<std::endl;
      lambda_y2.push_back(this->input_b_->get_secret_share_2()[0]);
      std::cout <<"my_id="<< my_id << " MULT lambda_y2 = u2 "<< this->input_b_->get_secret_share_2()[0]<<" lambda_y2 "<<lambda_y2[0] <<std::endl;

      std::cout<< " retrieved (2,3) SS of lambda_a lambda_b --------" <<std::endl;
      //============common between P0 and P2===========================
      auto& rng3 = mbp.get_my_randomness_generator(2);
      auto tmp2=rng3.GetUnsigned<T>(this->gate_id_, 3);
      auto& rng9 = mbp.get_my_randomness_generator(my_id); //only for p0
      auto tmp9=rng9.GetUnsigned<T>(this->gate_id_, 1);
      std::vector<T> r02; //r0
      std::vector<T> p02; //p0
      std::vector<T> row02; //row0
      r02.push_back(tmp2[0]); //r0
      p02.push_back(tmp9[0]);
      row02.push_back(tmp2[2]);
      std::cout<<" yoyo r0="<<r02[0]<<std::endl;
      std::cout<<" yoyo p0="<<p02[0]<<std::endl;
      std::cout<<" yoyo row0="<<row02[0]<<std::endl;
      this->output_->get_secret_share_0().push_back(r02[0]);// storing r0
      this->output_->get_public_share_0().push_back(p02[0]); //lambda_p0
      this->output_->get_public_share_0().resize(this->input_a_->get_num_simd());
      this->output_->get_secret_share_3().resize(this->input_a_->get_num_simd());
      std::vector<T> neg;
      // MAX64v.resize(this->input_a_->get_num_simd());
      // r02.resize(this->input_a_->get_num_simd());
      neg.resize(this->input_a_->get_num_simd());
      this->output_->get_public_share_0().resize(this->input_a_->get_num_simd());
      this->output_->get_secret_share_3().resize(this->input_a_->get_num_simd());
      std::transform(std::begin(MAX64v),
              std::end(MAX64v),
              std::begin(r02),
              std::begin(neg), std::minus{});
      neg[0]=neg[0]+1; //neg=Lambda_r0

      std::transform(std::begin(neg),
              std::end(neg),
              std::begin(this->output_->get_public_share_0()),
              std::begin(this->output_->get_secret_share_3()), std::plus{});
     std::cout <<"my_id="<< my_id << " MULT lambda_z0  "<< this->output_->get_secret_share_3()[0]<<" " <<std::endl;
     //=================================Common between P0 and p1
     auto& rng7 = mbp.get_my_randomness_generator(1);
     auto tmp3=rng7.GetUnsigned<T>(this->gate_id_, 3);
     auto& rng99 = mbp.get_our_randomness_generator(1);
     auto tmp99=rng99.GetUnsigned<T>(this->gate_id_, 1);
     std::vector<T> p11;
     std::vector<T> r01;
     std::vector<T> p01;
     std::vector<T> row01;
     r01.push_back(tmp3[0]);
     p01.push_back(tmp3[1]);
     row01.push_back(tmp3[2]);
     p11.push_back(tmp99[0]);
     std::cout<<" yoyo r2="<<r01[0]<<std::endl;
     std::cout<<" yoyo p2="<<p01[0]<<std::endl;
     std::cout<<" yoyo p1="<<p11[0]<<std::endl;
     std::cout<<" yoyo row2="<<row01[0]<<std::endl;
     this->output_->get_secret_share_1().push_back(r01[0]); //r2
     this->output_->get_public_share_1().push_back(p01[0]); //lambda_p2
     this->output_->get_secret_share_4().push_back(p11[0]); //lambda_p1
     this->output_->get_public_share_1().resize(this->input_a_->get_num_simd());
     this->output_->get_public_share_3().resize(this->input_a_->get_num_simd());
     std::vector<T> neg1;
     MAX64v.resize(this->input_a_->get_num_simd());
     r01.resize(this->input_a_->get_num_simd());
     neg1.resize(this->input_a_->get_num_simd());
     std::transform(std::begin(MAX64v),
             std::end(MAX64v),
             std::begin(r01),
             std::begin(neg1), std::minus{});
     neg1[0]=neg1[0]+1; //neg=lambda_r2
     std::transform(std::begin(neg1),
             std::end(neg1),
             std::begin(this->output_->get_public_share_1()),
             std::begin(this->output_->get_public_share_3()), std::plus{});
    std::cout <<"my_id="<< my_id << " MULT lambda_z2 "<< this->output_->get_public_share_3()[0]<<" " <<std::endl;

     //=================================end of common between p0 and p1
     std::cout<<"\n ----------------start of MULT of DIZK------------------------ \n"<<std::endl;
     std::vector<T> u1;
     std::vector<T> u2;
     std::vector<T> v1;
     std::vector<T> v2;
     v1.push_back(lambda_x0[0]);
     v2.push_back(lambda_x2[0]);
     u1.push_back(lambda_y0[0]);
     u2.push_back(lambda_y2[0]);
     std::vector<T> alpha0(num_simd_);
     std::transform(std::begin(row02),
            std::end(row02),
            std::begin(row01),
            std::begin(alpha0), std::minus{}); // alpha0= row0-row2;
    std::cout<<" MULT alpha0 ="<<alpha0[0]<<std::endl;
    std::vector<T> term1(1);
    std::vector<T> term2(1);
    std::vector<T> term3(1);
    std::vector<T> term4(1);
    std::vector<T> term5(1);
    std::vector<T> z0(1);
    std::transform(std::begin(u1),
           std::end(u1),
           std::begin(v1),
           std::begin(term1), std::multiplies{}); // u1.v1
   std::cout<<" u1 "<<u1[0]<<" v1 "<<v1[0]<< " u1.v1 "<< term1[0]<<std::endl;
   std::transform(std::begin(u1),
           std::end(u1),
           std::begin(v2),
           std::begin(term2), std::multiplies{}); // u1.v2
  std::cout<<" u1 "<<u1[0]<<" v2 "<<v2[0]<< " u1.v2 "<< term2[0]<<std::endl;
  std::transform(std::begin(u2),
         std::end(u2),
         std::begin(v1),
         std::begin(term3), std::multiplies{}); // u2.v1
  std::cout<<" u2 "<<u2[0]<<" v1 "<<v1[0]<< " u2.v1 "<< term3[0]<<std::endl;
  std::transform(std::begin(term1),
       std::end(term1),
       std::begin(term2),
       std::begin(term4), std::plus{}); // u1.v1 + u1.v2
  std::cout<<" term1 + term2 = term4 "<< term4[0]<<std::endl;
  std::transform(std::begin(term4),
       std::end(term4),
       std::begin(term3),
       std::begin(term5), std::plus{}); // u1.v1 + u1.v2 + u2.v1
  std::cout<<" term5= term4 + term3 "<< term5[0]<<std::endl;
 std::transform(std::begin(term5),
       std::end(term5),
       std::begin(alpha0),
       std::begin(z0), std::plus{}); // u1.v1 + u1.v2 + u2.v1
 std::cout<< "term5 + alpha1= z2 " <<z0[0]<<std::endl;
 std::cout <<"my_id="<< my_id << " MULT z0 "<< z0[0]<<" " <<std::endl;
 beavy_provider_.send_ints_message(2, this->gate_id_, z0, 1);
 auto z2=share_future0_.get();
 std::cout<<" z2 received from p1 = "<<z2[0] <<std::endl;
 std::cout<< " \n---------------end of MULT of DIZK ------------\n" <<std::endl;
 std::vector<T> gamma_r_0(num_simd_);
 z0.resize(this->input_a_->get_num_simd());
 r02.resize(this->input_a_->get_num_simd());
 std::transform(std::begin(z0),
       std::end(z0),
       std::begin(r02),
       std::begin(gamma_r_0), std::minus{});
 std::cout <<"my_id="<< my_id << " MULT gamma_r_0 "<< gamma_r_0[0]<<" " <<std::endl;
 std::vector<T> gamma_r_2(num_simd_);
 z2.resize(this->input_a_->get_num_simd());
 r01.resize(this->input_a_->get_num_simd());
 std::transform(std::begin(z2),
       std::end(z2),
       std::begin(r01),
       std::begin(gamma_r_2), std::minus{});
std::cout <<"my_id="<< my_id << " MULT gamma_r_2 "<< gamma_r_2[0]<<" " <<std::endl;
 this->output_->get_secret_share_2()=gamma_r_0;
 this->output_->get_public_share_2()=gamma_r_2;
 // this->output_->set_setup_ready();

 std::cout<<"\n----------------CONSISTENCY CHECK--------------------\n"<<std::endl;
 std::cout<< " MULT: u1 "<<u1[0]<<std::endl;
 std::cout<< " MULT: u2 "<<u2[0]<<std::endl;
 std::cout<< " MULT: v1 "<<v1[0]<<std::endl;
 std::cout<< " MULT: v2 "<<v2[0]<<std::endl;
 std::cout<<"\n----------------CONSISTENCY CHECK--------------------\n"<<std::endl;


 beavy_provider_.set_cckt(this-> gate_id_, u1, u2, v1, v2, z0, z2, alpha0, row02, row01);

 std::size_t last_mult_gate_id=99;
 beavy_provider_.DIZK_verify(last_mult_gate_id);
 this->output_->set_setup_ready();



} //end of party 0
    if(my_id==1){
      lambda_y1.push_back(this->input_b_->get_secret_share()[0]);
      std::cout <<"my_id="<< my_id << " MULT Lambda_y1 "<< this->input_b_->get_secret_share()[0]<<" lambda_y1 "<<lambda_y1[0] <<std::endl;
      lambda_x1.push_back(this->input_a_->get_secret_share()[0]);
      std::cout <<"my_id="<< my_id << " MULT Lambda_x1 "<< this->input_a_->get_secret_share()[0]<<" lambda_x1 "<<lambda_x1[0] <<std::endl;
      lambda_y2.push_back(this->input_b_->get_public_share_2()[0]);
      std::cout <<"my_id="<< my_id << "MULT lambda_y2  "<< this->input_b_->get_public_share_2()[0]<<" lambda_y2 "<<lambda_y2[0] <<std::endl;

      lambda_x2.push_back(this->input_a_->get_secret_share_2()[0]);
      std::cout <<"my_id="<< my_id << " MULT lambda_x2 "<< this->input_a_->get_secret_share_2()[0]<<" lambda_x2 "<<lambda_x2[0] <<std::endl;

      std::cout<< " -------- retrieved (2,3) SS of lambda_a lambda_b --------" <<std::endl;
      //-----------------common between p1 and  p2------------------------------
       auto& rng8 = mbp.get_my_randomness_generator(2);
       auto tmp1=rng8.GetUnsigned<T>(this->gate_id_, 3);
       auto& rng13 = mbp.get_my_randomness_generator(my_id);
       auto tmp13=rng13.GetUnsigned<T>(this->gate_id_, 1); //lambda_p1
       std::vector<T> r12;
       std::vector<T> p12;
       std::vector<T> row12;
       r12.push_back(tmp1[0]);
       p12.push_back(tmp13[0]);
       row12.push_back(tmp1[2]);
       std::cout<<" yoyo r1="<<r12[0]<<std::endl;
       std::cout<<" yoyo p1="<<p12[0]<<std::endl;
       std::cout<<" yoyo row1="<<row12[0]<<std::endl;
       this->output_->get_secret_share_0().push_back(r12[0]); //r1
       this->output_->get_public_share_0().push_back(p12[0]); //lambda_p1
       std::vector<T> neg;
       MAX64v.resize(this->input_a_->get_num_simd());
       r12.resize(this->input_a_->get_num_simd());
       neg.resize(this->input_a_->get_num_simd()); //lambda_r1
       this->output_->get_public_share_0().resize(this->input_a_->get_num_simd());//lambda_p0
       this->output_->get_secret_share_3().resize(this->input_a_->get_num_simd()); //z1
       std::transform(std::begin(MAX64v),
               std::end(MAX64v),
               std::begin(r12),
               std::begin(neg), std::minus{});
       neg[0]=neg[0]+1; //neg=Lambda_r0
       std::transform(std::begin(neg),
               std::end(neg),
               std::begin(this->output_->get_public_share_0()),
               std::begin(this->output_->get_secret_share_3()), std::plus{}); //lambda_r0 + lambda_p = lambda_z0
     std::cout <<"my_id="<< my_id << " MULT lambda_z1  "<< this->output_->get_secret_share_3()[0]<<" " <<std::endl;
     //===========end of common part between p1 and p2============
     //===========start of common part between p1 and p0==========
     auto& rng5 = mbp.get_their_randomness_generator(0);
     auto tmp2=rng5.GetUnsigned<T>(this->gate_id_, 3); //lambda_z2
     auto& rng6 = mbp.get_our_randomness_generator(0);
     auto tmp6=rng6.GetUnsigned<T>(this->gate_id_, 1); //lambda_p0
     std::vector<T> p00;
     std::vector<T> r10;
     std::vector<T> p10;
     std::vector<T> row10;
     r10.push_back(tmp2[0]);
     p10.push_back(tmp2[1]);
     p00.push_back(tmp6[0]);
     row10.push_back(tmp2[2]);
     std::cout<<" yoyo r2="<<r10[0]<<std::endl;
     std::cout<<" yoyo p2="<<p10[0]<<std::endl;
     std::cout<<" yoyo row2="<<row10[0]<<std::endl;
     std::cout<<" yoyo p0="<<p00[0]<<std::endl;
     this->output_->get_secret_share_1().push_back(r10[0]); //lambda_r2
     this->output_->get_public_share_1().push_back(p10[0]); //lambda_p2
     this->output_->get_secret_share_4().push_back(p00[0]); //lambda_p0
     this->output_->get_public_share_1().resize(this->input_a_->get_num_simd());
     this->output_->get_public_share_3().resize(this->input_a_->get_num_simd());
     std::vector<T> neg1;
     MAX64v.resize(this->input_a_->get_num_simd());
     r10.resize(this->input_a_->get_num_simd());
     neg1.resize(this->input_a_->get_num_simd()); //lambda_r2
     this->output_->get_public_share_1().resize(this->input_a_->get_num_simd());//lambda_p2
     this->output_->get_secret_share_3().resize(this->input_a_->get_num_simd()); //z1
     std::transform(std::begin(MAX64v),
             std::end(MAX64v),
             std::begin(r10),
             std::begin(neg1), std::minus{});
     neg1[0]=neg1[0]+1; //neg=Lambda_r2
     std::transform(std::begin(neg1),
             std::end(neg1),
             std::begin(this->output_->get_public_share_1()),
             std::begin(this->output_->get_public_share_3()), std::plus{}); //lambda_r0 + lambda_p = lambda_z0
   std::cout <<"my_id="<< my_id << " MULT lambda_z2  "<< this->output_->get_public_share_3()[0]<<" " <<std::endl;
  //===========end of common part between p1 and p0==================
   std::cout<<"\n ----------------start of MULT of DIZK------------------------ \n"<<std::endl;
   std::vector<T> u1;
   std::vector<T> u2;
   std::vector<T> v1;
   std::vector<T> v2;

   v1.push_back(lambda_x2[0]);
   v2.push_back(lambda_x1[0]);
   u1.push_back(lambda_y2[0]); //shared with p0
   u2.push_back(lambda_y1[0]); //shared with p2

   std::vector<T> alpha1(num_simd_);
   std::transform(std::begin(row10),
          std::end(row10),
          std::begin(row12),
          std::begin(alpha1), std::minus{}); // alpha0= row0-row3;
  std::cout <<"my_id="<< my_id << " MULT alpha1 "<< alpha1[0]<<" " <<std::endl;
  std::vector<T> term1(1);
  std::vector<T> term2(1);
  std::vector<T> term3(1);
  std::vector<T> term4(1);
  std::vector<T> term5(1);
  std::vector<T> z2(1); //change here
  std::transform(std::begin(u1),
         std::end(u1),
         std::begin(v1),
         std::begin(term1), std::multiplies{}); // u1.v1
  std::cout<<" u1 "<<u1[0]<<" v1 "<<v1[0]<< " u1.v1 "<< term1[0]<<std::endl;
  std::transform(std::begin(u1),
         std::end(u1),
         std::begin(v2),
         std::begin(term2), std::multiplies{}); // u1.v2
  std::cout<<" u1 "<<u1[0]<<" v2 "<<v2[0]<< " u1.v2 "<< term2[0]<<std::endl;
   std::transform(std::begin(u2),
           std::end(u2),
           std::begin(v1),
           std::begin(term3), std::multiplies{});
  std::cout<<" u2 "<<u2[0]<<" v1 "<<v1[0]<< " u2.v1 "<< term3[0]<<std::endl;
   std::transform(std::begin(term1),
         std::end(term1),
         std::begin(term2),
         std::begin(term4), std::plus{}); // u1.v1 + u1.v2
  std::cout<<" term1 + term2 = term4 "<< term4[0]<<std::endl;
   std::transform(std::begin(term4),
         std::end(term4),
         std::begin(term3),
         std::begin(term5), std::plus{}); // u1.v1 + u1.v2 + u2.v1
  std::cout<<" term5= term4 + term3 "<< term5[0]<<std::endl;
  std::transform(std::begin(term5),
       std::end(term5),
       std::begin(alpha1),
       std::begin(z2), std::plus{}); // u1.v1 + u1.v2 + u2.v1
  std::cout<< "term5 + alpha1= z2 " <<z2[0]<<std::endl;
  std::cout <<"my_id="<< my_id << " MULT z2 generated "<< z2[0]<<" " <<std::endl;
  beavy_provider_.send_ints_message(0, this->gate_id_, z2, 1);
  auto z1=share_future1_.get();
  std::cout<< "++++++++++++++++++++ z1 received from p2 +++++++++++++++" <<z1[0]<<std::endl;
  std::cout<< " \n---------------end of MULT of DIZK ------------\n" <<std::endl;
  std::vector<T> gamma_r_2(num_simd_); //common between p0 and p1
  std::transform(std::begin(z2),
        std::end(z2),
        std::begin(r10),
        std::begin(gamma_r_2), std::minus{});
  std::cout <<"my_id="<< my_id << " MULT gamma_r_2 "<< gamma_r_2[0]<<" " <<std::endl;
  std::vector<T> gamma_r_1(num_simd_);
  std::transform(std::begin(z1),
        std::end(z1),
        std::begin(r12), //z1 is received from p2 //r12 is (p0,p2)
        std::begin(gamma_r_1), std::minus{});
    std::cout <<"my_id="<< my_id << " MULT gamma_r_1 "<< gamma_r_1[0]<<" " <<std::endl;
    this->output_->get_secret_share_2()=gamma_r_2; //nijer ta
    this->output_->get_public_share_2()=gamma_r_1; //onner ta
    // this->output_->set_setup_ready();

    std::vector<T> zero_v(1);
    zero_v.push_back(0);

    beavy_provider_.set_cckt(this-> gate_id_, u1, u2, v1, v2, z2, z1, alpha1,  row10, row12);
    std::size_t last_mult_gate_id=99;
    beavy_provider_.DIZK_verify(last_mult_gate_id);
    this->output_->set_setup_ready();


    }
    if(my_id==2){
      lambda_x0.push_back(this->input_a_->get_secret_share_0()[0]);
      std::cout <<"my_id="<< my_id << " MULT Lambda_x0 "<< this->input_a_->get_secret_share_0()[0]<<" lambda_x0 "<<lambda_x0[0] <<std::endl;
      lambda_y0.push_back(this->input_b_->get_public_share_1()[0]);
      std::cout <<"my_id="<< my_id << " MULT Lambda_y0 "<< this->input_b_->get_public_share_1()[0]<<" lambda_y0 "<<lambda_y0[0] <<std::endl;
      lambda_x1.push_back(this->input_a_->get_public_share_0()[0]);
      std::cout <<"my_id="<< my_id << "MULT lambda_x1 "<< this->input_a_->get_public_share_0()[0]<<" lambda_x1 "<<lambda_x1[0] <<std::endl;
      lambda_y1.push_back(this->input_b_->get_secret_share_1()[0]);
      std::cout <<"my_id="<< my_id << " MULT lambda_y1 "<< this->input_b_->get_secret_share_1()[0]<<" lambda_y1 "<< lambda_y1[0] <<std::endl;

      //==================common between p2 and p0
      auto& rng3 = mbp.get_their_randomness_generator(0);
      auto tmp3=rng3.GetUnsigned<T>(this->gate_id_-1, 3);
      auto& rng9 = mbp.get_our_randomness_generator(0);
      auto tmp9=rng9.GetUnsigned<T>(this->gate_id_-1, 1);
      std::vector<T> r20;
      std::vector<T> p20;
      std::vector<T> row20;
      r20.push_back(tmp3[0]); //r0
      p20.push_back(tmp9[0]); //p0
      row20.push_back(tmp3[2]); //row0
      std::cout<<" yoyo r0="<<r20[0]<<std::endl;
      std::cout<<" yoyo p0="<<p20[0]<<std::endl;
      std::cout<<" yoyo row0="<<row20[0]<<std::endl;
      this->output_->get_secret_share_0().push_back(r20[0]); //r0
      this->output_->get_public_share_0().push_back(p20[0]); //p0
      std::vector<T> neg;
      // MAX64v.resize(this->input_a_->get_num_simd());
      // r20.resize(this->input_a_->get_num_simd());
      neg.resize(this->input_a_->get_num_simd());
      this->output_->get_public_share_0().resize(this->input_a_->get_num_simd());
      this->output_->get_secret_share_3().resize(this->input_a_->get_num_simd());
      std::transform(std::begin(MAX64v),
              std::end(MAX64v),
              std::begin(r20),
              std::begin(neg), std::minus{});
      neg[0]=neg[0]+1; //neg=Lambda_r0
      std::transform(std::begin(neg),
              std::end(neg),
              std::begin(this->output_->get_public_share_0()),
              std::begin(this->output_->get_secret_share_3()), std::plus{}); //lambda_r0 + lambda_p = lambda_z
      std::cout <<"my_id="<< my_id << " MULT lambda_z0  "<< this->output_->get_secret_share_3()[0]<<" " <<std::endl;
    //===================common between p2 and p1=============
    auto& rng10 = mbp.get_their_randomness_generator(1);
    auto tmp10=rng10.GetUnsigned<T>(this->gate_id_-1, 3);
    auto& rng11 = mbp.get_our_randomness_generator(1);
    auto tmp11=rng11.GetUnsigned<T>(this->gate_id_-1, 3);
    std::vector<T> r21;
    std::vector<T> p21;
    std::vector<T> row21;
    r21.push_back(tmp10[0]);
    p21.push_back(tmp11[0]);
    row21.push_back(tmp10[2]);
    std::cout<<" yoyo r1="<<r21[0]<<std::endl;
    std::cout<<" yoyo p1="<<p21[0]<<std::endl;
    std::cout<<" yoyo row1="<<row21[0]<<std::endl;
    this->output_->get_secret_share_1().push_back(r21[0]); //r1
    this->output_->get_public_share_1().push_back(p21[0]); //lambda_p1
    std::vector<T> neg1;
    // MAX64v.resize(this->input_a_->get_num_simd());
    // r21.resize(this->input_a_->get_num_simd());
    neg1.resize(this->input_a_->get_num_simd());
    this->output_->get_public_share_1().resize(this->input_a_->get_num_simd());
    this->output_->get_public_share_3().resize(this->input_a_->get_num_simd());
    std::transform(std::begin(MAX64v),
            std::end(MAX64v),
            std::begin(r21),
            std::begin(neg1), std::minus{});
    neg1[0]=neg1[0]+1; //neg=Lambda_r0
    std::transform(std::begin(neg1),
            std::end(neg1),
            std::begin(this->output_->get_public_share_1()),
            std::begin(this->output_->get_public_share_3()), std::plus{}); //lambda_r0 + lambda_p = lambda_z
    std::cout <<"my_id="<< my_id << " MULT lambda_z1 "<< this->output_->get_public_share_3()[0]<<" " <<std::endl;
    std::cout<< " -------- retrieved (2,3) SS of lambda_a lambda_b --------" <<std::endl;
    std::cout<<"\n ----------------start of MULT of DIZK------------------------ \n"<<std::endl;
    std::vector<T> u1;
    std::vector<T> u2;
    std::vector<T> v1;
    std::vector<T> v2;
    v1.push_back(lambda_x1[0]);
    v2.push_back(lambda_x0[0]);
    u1.push_back(lambda_y1[0]); //shared with p1
    u2.push_back(lambda_y0[0]); //shared with p0
    std::vector<T> alpha2(num_simd_);
    std::transform(std::begin(row21),
           std::end(row21),
           std::begin(row20),
           std::begin(alpha2), std::minus{}); // alpha0= row0-row3;
    std::cout <<"my_id="<< my_id << " MULT alpha2 "<< alpha2[0]<<" " <<std::endl;
    std::vector<T> term1(1);
    std::vector<T> term2(1);
    std::vector<T> term3(1);
    std::vector<T> term4(1);
    std::vector<T> term5(1);
    std::vector<T> z1(1);
    std::transform(std::begin(u1),
           std::end(u1),
           std::begin(v1),
           std::begin(term1), std::multiplies{}); // u1.v1
    std::cout <<"my_id="<< my_id << " MULT term1 = u1.v1 "<< term1[0]<<" " <<std::endl;
    std::transform(std::begin(u1),
          std::end(u1),
          std::begin(v2),
          std::begin(term2), std::multiplies{}); // u1.v2
    std::cout<<" u1 "<<u1[0]<<" v2 "<<v2[0]<< " u1.v2 "<< term2[0]<<std::endl;
    std::transform(std::begin(u2),
            std::end(u2),
            std::begin(v1),
            std::begin(term3), std::multiplies{}); // u2.v1
    std::cout<<" u2 "<<u2[0]<<" v1 "<<v1[0]<< " u2.v1 "<< term3[0]<<std::endl;
    std::transform(std::begin(term1),
          std::end(term1),
          std::begin(term2),
          std::begin(term4), std::plus{}); // u1.v1 + u1.v2
    std::cout<<" term1 + term2 = term4 "<< term4[0]<<std::endl;
    std::transform(std::begin(term4),
          std::end(term4),
          std::begin(term3),
          std::begin(term5), std::plus{}); // u1.v1 + u1.v2 + u2.v1
      std::cout<<" term5= term4 + term3 "<< term5[0]<<std::endl;
    std::transform(std::begin(term5),
          std::end(term5),
          std::begin(alpha2),
          std::begin(z1), std::plus{}); // u1.v1 + u1.v2 + u2.v1
    std::cout<< "term5 + alpha1= z1 " <<z1[0]<<std::endl;
    std::cout <<"my_id="<< my_id << " MULT z1 generated "<< z1[0]<<" " <<std::endl;
    beavy_provider_.send_ints_message(1, this->gate_id_-1, z1 ,1);
    auto z0=share_future2_.get();
    std::cout<<" z0 received from p0 " << z1[0] <<std::endl;
    std::vector<T> gamma_r_0(num_simd_);
    std::transform(std::begin(z0),
          std::end(z0),
          std::begin(r20),
          std::begin(gamma_r_0), std::minus{});
    std::cout <<"my_id="<< my_id << " MULT gamma_r_0 "<< gamma_r_0[0]<<" " <<std::endl;
    std::vector<T> gamma_r_1(num_simd_);
    std::transform(std::begin(z1),
          std::end(z1),
          std::begin(r21),
          std::begin(gamma_r_1), std::minus{});
    std::cout <<"my_id="<< my_id << " MULT gamma_r_1 "<< gamma_r_1[0]<<" " <<std::endl;
    this->output_->get_secret_share_2()=gamma_r_0; //nijer ta
    this->output_->get_public_share_2()=gamma_r_1; //onner ta
    // this->output_->set_setup_ready();

    std::vector<T> zero_v(1);
    zero_v.push_back(0);
    //
    // beavy_provider_.set_cckt(this->gate_id_, zero_v, u2, zero_v, v2, zero_v, row20);
    beavy_provider_.set_cckt(this->gate_id_, u1, u2, v1, v2, z1, z0, alpha2, row21, row20);
    std::size_t last_mult_gate_id=99;
    beavy_provider_.DIZK_verify(last_mult_gate_id);
    this->output_->set_setup_ready();

    }




  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYMULGate::evaluate_setup end", this->gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYMULGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYMULGate<T>::evaluate_online start", this->gate_id_));

    }
  }
  auto my_id = beavy_provider_.get_my_id();
  auto num_simd = this->input_a_->get_num_simd();
  this->input_a_->wait_online();
  this->input_b_->wait_online();
  auto& m_x = this->input_a_->get_public_share(); //Delta_a
  auto& m_y = this->input_b_->get_public_share(); //Delta_b
  if(my_id==0){
      std::cout<<" MULT ONLINE gamma_ab0 - r0 " <<this->output_->get_secret_share_2()[0]<<std::endl;
      std::cout<<" MULT online gamma_ab2 - r2 " <<this->output_->get_public_share_2()[0]<<std::endl;
      std::cout<<" MULT online Lambda_x0" <<this->input_a_->get_secret_share()[0]<<std::endl;
      std::cout<<" MULT online Lambda_y0" <<this->input_b_->get_secret_share()[0]<<std::endl;
      //======y0=-lambda_x0.my -lambda_y0.mx + (gamma_ab0- r0)
      //y0=Delta_y_share0_
      std::vector<T> Delta_y_share0_; //y0
      // this->output_->get_secret_share_2().resize(this->input_b_->get_num_simd());
      Delta_y_share0_.resize(this->input_b_->get_num_simd());
      std::transform(std::begin(this->output_->get_secret_share_2()),  std::end(this->output_->get_secret_share_2()), std::begin(Delta_y_share0_),
                     std::begin(Delta_y_share0_), std::plus{}); // + gammaxy_r0
      std::vector<T> term1;
      // this->input_a_->get_secret_share().resize(this->input_a_->get_num_simd());
      term1.resize(this->input_b_->get_num_simd());
      Delta_y_share0_.resize(this->input_b_->get_num_simd());
      std::transform(std::begin(this->input_a_->get_secret_share()), std::end(this->input_a_->get_secret_share()), std::begin(m_y),
                     std::begin(term1), std::multiplies{});
       Delta_y_share0_.resize(this->input_b_->get_num_simd());
       term1.resize(this->input_b_->get_num_simd());
       std::transform(std::begin(Delta_y_share0_), std::end(Delta_y_share0_), std::begin(term1),
        std::begin(Delta_y_share0_), std::minus{});
        std::vector<T> term2;
        // this->input_b_->get_secret_share().resize(this->input_a_->get_num_simd());
        term2.resize(this->input_b_->get_num_simd());
        std::transform(std::begin(this->input_b_->get_secret_share()), std::end(this->input_b_->get_secret_share()), std::begin(m_x),
                       std::begin(term2), std::multiplies{});
       term2.resize(this->input_b_->get_num_simd());
       Delta_y_share0_.resize(this->input_b_->get_num_simd());
       std::transform(std::begin(Delta_y_share0_), std::end(Delta_y_share0_), std::begin(term2),
                      std::begin(Delta_y_share0_), std::minus{});
      std::cout<< " MULT online::  Delta_y_share0_=y0= "<<Delta_y_share0_[0]<<std::endl;
      //
      //y2=-lambda_x2.my -lambda_y2.mx + (gamma_ab2- r2)
      std::vector<T> Delta_y_share2_;
      std::cout<<" MULT ONLINE lambda_x2 = "<<this->input_a_->get_public_share_2()[0]<<std::endl;
      std::cout<<" MULT ONLINE lambda_y2 = "<<this->input_b_->get_secret_share_2()[0]<<std::endl;
      // this->output_->get_public_share_2().resize(this->input_a_->get_num_simd());
      Delta_y_share2_.resize(this->input_a_->get_num_simd());
      std::transform(std::begin(Delta_y_share2_), std::end(Delta_y_share2_), std::begin(this->output_->get_public_share_2()),
                     std::begin(Delta_y_share2_), std::plus{});
     std::vector<T> term3;
     // this->input_a_->get_secret_share().resize(this->input_a_->get_num_simd());
     term3.resize(this->input_a_->get_num_simd());
     std::transform(std::begin(this->input_a_->get_public_share_2()), std::end(this->input_a_->get_public_share_2()), std::begin(m_y),
                    std::begin(term3), std::multiplies{});
    Delta_y_share2_.resize(this->input_a_->get_num_simd());
    term3.resize(this->input_a_->get_num_simd());
    std::transform(std::begin(Delta_y_share2_), std::end(Delta_y_share2_), std::begin(term3),
                   std::begin(Delta_y_share2_), std::minus{});
     std::vector<T> term4;
     // this->input_b_->get_secret_share_2().resize(this->input_b_->get_num_simd());
     term4.resize(this->input_b_->get_num_simd());
     std::transform(std::begin(this->input_b_->get_secret_share_2()), std::end(this->input_b_->get_secret_share_2()), std::begin(m_x),
                    std::begin(term4), std::multiplies{});
    Delta_y_share2_.resize(this->input_b_->get_num_simd());
    term4.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(Delta_y_share2_), std::end(Delta_y_share2_), std::begin(term4),
                  std::begin(Delta_y_share2_), std::minus{});
    std::cout<< " MULT online::  Delta_y_share2_ = y2= "<<Delta_y_share2_[0]<<std::endl;
    //p0 and p2 send y0 to p1
    beavy_provider_.send_ints_message(1, this->gate_id_, Delta_y_share0_, 2 ); //2nd message
    auto y1= share_future00_.get();
    std::cout<<" JUST FOR CORRECTNESS(plug in JSend): y1 received from p1 "<<y1[0]<<std::endl;
    //calculate p=y0+y1+y2 + mxy //Delta_y_share0_ + y1[0] + Delta_y_share2_
    std::vector<T> p0;
    p0.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(p0),  std::end(p0), std::begin(Delta_y_share0_),
                   std::begin(p0), std::plus{});
    p0.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(p0),  std::end(p0), std::begin(Delta_y_share2_),
                   std::begin(p0), std::plus{});
    std::transform(std::begin(p0),  std::end(p0), std::begin(y1),
                 std::begin(p0), std::plus{});
    std::vector<T> tmp; //mx.my
   tmp.resize(this->input_b_->get_num_simd());
   std::transform(std::begin(m_x),  std::end(m_x), std::begin(m_y),
                 std::begin(tmp), std::multiplies{});
   p0.resize(this->input_b_->get_num_simd());
   std::transform(std::begin(p0),  std::end(p0), std::begin(tmp),
                 std::begin(p0), std::plus{});
  std::cout<<" p=y0+y1+y2 + mxy " <<p0[0]<<std::endl;
  std::cout<< " \n---------TESTED both p0 and p1 get the same p-----------\n"<<std::endl;
  std::cout<<" lambda_p0 = "<<this->output_->get_public_share_0()[0]<<std::endl;
  std::cout<<" lambda_p1 = "<<this->output_->get_secret_share_4()[0]<<std::endl;
  std::cout<<" lambda_p2 = "<<this->output_->get_public_share_1()[0]<<std::endl;


  std::vector<T> mp0;
  mp0.resize(this->input_b_->get_num_simd());
  std::transform(std::begin(p0),  std::end(p0), std::begin(this->output_->get_public_share_0()),
               std::begin(mp0), std::plus{});
   std::transform(std::begin(mp0),  std::end(mp0), std::begin(this->output_->get_public_share_1()),
                std::begin(mp0), std::plus{});
  std::transform(std::begin(mp0),  std::end(mp0), std::begin(this->output_->get_secret_share_4()),
               std::begin(mp0), std::plus{});
  std::cout<<" mp0 = "<<mp0[0]<<std::endl;
  // beavy_provider_.send_ints_message(1, this->gate_id_, mp0, 3);
  // auto mp1=share_future01_.get();
  // std::cout<< " mp1 got from p1 = "<<mp1[0]<<std::endl;
  this->output_->get_public_share()=std::move(mp0); //mz=mp+mr //since mr=0, so mz=mp set as publicshare
  // this->output->get_public_share_4()=std::move(mp1);
  this->output_->set_online_ready();
  }//end of party 0
  if(my_id==1){
      std::cout<<" MULT online lambda_y1 = " <<this->input_b_->get_secret_share()[0]<<std::endl;
      std::cout<<" MULT online lambda_x1 = " <<this->input_a_->get_secret_share()[0]<<std::endl;
      std::cout <<"MULT lambda_y2 = "<< this->input_b_->get_public_share_2()[0]<<std::endl;
      std::cout <<" MULT lambda_x2 = "<< this->input_a_->get_secret_share_2()[0]<<std::endl;
      std::cout<<" MULT online, gamma_r_1 = "<< this->output_->get_public_share_2()[0]<<std::endl;
      std::cout<<" MULT online, gamma_r_2 = "<< this->output_->get_secret_share_2()[0]<<std::endl; //p1 has generated z2. so p1 would have z2 in the secret share label.
      //y1=-lambda_x1.m_y - lambda_y1.m_x + (Gamma_xy - r)^1
      std::vector<T> Delta_y_share1_;
      // this->output_->get_public_share_2().resize(this->input_a_->get_num_simd()); //gamma_r_2
      Delta_y_share1_.resize(this->input_a_->get_num_simd());
      std::transform(std::begin(Delta_y_share1_),
                              std::end(Delta_y_share1_),
                              std::begin(this->output_->get_public_share_2()),
                              std::begin(Delta_y_share1_), std::plus{});
      std::vector<T> term5;
      // this->input_a_->get_secret_share().resize(this->input_a_->get_num_simd());
      term5.resize(this->input_a_->get_num_simd());
      std::transform(std::begin(this->input_a_->get_secret_share()),  std::end(this->input_a_->get_secret_share()), std::begin(m_y),
       std::begin(term5), std::multiplies{}); //lambda_x1.my
       term5.resize(this->input_a_->get_num_simd());
       Delta_y_share1_.resize(this->input_a_->get_num_simd());
       std::transform(std::begin(Delta_y_share1_), std::end(Delta_y_share1_), std::begin(term5),
      std::begin(Delta_y_share1_), std::minus{});
      std::vector<T> term6; //lambda_y1.mx
      // this->input_a_->get_secret_share().resize(this->input_a_->get_num_simd());
      term6.resize(this->input_a_->get_num_simd());
      std::transform(std::begin(this->input_b_->get_secret_share()),  std::end(this->input_b_->get_secret_share()), std::begin(m_x),
                     std::begin(term6), std::multiplies{}); //lambda_y1.mx
     term6.resize(this->input_a_->get_num_simd());
     Delta_y_share1_.resize(this->input_a_->get_num_simd());
     std::transform(std::begin(Delta_y_share1_), std::end(Delta_y_share1_), std::begin(term6),
                    std::begin(Delta_y_share1_), std::minus{}); //-lambda_y1.mx
    std::cout<<"  Delta_y_share1_ =y1  =" <<Delta_y_share1_[0]<<std::endl;
  //y2=-lambda_x2.m_y -lambda_y2.m_x + (gamma_xy-r)^2
  std::vector<T> Delta_y_share2_;
  Delta_y_share2_.resize(this->input_a_->get_num_simd());
  std::transform(std::begin(Delta_y_share2_),
                          std::end(Delta_y_share2_),
                          std::begin(this->output_->get_secret_share_2()),
                          std::begin(Delta_y_share2_), std::plus{});
  std::vector<T> term7;
  term7.resize(this->input_a_->get_num_simd());
  std::transform(std::begin(this->input_a_->get_secret_share_2()),  std::end(this->input_a_->get_secret_share_2()), std::begin(m_y),
   std::begin(term7), std::multiplies{}); //lambda_x2.my
   term7.resize(this->input_a_->get_num_simd());
   Delta_y_share2_.resize(this->input_a_->get_num_simd());
   std::transform(std::begin(Delta_y_share2_), std::end(Delta_y_share2_), std::begin(term7),
      std::begin(Delta_y_share2_), std::minus{});
  std::vector<T> term4;
  term4.resize(this->input_b_->get_num_simd());
  std::transform(std::begin(this->input_b_->get_public_share_2()), std::end(this->input_b_->get_public_share_2()), std::begin(m_x),
                 std::begin(term4), std::multiplies{}); //lambda_y2.mx
 Delta_y_share2_.resize(this->input_b_->get_num_simd());
 term4.resize(this->input_b_->get_num_simd());
 std::transform(std::begin(Delta_y_share2_), std::end(Delta_y_share2_), std::begin(term4),
               std::begin(Delta_y_share2_), std::minus{});
 std::cout<< " MULT online::  Delta_y_share2_ = y2= "<<Delta_y_share2_[0]<<std::endl;
 //p1 and p2 send y1 to p0
  beavy_provider_.send_ints_message(0, this->gate_id_, Delta_y_share1_, 2 );
  auto y0= share_future11_.get();
  std::cout<<" JUST FOR CORRECTNESS(plug in JSend): y0 received from p0 "<<y0[0]<<std::endl;
  //calculate p1=y0+y1+y2 + mxy //y0 + Delta_y_share1_ + Delta_y_share2_
  std::vector<T> p1;
  p1.resize(this->input_b_->get_num_simd());
  std::transform(std::begin(p1),  std::end(p1), std::begin(Delta_y_share2_),
                 std::begin(p1), std::plus{});
  p1.resize(this->input_b_->get_num_simd());
  std::transform(std::begin(p1),  std::end(p1), std::begin(Delta_y_share1_),
                 std::begin(p1), std::plus{});
  std::transform(std::begin(p1),  std::end(p1), std::begin(y0),
               std::begin(p1), std::plus{});
  std::vector<T> tmp; //mx.my
  tmp.resize(this->input_b_->get_num_simd());
  std::transform(std::begin(m_x),  std::end(m_x), std::begin(m_y),
               std::begin(tmp), std::multiplies{});
  p1.resize(this->input_b_->get_num_simd());
  std::transform(std::begin(p1),  std::end(p1), std::begin(tmp),
               std::begin(p1), std::plus{});
  std::cout<<" p=y0+y1+y2 + mxy " <<p1[0]<<std::endl;
  std::cout<< " \n---------TESTED both p0 and p1 get the same p-----------\n"<<std::endl;
  //mp= p+ lambda_p
  std::vector<T> mp1;
  mp1.resize(this->input_b_->get_num_simd());
  std::cout<<" lambda_p0 = "<<this->output_->get_secret_share_4()[0]<<std::endl;
  std::cout<<" lambda_p1 = "<<this->output_->get_public_share_0()[0]<<std::endl;
  std::cout<<" lambda_p2 = "<<this->output_->get_public_share_1()[0]<<std::endl;


  std::transform(std::begin(p1),  std::end(p1), std::begin(this->output_->get_public_share_0()),
               std::begin(mp1), std::plus{});
   std::transform(std::begin(mp1),  std::end(mp1), std::begin(this->output_->get_public_share_1()),
                std::begin(mp1), std::plus{});
  std::transform(std::begin(mp1),  std::end(mp1), std::begin(this->output_->get_secret_share_4()),
               std::begin(mp1), std::plus{});
  std::cout<<" mp1 = "<<mp1[0]<<std::endl;
  //beavy_provider_.broadcast_ints_message(this->gate_id_, mp1); //this is just for verfication to be sent to p2
  // beavy_provider_.send_ints_message(0, this->gate_id_, mp1, 3);
  // auto mp0=share_future10_.get();
  // std::cout<< " mp1 got from p1 = "<<mp0[0]<<std::endl;
  this->output_->get_public_share()=std::move(mp1); //mz=mp+mr //since mr=0, so mz=mp set as publicshare //nijer ta public_share label e
  // this->output->get_public_share_4()=std::move(mp1);


    this->output_->set_online_ready();


  }
  if(my_id==2){
    std::cout<<" MULT online m_x "<<this->input_a_->get_public_share_3()[0]<<std::endl;
    std::cout<<" MULT online m_y "<<this->input_b_->get_public_share()[0]<<std::endl;
    std::cout<<" MULT online lambda_x0 " <<this->input_a_->get_secret_share_0()[0]<<std::endl;
    std::cout<<" MULT online lambda_y0 " <<this->input_b_->get_public_share_1()[0]<<std::endl;
    std::cout <<"MULT online lambda_x1 "<< this->input_a_->get_public_share_0()[0]<<std::endl;
    std::cout <<"MULT online lambda_y1 "<< this->input_b_->get_secret_share_1()[0]<<std::endl;
    std::cout<<" MULT online gamma_r_1 " <<this->output_->get_public_share_2()[0]<<std::endl;
    std::cout<<" MULT online gamma_r_0 " <<this->output_->get_secret_share_2()[0]<<std::endl;
    m_x = this->input_a_->get_public_share_3(); //Delta_a
    m_y = this->input_b_->get_public_share();
    //======y0=-lambda_x0.my -lambda_y0.mx + (gamma_ab0- r0)
    //y0=Delta_y_share0_
    std::vector<T> Delta_y_share0_; //y0
    // this->output_->get_secret_share_2().resize(this->input_b_->get_num_simd());
    Delta_y_share0_.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(this->output_->get_secret_share_2()),  std::end(this->output_->get_secret_share_2()), std::begin(Delta_y_share0_),
                   std::begin(Delta_y_share0_), std::plus{}); // + gammaxy_r0
    std::vector<T> term10;
    // this->input_a_->get_secret_share_0().resize(this->input_a_->get_num_simd()); //lambda_x0
    term10.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(this->input_a_->get_secret_share_0()),  std::end(this->input_a_->get_secret_share_0()), std::begin(m_y),
                   std::begin(term10), std::multiplies{}); //lambda_x0.my
    Delta_y_share0_.resize(this->input_b_->get_num_simd());
    term10.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(Delta_y_share0_),  std::end(Delta_y_share0_), std::begin(term10),
                   std::begin(Delta_y_share0_), std::minus{}); //lambda_x0.my
    std::vector<T> term11; //lambda_y0.mx
    // this->input_b_->get_secret_share_1().resize(this->input_b_->get_num_simd());
    term11.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(this->input_b_->get_public_share_1()),  std::end(this->input_b_->get_public_share_1()), std::begin(m_x),
                   std::begin(term11), std::multiplies{}); //lambda_y0.my
    term11.resize(this->input_b_->get_num_simd());
    Delta_y_share0_.resize(this->input_b_->get_num_simd());
   std::transform(std::begin(Delta_y_share0_),  std::end(Delta_y_share0_), std::begin(term11),
                  std::begin(Delta_y_share0_), std::minus{}); //
   std::cout<<"  Delta_y_share0_ =y0  =" <<Delta_y_share0_[0]<<std::endl;
   //y1= -lambda_x1.my - lambda_y1.mx + (gamma_xy_r1)
   std::vector<T> Delta_y_share1_;
   this->output_->get_public_share_2().resize(this->input_b_->get_num_simd());
   Delta_y_share1_.resize(this->input_b_->get_num_simd());
   std::transform(std::begin(Delta_y_share1_),  std::end(Delta_y_share1_), std::begin(this->output_->get_public_share_2()),
                  std::begin(Delta_y_share1_), std::plus{}); //gamma_xy1-r1
  std::vector<T> term13; //lambda_x1.my
  this->input_a_->get_public_share_0().resize(this->input_a_->get_num_simd()); //lambda_x1
  term13.resize(this->input_a_->get_num_simd());
  std::transform(std::begin(this->input_a_->get_public_share_0()),  std::end(this->input_a_->get_public_share_0()), std::begin(m_y),
                 std::begin(term13), std::multiplies{}); //lambda_x1.my
   Delta_y_share1_.resize(this->input_a_->get_num_simd());
   term13.resize(this->input_a_->get_num_simd());
   std::transform(std::begin(Delta_y_share1_), std::end(Delta_y_share1_), std::begin(term13),
    std::begin(Delta_y_share1_), std::minus{});
    std::vector<T> term12; //lambda_y1.mx
    this->input_b_->get_secret_share_1().resize(this->input_b_->get_num_simd());
    term12.resize(this->input_b_->get_num_simd());
    std::transform(std::begin(this->input_b_->get_secret_share_1()), std::end(this->input_b_->get_secret_share_1()), std::begin(m_x),
                   std::begin(term12), std::multiplies{});
   term12.resize(this->input_a_->get_num_simd());
   Delta_y_share1_.resize(this->input_a_->get_num_simd());
   std::transform(std::begin(Delta_y_share1_), std::end(Delta_y_share1_), std::begin(term12),
                  std::begin(Delta_y_share1_), std::minus{});
  std::cout<<"  Delta_y_share1_ =y1  =" <<Delta_y_share1_[0]<<std::endl; //correct
  this->output_->set_online_ready();
  }




  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYMULGate<T>::evaluate_online end", this->gate_id_));
    }
  }
}

template class ArithmeticBEAVYMULGate<std::uint8_t>;
template class ArithmeticBEAVYMULGate<std::uint16_t>;
template class ArithmeticBEAVYMULGate<std::uint32_t>;
template class ArithmeticBEAVYMULGate<std::uint64_t>;

template <typename T>
ArithmeticBEAVYSQRGate<T>::ArithmeticBEAVYSQRGate(std::size_t gate_id,
                                                  BEAVYProvider& beavy_provider,
                                                  ArithmeticBEAVYWireP<T>&& in)
    : detail::BasicArithmeticBEAVYUnaryGate<T>(gate_id, beavy_provider, std::move(in)),
      beavy_provider_(beavy_provider) {
  auto my_id = beavy_provider_.get_my_id();
  auto num_simd = this->input_->get_num_simd();
  share_future_ = beavy_provider_.register_for_ints_message<T>(1 - my_id, this->gate_id_, num_simd);
  auto& ap = beavy_provider_.get_arith_manager().get_provider(1 - my_id);
  if (my_id == 0) {
    mult_sender_ = ap.template register_integer_multiplication_send<T>(num_simd);
    mult_receiver_ = nullptr;
  } else {
    mult_receiver_ = ap.template register_integer_multiplication_receive<T>(num_simd);
    mult_sender_ = nullptr;
  }
}

template <typename T>
ArithmeticBEAVYSQRGate<T>::~ArithmeticBEAVYSQRGate() = default;

template <typename T>
void ArithmeticBEAVYSQRGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYSQRGate<T>::evaluate_setup start", this->gate_id_));
    }
  }

  auto num_simd = this->input_->get_num_simd();

  this->output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
  this->output_->set_setup_ready();

  const auto& delta_a_share = this->input_->get_secret_share();
  const auto& delta_y_share = this->output_->get_secret_share();

  if (mult_sender_) {
    mult_sender_->set_inputs(delta_a_share);
  } else {
    mult_receiver_->set_inputs(delta_a_share);
  }

  Delta_y_share_.resize(num_simd);
  // [Delta_y]_i = [delta_a]_i * [delta_a]_i
  std::transform(std::begin(delta_a_share), std::end(delta_a_share), std::begin(Delta_y_share_),
                 [](auto x) { return x * x; });
  // [Delta_y]_i += [delta_y]_i
  std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(delta_y_share),
                 std::begin(Delta_y_share_), std::plus{});

  // [[delta_a]_i * [delta_a]_(1-i)]_i
  std::vector<T> delta_aa_share;
  if (mult_sender_) {
    mult_sender_->compute_outputs();
    delta_aa_share = mult_sender_->get_outputs();
  } else {
    mult_receiver_->compute_outputs();
    delta_aa_share = mult_receiver_->get_outputs();
  }
  // [Delta_y]_i += 2 * [[delta_a]_i * [delta_a]_(1-i)]_i
  std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(delta_aa_share),
                 std::begin(Delta_y_share_), [](auto x, auto y) { return x + 2 * y; });

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYSQRGate::evaluate_setup end", this->gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYSQRGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYSQRGate<T>::evaluate_online start", this->gate_id_));
    }
  }

  auto num_simd = this->input_->get_num_simd();
  this->input_->wait_online();
  const auto& Delta_a = this->input_->get_public_share();
  const auto& delta_a_share = this->input_->get_secret_share();
  std::vector<T> tmp(num_simd);

  // after setup phase, `Delta_y_share_` contains [delta_y]_i + [delta_ab]_i

  // [Delta_y]_i -= 2 * Delta_a * [delta_a]_i
  std::transform(std::begin(Delta_a), std::end(Delta_a), std::begin(delta_a_share), std::begin(tmp),
                 [](auto x, auto y) { return 2 * x * y; });
  std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
                 std::begin(Delta_y_share_), std::minus{});

  // [Delta_y]_i += Delta_aa (== Delta_a * Delta_a)
  if (beavy_provider_.is_my_job(this->gate_id_)) {
    std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(Delta_a),
                   std::begin(Delta_y_share_), [](auto x, auto y) { return x + y * y; });
  }
  // broadcast [Delta_y]_i
  beavy_provider_.broadcast_ints_message(this->gate_id_, Delta_y_share_);
  // Delta_y = [Delta_y]_i + [Delta_y]_(1-i)
  std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
                 std::begin(share_future_.get()), std::begin(Delta_y_share_), std::plus{});
  this->output_->get_public_share() = std::move(Delta_y_share_);
  this->output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYSQRGate<T>::evaluate_online end", this->gate_id_));
    }
  }
}

template class ArithmeticBEAVYSQRGate<std::uint8_t>;
template class ArithmeticBEAVYSQRGate<std::uint16_t>;
template class ArithmeticBEAVYSQRGate<std::uint32_t>;
template class ArithmeticBEAVYSQRGate<std::uint64_t>;

template <typename T>
BooleanXArithmeticBEAVYMULGate<T>::BooleanXArithmeticBEAVYMULGate(std::size_t gate_id,
                                                                  BEAVYProvider& beavy_provider,
                                                                  BooleanBEAVYWireP&& in_a,
                                                                  ArithmeticBEAVYWireP<T>&& in_b)
    : detail::BasicBooleanXArithmeticBEAVYBinaryGate<T>(gate_id, beavy_provider, std::move(in_a),
                                                        std::move(in_b)),
      beavy_provider_(beavy_provider) {
  if (beavy_provider_.get_num_parties() != 2) {
    throw std::logic_error("currently only two parties are supported");
  }
  const auto my_id = beavy_provider_.get_my_id();
  auto num_simd = this->input_arith_->get_num_simd();
  auto& ap = beavy_provider_.get_arith_manager().get_provider(1 - my_id);
  if (beavy_provider_.is_my_job(this->gate_id_)) {
    mult_int_side_ = ap.register_bit_integer_multiplication_int_side<T>(num_simd, 2);
    mult_bit_side_ = ap.register_bit_integer_multiplication_bit_side<T>(num_simd, 1);
  } else {
    mult_int_side_ = ap.register_bit_integer_multiplication_int_side<T>(num_simd, 1);
    mult_bit_side_ = ap.register_bit_integer_multiplication_bit_side<T>(num_simd, 2);
  }
  delta_b_share_.resize(num_simd);
  delta_b_x_delta_n_share_.resize(num_simd);
  share_future_ = beavy_provider_.register_for_ints_message<T>(1 - my_id, this->gate_id_, num_simd);
}

template <typename T>
BooleanXArithmeticBEAVYMULGate<T>::~BooleanXArithmeticBEAVYMULGate() = default;

template <typename T>
void BooleanXArithmeticBEAVYMULGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanXArithmeticBEAVYMULGate<T>::evaluate_setup start", this->gate_id_));
    }
  }

  auto num_simd = this->input_arith_->get_num_simd();


  this->output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
  this->output_->set_setup_ready();

  this->input_arith_->wait_setup();
  this->input_bool_->wait_setup();
  const auto& int_sshare = this->input_arith_->get_secret_share();
  assert(int_sshare.size() == num_simd);
  const auto& bit_sshare = this->input_bool_->get_secret_share();
  assert(bit_sshare.GetSize() == num_simd);

  // Use the optimized variant from Lennart's thesis to compute the setup phase
  // using only two (vector) OTs per multiplication.

  std::vector<T> bit_sshare_as_ints(num_simd);
  for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
    bit_sshare_as_ints[int_i] = bit_sshare.Get(int_i);
  }

  mult_bit_side_->set_inputs(bit_sshare);

  if (beavy_provider_.is_my_job(this->gate_id_)) {
    std::vector<T> mult_inputs(2 * num_simd);
    for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
      mult_inputs[2 * int_i] = bit_sshare_as_ints[int_i];
      mult_inputs[2 * int_i + 1] =
          int_sshare[int_i] - 2 * bit_sshare_as_ints[int_i] * int_sshare[int_i];
    }
    mult_int_side_->set_inputs(std::move(mult_inputs));
  } else {
    std::vector<T> mult_inputs(num_simd);
    std::transform(std::begin(int_sshare), std::end(int_sshare), std::begin(bit_sshare_as_ints),
                   std::begin(mult_inputs), [](auto n, auto b) { return n - 2 * b * n; });
    mult_int_side_->set_inputs(std::move(mult_inputs));
  }

  mult_bit_side_->compute_outputs();
  mult_int_side_->compute_outputs();
  auto mult_bit_side_out = mult_bit_side_->get_outputs();
  auto mult_int_side_out = mult_int_side_->get_outputs();

  // compute [delta_b]^A and [delta_b * delta_n]^A
  if (beavy_provider_.is_my_job(this->gate_id_)) {
    for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
      delta_b_share_[int_i] = bit_sshare_as_ints[int_i] - 2 * mult_int_side_out[2 * int_i];
      delta_b_x_delta_n_share_[int_i] = bit_sshare_as_ints[int_i] * int_sshare[int_i] +
                                        mult_int_side_out[2 * int_i + 1] + mult_bit_side_out[int_i];
    }
  } else {
    for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
      delta_b_share_[int_i] = bit_sshare_as_ints[int_i] - 2 * mult_bit_side_out[2 * int_i];
      delta_b_x_delta_n_share_[int_i] = bit_sshare_as_ints[int_i] * int_sshare[int_i] +
                                        mult_bit_side_out[2 * int_i + 1] + mult_int_side_out[int_i];
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanXArithmeticBEAVYMULGate<T>::evaluate_setup end",
                                   this->gate_id_));
    }
  }
}

template <typename T>
void BooleanXArithmeticBEAVYMULGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanXArithmeticBEAVYMULGate<T>::evaluate_online start", this->gate_id_));
    }
  }

  auto num_simd = this->input_arith_->get_num_simd();

  this->input_bool_->wait_online();
  this->input_arith_->wait_online();
  const auto& int_sshare = this->input_arith_->get_secret_share();
  const auto& int_pshare = this->input_arith_->get_public_share();
  assert(int_pshare.size() == num_simd);
  const auto& bit_pshare = this->input_bool_->get_public_share();
  assert(bit_pshare.GetSize() == num_simd);

  const auto& sshare = this->output_->get_secret_share();
  std::vector<T> pshare(num_simd);

  for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
    T Delta_b = bit_pshare.Get(simd_j);
    auto Delta_n = int_pshare[simd_j];
    pshare[simd_j] = delta_b_share_[simd_j] * (Delta_n - 2 * Delta_b * Delta_n) -
                    Delta_b * int_sshare[simd_j] -
                    delta_b_x_delta_n_share_[simd_j] * (1 - 2 * Delta_b) + sshare[simd_j];
    if (beavy_provider_.is_my_job(this->gate_id_)) {
      pshare[simd_j] += Delta_b * Delta_n;
    }
  }

  beavy_provider_.broadcast_ints_message(this->gate_id_, pshare);
  const auto other_pshare = share_future_.get();
  std::transform(std::begin(pshare), std::end(pshare), std::begin(other_pshare), std::begin(pshare),
                 std::plus{});

  this->output_->get_public_share() = std::move(pshare);
  this->output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanXArithmeticBEAVYMULGate<T>::evaluate_online end", this->gate_id_));
    }
  }
}

template class BooleanXArithmeticBEAVYMULGate<std::uint8_t>;
template class BooleanXArithmeticBEAVYMULGate<std::uint16_t>;
template class BooleanXArithmeticBEAVYMULGate<std::uint32_t>;
template class BooleanXArithmeticBEAVYMULGate<std::uint64_t>;

}  // namespace MOTION::proto::beavy
