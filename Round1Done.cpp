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

#include "beavy_provider.h"

#include <cstdint>
#include <unordered_map>

#include "base/gate_register.h"
#include "communication/communication_layer.h"
#include "communication/fbs_headers/gmw_message_generated.h"
#include "communication/message.h"
#include "communication/message_handler.h"
#include "conversion.h"
#include "crypto/motion_base_provider.h"
#include "gate.h"
#include "plain.h"
#include "protocols/gmw/wire.h"
#include "protocols/plain/wire.h"
#include "tensor_op.h"
#include "utility/constants.h"
#include "utility/logger.h"
#include "utility/meta.hpp"
#include "wire.h"


#include <vector>
// #include <type_traits>
// #include <iostream>
// #include <NTL/ZZ_p.h>
// #include <NTL/ZZ_pX.h> //z_2^k[x]
// #include <NTL/ZZ_pE.h> // z_2^k[x] / f[x]
// #include <NTL/ZZ_pEX.h>
// #include <NTL/GF2.h>  //F_2
// #include <NTL/GF2X.h>
// #include <NTL/vec_GF2.h>
//Round 2 section b is run by each of the two parties. So, in two_party_backend, make the two data structures needed for each party, the structures in step b.

//---------------global values-------------------------
#define N NUMgGATES+1
#define d 4 //d = number of coefficients of the polynomial. //(d-1) degree polynomial has d number of coefficients
#define k 64 // Z_2^k is the k here. Attenuate the value according to how big a Ring you want
//#define M 5
//degree of the polynomial is d-1. we are using x^3 + x^2 +1 as the f(x). degree=3. But we take d=4. Needed to assign the coefficients for operations.

//#define L 1
int m = NUMgGATES * NUMcGATES;
using namespace std;
using namespace NTL;

namespace MOTION::proto::beavy {

BEAVYProvider::BEAVYProvider(Communication::CommunicationLayer& communication_layer,
                             GateRegister& gate_register, CircuitLoader& circuit_loader,
                             Crypto::MotionBaseProvider& motion_base_provider,
                             ENCRYPTO::ObliviousTransfer::OTProviderManager& ot_manager,
                             ArithmeticProviderManager& arith_manager,
                             std::shared_ptr<Logger> logger, bool fake_setup)
    : CommMixin(communication_layer, Communication::MessageType::BEAVYGate, logger),
      communication_layer_(communication_layer),
      gate_register_(gate_register),
      circuit_loader_(circuit_loader),
      motion_base_provider_(motion_base_provider),
      ot_manager_(ot_manager),
      arith_manager_(arith_manager),
      my_id_(communication_layer_.get_my_id()),
      num_parties_(communication_layer_.get_num_parties()),
      next_input_id_(0),
      logger_(std::move(logger)),
      fake_setup_(fake_setup) {
  // if (communication_layer.get_num_parties() != 2) {
  //   throw std::logic_error("currently only two parties are supported");
  // }
  std::cout << "Beavy suppports multi parties now ;)" << std::endl;
  // share_future_8 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>>;
  // share_future_verify_8 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>>;
  // share_future_16 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint16_t>>>;
  // share_future_verify_16 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint16_t>>>;
  // share_future_32 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint32_t>>>;
  // share_future_verify_32 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint32_t>>>;
  // share_future_64 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>>>;
  // share_future_verify_64 = std::make_unique<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>>>;
}

BEAVYProvider::~BEAVYProvider() = default;

void BEAVYProvider::setup() {
  motion_base_provider_.wait_setup();
  // TODO wait for ot setup
  set_setup_ready();
}

bool BEAVYProvider::is_my_job(std::size_t gate_id) const noexcept {
  return my_id_ == (gate_id % num_parties_);
}

std::size_t BEAVYProvider::get_next_input_id(std::size_t num_inputs) noexcept {
  auto next_id = next_input_id_;
  next_input_id_ += num_inputs;
  return next_id;
}

static BooleanBEAVYWireVector cast_wires(std::vector<std::shared_ptr<NewWire>> wires) {
  BooleanBEAVYWireVector result(wires.size());
  std::transform(std::begin(wires), std::end(wires), std::begin(result),
                 [](auto& w) { return std::dynamic_pointer_cast<BooleanBEAVYWire>(w); });
  return result;
}

static plain::BooleanPlainWireVector cast_to_plain_wires(
    std::vector<std::shared_ptr<NewWire>> wires) {
  plain::BooleanPlainWireVector result(wires.size());
  std::transform(std::begin(wires), std::end(wires), std::begin(result), [](auto& w) {
    return std::dynamic_pointer_cast<proto::plain::BooleanPlainWire>(w);
  });
  return result;
}

static std::vector<std::shared_ptr<NewWire>> cast_wires(BooleanBEAVYWireVector&& wires) {
  return std::vector<std::shared_ptr<NewWire>>(std::begin(wires), std::end(wires));
}

template <typename T>
static ArithmeticBEAVYWireP<T> cast_arith_wire(std::shared_ptr<NewWire> wire) {
  auto ptr = std::dynamic_pointer_cast<ArithmeticBEAVYWire<T>>(wire);
  assert(ptr);
  return ptr;
}

template <typename T>
static plain::ArithmeticPlainWireP<T> cast_arith_plain_wire(std::shared_ptr<NewWire> wire) {
  auto ptr = std::dynamic_pointer_cast<proto::plain::ArithmeticPlainWire<T>>(wire);
  assert(ptr);
  return ptr;
}

template <typename T>
static std::shared_ptr<NewWire> cast_arith_wire(ArithmeticBEAVYWireP<T> wire) {
  return std::shared_ptr<NewWire>(wire);
}

// Boolean inputs/outputs

std::pair<ENCRYPTO::ReusableFiberPromise<BitValues>, WireVector>
BEAVYProvider::make_boolean_input_gate_my(std::size_t input_owner, std::size_t num_wires,
                                          std::size_t num_simd) {
  if (input_owner != my_id_) {
    throw std::logic_error("trying to create input gate for wrong party");
  }
  BooleanBEAVYWireVector output;
  ENCRYPTO::ReusableFiberPromise<std::vector<ENCRYPTO::BitVector<>>> promise;
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<BooleanBEAVYInputGateSender>(gate_id, *this, num_wires, num_simd,
                                                            promise.get_future());
  output = gate->get_output_wires();
  gate_register_.register_gate(std::move(gate));
  return {std::move(promise), cast_wires(std::move(output))};
}

WireVector BEAVYProvider::make_boolean_input_gate_other(std::size_t input_owner,
                                                        std::size_t num_wires,
                                                        std::size_t num_simd) {
  if (input_owner == my_id_) {
    throw std::logic_error("trying to create input gate for wrong party");
  }
  BooleanBEAVYWireVector output;
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<BooleanBEAVYInputGateReceiver>(gate_id, *this, num_wires, num_simd,
                                                              input_owner);
  output = gate->get_output_wires();
  gate_register_.register_gate(std::move(gate));
  return cast_wires(std::move(output));
}

ENCRYPTO::ReusableFiberFuture<BitValues> BEAVYProvider::make_boolean_output_gate_my(
    std::size_t output_owner, const WireVector& in) {
  if (output_owner != ALL_PARTIES && output_owner != my_id_) {
    throw std::logic_error("trying to create output gate for wrong party");
  }
  auto gate_id = gate_register_.get_next_gate_id();
  auto input = cast_wires(in);
  auto gate =
      std::make_unique<BooleanBEAVYOutputGate>(gate_id, *this, std::move(input), output_owner);
  auto future = gate->get_output_future();
  gate_register_.register_gate(std::move(gate));
  return future;
}

void BEAVYProvider::make_boolean_output_gate_other(std::size_t output_owner, const WireVector& in) {
  if (output_owner == ALL_PARTIES || output_owner == my_id_) {
    throw std::logic_error("trying to create output gate for wrong party");
  }
  auto gate_id = gate_register_.get_next_gate_id();
  auto input = cast_wires(in);
  auto gate =
      std::make_unique<BooleanBEAVYOutputGate>(gate_id, *this, std::move(input), output_owner);
  gate_register_.register_gate(std::move(gate));
}

// arithmetic inputs/outputs

template <typename T>
std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<T>>, WireVector>
BEAVYProvider::basic_make_arithmetic_input_gate_my(std::size_t input_owner, std::size_t num_simd) {
  if (input_owner != my_id_) {
    throw std::logic_error("trying to create input gate for wrong party");
  }
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> promise;
  auto gate_id = gate_register_.get_next_gate_id();
  //ADDED
  // const ArithmeticBEAVYWireP<T> dummy1;
  // const ArithmeticBEAVYWireP<T> dummy2;
  //added
  auto gate = std::make_unique<ArithmeticBEAVYInputGateSender<T>>(gate_id, *this, num_simd,
                                                                  promise.get_future());
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {std::move(promise), {cast_arith_wire(std::move(output))}};
}

std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint8_t>>, WireVector>
BEAVYProvider::make_arithmetic_8_input_gate_my(std::size_t input_owner, std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_my<std::uint8_t>(input_owner, num_simd);
}
std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint16_t>>, WireVector>
BEAVYProvider::make_arithmetic_16_input_gate_my(std::size_t input_owner, std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_my<std::uint16_t>(input_owner, num_simd);
}
std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint32_t>>, WireVector>
BEAVYProvider::make_arithmetic_32_input_gate_my(std::size_t input_owner, std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_my<std::uint32_t>(input_owner, num_simd);
}
std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint64_t>>, WireVector>
BEAVYProvider::make_arithmetic_64_input_gate_my(std::size_t input_owner, std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_my<std::uint64_t>(input_owner, num_simd);
}

template <typename T>
WireVector BEAVYProvider::basic_make_arithmetic_input_gate_other(std::size_t input_owner,
                                                                 std::size_t num_simd) {
  if (input_owner == my_id_) {
    throw std::logic_error("trying to create input gate for wrong party");
  }
  auto gate_id = gate_register_.get_next_gate_id();
  //---added

  //---added
  auto gate =
      std::make_unique<ArithmeticBEAVYInputGateReceiver<T>>(gate_id, *this, num_simd, input_owner);
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {cast_arith_wire(std::move(output))};
}

WireVector BEAVYProvider::make_arithmetic_8_input_gate_other(std::size_t input_owner,
                                                             std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_other<std::uint8_t>(input_owner, num_simd);
}
WireVector BEAVYProvider::make_arithmetic_16_input_gate_other(std::size_t input_owner,
                                                              std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_other<std::uint16_t>(input_owner, num_simd);
}
WireVector BEAVYProvider::make_arithmetic_32_input_gate_other(std::size_t input_owner,
                                                              std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_other<std::uint32_t>(input_owner, num_simd);
}
WireVector BEAVYProvider::make_arithmetic_64_input_gate_other(std::size_t input_owner,
                                                              std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_other<std::uint64_t>(input_owner, num_simd);
}

/*
//----------------------ADDED----------------------------
template <typename T>
WireVector BEAVYProvider::basic_make_arithmetic_input_gate_otherExtra(std::size_t input_owner,
                                                                 std::size_t num_simd) {
  if (input_owner == my_id_) {
    throw std::logic_error("trying to create input gate for wrong party");
  }
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate =
      std::make_unique<ArithmeticBEAVYInputGateReceiverExtra<T>>(gate_id, *this, num_simd, input_owner);
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {cast_arith_wire(std::move(output))};
}

WireVector BEAVYProvider::make_arithmetic_8_input_gate_other(std::size_t input_owner,
                                                             std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_otherExtra<std::uint8_t>(input_owner, num_simd);
}
WireVector BEAVYProvider::make_arithmetic_16_input_gate_other(std::size_t input_owner,
                                                              std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_otherExtra<std::uint16_t>(input_owner, num_simd);
}
WireVector BEAVYProvider::make_arithmetic_32_input_gate_other(std::size_t input_owner,
                                                              std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_otherExtra<std::uint32_t>(input_owner, num_simd);
}
WireVector BEAVYProvider::make_arithmetic_64_input_gate_other(std::size_t input_owner,
                                                              std::size_t num_simd) {
  return basic_make_arithmetic_input_gate_otherExtra<std::uint64_t>(input_owner, num_simd);
}
*/
//--------------------ADDED-------------------------------

template <typename T>
ENCRYPTO::ReusableFiberFuture<IntegerValues<T>> BEAVYProvider::basic_make_arithmetic_output_gate_my(
    std::size_t output_owner, const WireVector& in) {
  if (output_owner != ALL_PARTIES && output_owner != my_id_) {
    throw std::logic_error("trying to create output gate for wrong party");
  }
  if (in.size() != 1) {
    throw std::logic_error("invalid number of wires for arithmetic gate");
  }
  auto input = cast_arith_wire<T>(in[0]);
  if (input == nullptr) {
    throw std::logic_error("wrong wire type");
  }

  std::cout << "!!!!!!!!" << std::endl;
  auto gate_id = gate_register_.get_next_gate_id();
  std::cout << "!!!!!!!!XXX" << std::endl;
  auto gate = std::make_unique<ArithmeticBEAVYOutputGate<T>>(gate_id, *this, std::move(input), output_owner);
  std::cout << "!!!!!!!!2" << std::endl;
  auto future = gate->get_output_future();
  std::cout << "!!!!!!!!3" << std::endl;
  gate_register_.register_gate(std::move(gate));
  std::cout << "!!!!!!!!4" << std::endl;
  return future;
}

ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint8_t>>
BEAVYProvider::make_arithmetic_8_output_gate_my(std::size_t output_owner, const WireVector& in) {
  return basic_make_arithmetic_output_gate_my<std::uint8_t>(output_owner, in);
}
ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint16_t>>
BEAVYProvider::make_arithmetic_16_output_gate_my(std::size_t output_owner, const WireVector& in) {
  return basic_make_arithmetic_output_gate_my<std::uint16_t>(output_owner, in);
}
ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint32_t>>
BEAVYProvider::make_arithmetic_32_output_gate_my(std::size_t output_owner, const WireVector& in) {
  return basic_make_arithmetic_output_gate_my<std::uint32_t>(output_owner, in);
}
ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint64_t>>
BEAVYProvider::make_arithmetic_64_output_gate_my(std::size_t output_owner, const WireVector& in) {
  return basic_make_arithmetic_output_gate_my<std::uint64_t>(output_owner, in);
}

void BEAVYProvider::make_arithmetic_output_gate_other(std::size_t output_owner,
                                                      const WireVector& in) {
  if (output_owner == ALL_PARTIES || output_owner == my_id_) {
    throw std::logic_error("trying to create output gate for wrong party");
  }
  if (in.size() != 1) {
    throw std::logic_error("invalid number of wires for arithmetic gate");
  }
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  switch (in[0]->get_bit_size()) {
    case 8: {
      gate = std::make_unique<ArithmeticBEAVYOutputGate<std::uint8_t>>(
          gate_id, *this, cast_arith_wire<std::uint8_t>(in[0]), output_owner);
      break;
    }
    case 16: {
      gate = std::make_unique<ArithmeticBEAVYOutputGate<std::uint16_t>>(
          gate_id, *this, cast_arith_wire<std::uint16_t>(in[0]), output_owner);
      break;
    }
    case 32: {
      gate = std::make_unique<ArithmeticBEAVYOutputGate<std::uint32_t>>(
          gate_id, *this, cast_arith_wire<std::uint32_t>(in[0]), output_owner);
      break;
    }
    case 64: {
      gate = std::make_unique<ArithmeticBEAVYOutputGate<std::uint64_t>>(
          gate_id, *this, cast_arith_wire<std::uint64_t>(in[0]), output_owner);
      break;
    }
    default: {
      throw std::logic_error("unsupprted bit size");
    }
  }
  gate_register_.register_gate(std::move(gate));
}

std::pair<NewGateP, WireVector> BEAVYProvider::construct_unary_gate(
    ENCRYPTO::PrimitiveOperationType op, const WireVector& in_a) {
  switch (op) {
    case ENCRYPTO::PrimitiveOperationType::INV:
      return construct_inv_gate(in_a);
    default:
      throw std::logic_error(fmt::format("BEAVY does not support the unary operation {}", op));
  }
}

std::vector<std::shared_ptr<NewWire>> BEAVYProvider::make_unary_gate(
    ENCRYPTO::PrimitiveOperationType op, const std::vector<std::shared_ptr<NewWire>>& in_a) {
  switch (op) {
    case ENCRYPTO::PrimitiveOperationType::INV:
      return make_inv_gate(in_a);
    case ENCRYPTO::PrimitiveOperationType::NEG:
      return make_neg_gate(in_a);
    case ENCRYPTO::PrimitiveOperationType::SQR:
      return make_sqr_gate(in_a);
    default:
      throw std::logic_error(fmt::format("BEAVY does not support the unary operation {}", op));
  }
}

std::pair<NewGateP, WireVector> BEAVYProvider::construct_binary_gate(
    ENCRYPTO::PrimitiveOperationType op, const WireVector& in_a, const WireVector& in_b) {
  switch (op) {
    case ENCRYPTO::PrimitiveOperationType::XOR:
      return construct_xor_gate(in_a, in_b);
    case ENCRYPTO::PrimitiveOperationType::AND:
      return construct_and_gate(in_a, in_b);
    default:
      throw std::logic_error(fmt::format("BEAVY does not support the binary operation {}", op));
  }
}

std::vector<std::shared_ptr<NewWire>> BEAVYProvider::make_binary_gate(
    ENCRYPTO::PrimitiveOperationType op, const std::vector<std::shared_ptr<NewWire>>& in_a,
    const std::vector<std::shared_ptr<NewWire>>& in_b) {
  switch (op) {
    case ENCRYPTO::PrimitiveOperationType::XOR:
      return make_xor_gate(in_a, in_b);
    case ENCRYPTO::PrimitiveOperationType::AND:
      return make_and_gate(in_a, in_b);
    case ENCRYPTO::PrimitiveOperationType::ADD:
      return make_add_gate(in_a, in_b);
    case ENCRYPTO::PrimitiveOperationType::MUL:
      return make_mul_gate(in_a, in_b);
    default:
      throw std::logic_error(fmt::format("BEAVY does not support the binary operation {}", op));
  }
}

std::pair<std::unique_ptr<NewGate>, WireVector> BEAVYProvider::construct_inv_gate(
    const WireVector& in_a) {
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<BooleanBEAVYINVGate>(gate_id, *this, cast_wires(in_a));
  auto output = gate->get_output_wires();
  return {std::move(gate), cast_wires(std::move(output))};
}

WireVector BEAVYProvider::make_inv_gate(const WireVector& in_a) {
  auto [gate, output] = construct_inv_gate(in_a);
  gate_register_.register_gate(std::move(gate));
  return output;
}

template <typename BinaryGate, bool plain>
std::pair<NewGateP, WireVector> BEAVYProvider::construct_boolean_binary_gate(
    const WireVector& in_a, const WireVector& in_b) {
  BooleanBEAVYWireVector output;
  auto gate_id = gate_register_.get_next_gate_id();
  if constexpr (plain) {
    auto gate =
        std::make_unique<BinaryGate>(gate_id, *this, cast_wires(in_a), cast_to_plain_wires(in_b));
    output = gate->get_output_wires();
    return {std::move(gate), cast_wires(std::move(output))};
  } else {
    auto gate = std::make_unique<BinaryGate>(gate_id, *this, cast_wires(in_a), cast_wires(in_b));
    output = gate->get_output_wires();
    return {std::move(gate), cast_wires(std::move(output))};
  }
}

template <typename BinaryGate, bool plain>
WireVector BEAVYProvider::make_boolean_binary_gate(const WireVector& in_a, const WireVector& in_b) {
  auto [gate, out] = construct_boolean_binary_gate<BinaryGate, plain>(in_a, in_b);
  gate_register_.register_gate(std::move(gate));
  return out;
}

std::pair<NewGateP, WireVector> BEAVYProvider::construct_xor_gate(const WireVector& in_a,
                                                                  const WireVector& in_b) {
  // assume, at most one of the inputs is a plain wire
  if (in_a.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return construct_xor_gate(in_b, in_a);
  }
  assert(in_a.at(0)->get_protocol() == MPCProtocol::BooleanBEAVY);
  if (in_b.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return construct_boolean_binary_gate<BooleanBEAVYXORPlainGate, true>(in_a, in_b);
  } else {
    return construct_boolean_binary_gate<BooleanBEAVYXORGate>(in_a, in_b);
  }
}

std::pair<NewGateP, WireVector> BEAVYProvider::construct_and_gate(const WireVector& in_a,
                                                                  const WireVector& in_b) {
  // assume, at most one of the inputs is a plain wire
  if (in_a.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return construct_xor_gate(in_b, in_a);
  }
  assert(in_a.at(0)->get_protocol() == MPCProtocol::BooleanBEAVY);
  if (in_b.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return construct_boolean_binary_gate<BooleanBEAVYANDPlainGate, true>(in_a, in_b);
  } else {
    return construct_boolean_binary_gate<BooleanBEAVYANDGate>(in_a, in_b);
  }
}

WireVector BEAVYProvider::make_xor_gate(const WireVector& in_a, const WireVector& in_b) {
  // assume, at most one of the inputs is a plain wire
  if (in_a.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return make_xor_gate(in_b, in_a);
  }
  assert(in_a.at(0)->get_protocol() == MPCProtocol::BooleanBEAVY);
  if (in_b.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return make_boolean_binary_gate<BooleanBEAVYXORPlainGate, true>(in_a, in_b);
  } else {
    return make_boolean_binary_gate<BooleanBEAVYXORGate>(in_a, in_b);
  }
}

WireVector BEAVYProvider::make_and_gate(const WireVector& in_a, const WireVector& in_b) {
  // assume, at most one of the inputs is a plain wire
  if (in_a.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return make_xor_gate(in_b, in_a);
  }
  assert(in_a.at(0)->get_protocol() == MPCProtocol::BooleanBEAVY);
  if (in_b.at(0)->get_protocol() == MPCProtocol::BooleanPlain) {
    return make_boolean_binary_gate<BooleanBEAVYANDPlainGate, true>(in_a, in_b);
  } else {
    return make_boolean_binary_gate<BooleanBEAVYANDGate>(in_a, in_b);
  }
}

static std::size_t check_arithmetic_wire(const WireVector& in) {
  if (in.size() != 1) {
    throw std::logic_error("arithmetic operations support single wires only");
  }
  return in[0]->get_bit_size();
}

template <template <typename> class UnaryGate, typename T>
WireVector BEAVYProvider::make_arithmetic_unary_gate(const NewWireP& in_a) {
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<UnaryGate<T>>(gate_id, *this, cast_arith_wire<T>(in_a));
  auto output = {cast_arith_wire(gate->get_output_wire())};
  gate_register_.register_gate(std::move(gate));
  return output;
}

template <template <typename> class UnaryGate>
WireVector BEAVYProvider::make_arithmetic_unary_gate(const WireVector& in_a) {
  auto bit_size = check_arithmetic_wire(in_a);
  switch (bit_size) {
    case 8:
      return make_arithmetic_unary_gate<UnaryGate, std::uint8_t>(in_a[0]);
    case 16:
      return make_arithmetic_unary_gate<UnaryGate, std::uint16_t>(in_a[0]);
    case 32:
      return make_arithmetic_unary_gate<UnaryGate, std::uint32_t>(in_a[0]);
    case 64:
      return make_arithmetic_unary_gate<UnaryGate, std::uint64_t>(in_a[0]);
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
}

static std::size_t check_arithmetic_wires(const WireVector& in_a, const WireVector& in_b,
                                          bool bit_x_int = false) {
  if (in_a.size() != 1 || in_b.size() != 1) {
    throw std::logic_error("arithmetic operations support single wires only");
  }
  if (bit_x_int) {
    assert(std::min(in_a[0]->get_bit_size(), in_b[0]->get_bit_size()) == 1);
    return std::max(in_a[0]->get_bit_size(), in_b[0]->get_bit_size());
  } else {
    auto bit_size = in_a[0]->get_bit_size();
    if (bit_size != in_b[0]->get_bit_size()) {
      throw std::logic_error("different bit sizes on wires");
    }
    return bit_size;
  }
}

template <template <typename> class BinaryGate, typename T, BEAVYProvider::mixed_gate_mode_t mgm>
WireVector BEAVYProvider::make_arithmetic_binary_gate(const NewWireP& in_a, const NewWireP& in_b) {
  auto gate_id = gate_register_.get_next_gate_id();
  WireVector output;
  if constexpr (mgm == mixed_gate_mode_t::plain) {
    auto gate = std::make_unique<BinaryGate<T>>(gate_id, *this, cast_arith_wire<T>(in_a),
                                                cast_arith_plain_wire<T>(in_b));
    output = {cast_arith_wire(gate->get_output_wire())};
    gate_register_.register_gate(std::move(gate));
  } else if constexpr (mgm == mixed_gate_mode_t::boolean) {
    auto gate = std::make_unique<BinaryGate<T>>(gate_id, *this,
                                                std::dynamic_pointer_cast<BooleanBEAVYWire>(in_a),
                                                cast_arith_wire<T>(in_b));
    output = {cast_arith_wire(gate->get_output_wire())};
    gate_register_.register_gate(std::move(gate));
  } else {
    auto gate = std::make_unique<BinaryGate<T>>(gate_id, *this, cast_arith_wire<T>(in_a),
                                                cast_arith_wire<T>(in_b));
    output = {cast_arith_wire(gate->get_output_wire())};
    gate_register_.register_gate(std::move(gate));
  }
  return output;
}

template <template <typename> class BinaryGate, BEAVYProvider::mixed_gate_mode_t mgm>
WireVector BEAVYProvider::make_arithmetic_binary_gate(const WireVector& in_a,
                                                      const WireVector& in_b) {
  auto bit_size = check_arithmetic_wires(in_a, in_b, mgm == mixed_gate_mode_t::boolean);
  switch (bit_size) {
    case 8:
      return make_arithmetic_binary_gate<BinaryGate, std::uint8_t, mgm>(in_a[0], in_b[0]);
    case 16:
      return make_arithmetic_binary_gate<BinaryGate, std::uint16_t, mgm>(in_a[0], in_b[0]);
    case 32:
      return make_arithmetic_binary_gate<BinaryGate, std::uint32_t, mgm>(in_a[0], in_b[0]);
    case 64:
      return make_arithmetic_binary_gate<BinaryGate, std::uint64_t, mgm>(in_a[0], in_b[0]);
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
}

WireVector BEAVYProvider::make_neg_gate(const WireVector& in) {
  return make_arithmetic_unary_gate<ArithmeticBEAVYNEGGate>(in);
}

WireVector BEAVYProvider::make_add_gate(const WireVector& in_a, const WireVector& in_b) {
  // assume, at most one of the inputs is a plain wire
  if (in_a.at(0)->get_protocol() == MPCProtocol::ArithmeticPlain) {
    return make_add_gate(in_b, in_a);
  }
  assert(in_a.at(0)->get_protocol() == MPCProtocol::ArithmeticBEAVY);
  if (in_b.at(0)->get_protocol() == MPCProtocol::ArithmeticPlain) {
    return make_arithmetic_binary_gate<ArithmeticBEAVYADDPlainGate, mixed_gate_mode_t::plain>(in_a,
                                                                                              in_b);
  } else {
    return make_arithmetic_binary_gate<ArithmeticBEAVYADDGate>(in_a, in_b);
  }
}

WireVector BEAVYProvider::make_mul_gate(const WireVector& in_a, const WireVector& in_b) {
  // assume, at most one of the inputs is a plain wire or a Boolean wire
  if (in_a.at(0)->get_protocol() == MPCProtocol::ArithmeticPlain ||
      in_a.at(0)->get_protocol() == MPCProtocol::BooleanBEAVY) {
    return make_mul_gate(in_b, in_a);
  }
  assert(in_a.at(0)->get_protocol() == MPCProtocol::ArithmeticBEAVY);
  if (in_b.at(0)->get_protocol() == MPCProtocol::ArithmeticPlain) {
    return make_arithmetic_binary_gate<ArithmeticBEAVYMULPlainGate, mixed_gate_mode_t::plain>(in_a,
                                                                                              in_b);
  } else if (in_b.at(0)->get_protocol() == MPCProtocol::BooleanBEAVY) {
    return make_arithmetic_binary_gate<BooleanXArithmeticBEAVYMULGate, mixed_gate_mode_t::boolean>(
        in_b, in_a);
  } else {
    return make_arithmetic_binary_gate<ArithmeticBEAVYMULGate>(in_a, in_b);
  }
}

WireVector BEAVYProvider::make_sqr_gate(const WireVector& in) {
  return make_arithmetic_unary_gate<ArithmeticBEAVYSQRGate>(in);
}

template <typename T>
WireVector BEAVYProvider::basic_make_convert_to_arithmetic_beavy_gate(
    BooleanBEAVYWireVector&& in_a) {
  [[maybe_unused]] auto num_wires = in_a.size();
  assert(num_wires == ENCRYPTO::bit_size_v<T>);
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<BooleanToArithmeticBEAVYGate<T>>(gate_id, *this, std::move(in_a));
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {std::dynamic_pointer_cast<NewWire>(output)};
}

WireVector BEAVYProvider::make_convert_to_arithmetic_beavy_gate(BooleanBEAVYWireVector&& in_a) {
  auto bit_size = in_a.size();
  switch (bit_size) {
    case 8:
      return basic_make_convert_to_arithmetic_beavy_gate<std::uint8_t>(std::move(in_a));
    case 16:
      return basic_make_convert_to_arithmetic_beavy_gate<std::uint16_t>(std::move(in_a));
    case 32:
      return basic_make_convert_to_arithmetic_beavy_gate<std::uint32_t>(std::move(in_a));
    case 64:
      return basic_make_convert_to_arithmetic_beavy_gate<std::uint64_t>(std::move(in_a));
    default:
      throw std::logic_error(fmt::format(
          "unsupported bit size {} for Boolean to Arithmetic BEAVY conversion\n", bit_size));
  }
}

template <typename T>
WireVector BEAVYProvider::basic_make_convert_bit_to_arithmetic_beavy_gate(BooleanBEAVYWireP in_a) {
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<BooleanBitToArithmeticBEAVYGate<T>>(gate_id, *this, std::move(in_a));
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {std::dynamic_pointer_cast<NewWire>(output)};
}

template WireVector BEAVYProvider::basic_make_convert_bit_to_arithmetic_beavy_gate<std::uint8_t>(
    BooleanBEAVYWireP);
template WireVector BEAVYProvider::basic_make_convert_bit_to_arithmetic_beavy_gate<std::uint16_t>(
    BooleanBEAVYWireP);
template WireVector BEAVYProvider::basic_make_convert_bit_to_arithmetic_beavy_gate<std::uint32_t>(
    BooleanBEAVYWireP);
template WireVector BEAVYProvider::basic_make_convert_bit_to_arithmetic_beavy_gate<std::uint64_t>(
    BooleanBEAVYWireP);

WireVector BEAVYProvider::make_convert_to_boolean_gmw_gate(BooleanBEAVYWireVector&& in_a) {
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<BooleanBEAVYToGMWGate>(gate_id, *this, std::move(in_a));
  auto output = gate->get_output_wires();
  gate_register_.register_gate(std::move(gate));
  return std::vector<std::shared_ptr<NewWire>>(std::begin(output), std::end(output));
}

template <typename T>
WireVector BEAVYProvider::basic_make_convert_to_arithmetic_gmw_gate(const NewWireP& in_a) {
  auto input = std::dynamic_pointer_cast<ArithmeticBEAVYWire<T>>(in_a);
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<ArithmeticBEAVYToGMWGate<T>>(gate_id, *this, input);
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {std::dynamic_pointer_cast<NewWire>(output)};
}

WireVector BEAVYProvider::make_convert_to_arithmetic_gmw_gate(const WireVector& in_a) {
  assert(in_a.size() == 1);
  const auto& wire = in_a.at(0);
  auto bit_size = wire->get_bit_size();
  switch (bit_size) {
    case 8:
      return basic_make_convert_to_arithmetic_gmw_gate<std::uint8_t>(wire);
    case 16:
      return basic_make_convert_to_arithmetic_gmw_gate<std::uint16_t>(wire);
    case 32:
      return basic_make_convert_to_arithmetic_gmw_gate<std::uint32_t>(wire);
    case 64:
      return basic_make_convert_to_arithmetic_gmw_gate<std::uint64_t>(wire);
    default:
      throw std::logic_error(fmt::format(
          "unsupported bit size {} for Arithmetic BEAVY to GMW conversion\n", bit_size));
  }
}

WireVector BEAVYProvider::convert_from_boolean_beavy(MPCProtocol proto, const WireVector& in) {
  auto input = cast_wires(in);

  switch (proto) {
    case MPCProtocol::ArithmeticBEAVY:
      return make_convert_to_arithmetic_beavy_gate(std::move(input));
    case MPCProtocol::BooleanGMW:
      return make_convert_to_boolean_gmw_gate(std::move(input));
    default:
      throw std::logic_error(
          fmt::format("BooleanBEAVY does not support conversion to {}", ToString(proto)));
  }
}

WireVector BEAVYProvider::convert_from_arithmetic_beavy(MPCProtocol proto, const WireVector& in) {
  switch (proto) {
    case MPCProtocol::ArithmeticGMW:
      return make_convert_to_arithmetic_gmw_gate(in);
    default:
      throw std::logic_error(
          fmt::format("ArithmeticBEAVY does not support conversion to {}", ToString(proto)));
  }
}

BooleanBEAVYWireVector BEAVYProvider::make_convert_from_boolean_gmw_gate(const WireVector& in) {
  auto gate_id = gate_register_.get_next_gate_id();
  gmw::BooleanGMWWireVector input;
  input.reserve(in.size());
  std::transform(std::begin(in), std::end(in), std::back_inserter(input),
                 [](auto& w) { return std::dynamic_pointer_cast<gmw::BooleanGMWWire>(w); });
  auto gate = std::make_unique<BooleanGMWToBEAVYGate>(gate_id, *this, std::move(input));
  auto output = gate->get_output_wires();
  gate_register_.register_gate(std::move(gate));
  return output;
}

WireVector BEAVYProvider::convert_from_other_to_boolean_beavy(const WireVector& in) {
  assert(in.size() > 0);
  auto src_proto = in.at(0)->get_protocol();

  switch (src_proto) {
    case MPCProtocol::BooleanGMW:
      return cast_wires(make_convert_from_boolean_gmw_gate(in));
    default:
      throw std::logic_error(
          fmt::format("BooleanBEAVY does not support conversion from {}", ToString(src_proto)));
  }
}

template <typename T>
WireVector BEAVYProvider::basic_make_convert_from_arithmetic_gmw_gate(const NewWireP& in_a) {
  auto input = std::dynamic_pointer_cast<gmw::ArithmeticGMWWire<T>>(in_a);
  auto gate_id = gate_register_.get_next_gate_id();
  auto gate = std::make_unique<ArithmeticGMWToBEAVYGate<T>>(gate_id, *this, input);
  auto output = gate->get_output_wire();
  gate_register_.register_gate(std::move(gate));
  return {std::dynamic_pointer_cast<NewWire>(output)};
}

WireVector BEAVYProvider::make_convert_from_arithmetic_gmw_gate(const WireVector& in_a) {
  assert(in_a.size() == 1);
  const auto& wire = in_a.at(0);
  auto bit_size = wire->get_bit_size();
  switch (bit_size) {
    case 8:
      return basic_make_convert_from_arithmetic_gmw_gate<std::uint8_t>(wire);
    case 16:
      return basic_make_convert_from_arithmetic_gmw_gate<std::uint16_t>(wire);
    case 32:
      return basic_make_convert_from_arithmetic_gmw_gate<std::uint32_t>(wire);
    case 64:
      return basic_make_convert_from_arithmetic_gmw_gate<std::uint64_t>(wire);
    default:
      throw std::logic_error(fmt::format(
          "unsupported bit size {} for Arithmetic BEAVY from GMW conversion\n", bit_size));
  }
}

WireVector BEAVYProvider::convert_from_other_to_arithmetic_beavy(const WireVector& in) {
  assert(in.size() > 0);
  const auto src_proto = in.at(0)->get_protocol();
  switch (src_proto) {
    case MPCProtocol::ArithmeticGMW:
      return make_convert_from_arithmetic_gmw_gate(in);
    default:
      throw std::logic_error(
          fmt::format("ArithmeticBEAVY does not support conversion from {}", ToString(src_proto)));
  }
}

WireVector BEAVYProvider::convert(MPCProtocol dst_proto, const WireVector& in) {
  if (in.empty()) {
    throw std::logic_error("empty WireVector");
  }
  const auto src_proto = in[0]->get_protocol();
  if (src_proto == MPCProtocol::ArithmeticBEAVY) {
    return convert_from_arithmetic_beavy(dst_proto, in);
  } else if (src_proto == MPCProtocol::BooleanBEAVY) {
    return convert_from_boolean_beavy(dst_proto, in);
  } else if (dst_proto == MPCProtocol::ArithmeticBEAVY) {
    return convert_from_other_to_arithmetic_beavy(in);
  } else if (dst_proto == MPCProtocol::BooleanBEAVY) {
    return convert_from_other_to_boolean_beavy(in);
  }
  throw std::logic_error("expected conversion to or from BEAVY protocol");
}

// implementation of TensorOpFactory

template <typename T>
std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<T>>, tensor::TensorCP>
BEAVYProvider::basic_make_arithmetic_tensor_input_my(const tensor::TensorDimensions& dims) {
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> promise;
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op = std::make_unique<ArithmeticBEAVYTensorInputSender<T>>(gate_id, *this, dims,
                                                                         promise.get_future());
  auto output = tensor_op->get_output_tensor();
  gate_register_.register_gate(std::move(tensor_op));
  return {std::move(promise), std::dynamic_pointer_cast<const tensor::Tensor>(output)};
}

template std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint64_t>>, tensor::TensorCP>
BEAVYProvider::basic_make_arithmetic_tensor_input_my(const tensor::TensorDimensions&);

template <typename T>
tensor::TensorCP BEAVYProvider::basic_make_arithmetic_tensor_input_other(
    const tensor::TensorDimensions& dims) {
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op = std::make_unique<ArithmeticBEAVYTensorInputReceiver<T>>(gate_id, *this, dims);
  auto output = tensor_op->get_output_tensor();
  gate_register_.register_gate(std::move(tensor_op));
  return std::dynamic_pointer_cast<const tensor::Tensor>(output);
}

template tensor::TensorCP BEAVYProvider::basic_make_arithmetic_tensor_input_other<std::uint64_t>(
    const tensor::TensorDimensions&);

std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint32_t>>, tensor::TensorCP>
BEAVYProvider::make_arithmetic_32_tensor_input_my(const tensor::TensorDimensions& dims) {
  return basic_make_arithmetic_tensor_input_my<std::uint32_t>(dims);
}

std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint64_t>>, tensor::TensorCP>
BEAVYProvider::make_arithmetic_64_tensor_input_my(const tensor::TensorDimensions& dims) {
  return basic_make_arithmetic_tensor_input_my<std::uint64_t>(dims);
}

tensor::TensorCP BEAVYProvider::make_arithmetic_32_tensor_input_other(
    const tensor::TensorDimensions& dims) {
  return basic_make_arithmetic_tensor_input_other<std::uint32_t>(dims);
}

tensor::TensorCP BEAVYProvider::make_arithmetic_64_tensor_input_other(
    const tensor::TensorDimensions& dims) {
  return basic_make_arithmetic_tensor_input_other<std::uint64_t>(dims);
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<IntegerValues<T>>
BEAVYProvider::basic_make_arithmetic_tensor_output_my(const tensor::TensorCP& in) {
  auto input = std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(in);
  if (input == nullptr) {
    throw std::logic_error("wrong tensor type");
  }
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op =
      std::make_unique<ArithmeticBEAVYTensorOutput<T>>(gate_id, *this, std::move(input), my_id_);
  auto future = tensor_op->get_output_future();
  gate_register_.register_gate(std::move(tensor_op));
  return future;
}

template ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint64_t>>
BEAVYProvider::basic_make_arithmetic_tensor_output_my(const tensor::TensorCP&);

ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint32_t>>
BEAVYProvider::make_arithmetic_32_tensor_output_my(const tensor::TensorCP& in) {
  return basic_make_arithmetic_tensor_output_my<std::uint32_t>(in);
}

ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint64_t>>
BEAVYProvider::make_arithmetic_64_tensor_output_my(const tensor::TensorCP& in) {
  return basic_make_arithmetic_tensor_output_my<std::uint64_t>(in);
}

void BEAVYProvider::make_arithmetic_tensor_output_other(const tensor::TensorCP& in) {
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  switch (in->get_bit_size()) {
    case 32: {
      gate = std::make_unique<ArithmeticBEAVYTensorOutput<std::uint32_t>>(
          gate_id, *this, std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<std::uint32_t>>(in),
          1 - my_id_);
      break;
    }
    case 64: {
      gate = std::make_unique<ArithmeticBEAVYTensorOutput<std::uint64_t>>(
          gate_id, *this, std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<std::uint64_t>>(in),
          1 - my_id_);
      break;
    }
    default: {
      throw std::logic_error("unsupprted bit size");
    }
  }
  gate_register_.register_gate(std::move(gate));
}

tensor::TensorCP BEAVYProvider::make_tensor_flatten_op(const tensor::TensorCP input,
                                                       std::size_t axis) {
  if (axis > 4) {
    throw std::invalid_argument("invalid axis argument > 4");
  }
  auto bit_size = input->get_bit_size();
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  tensor::TensorCP output;
  const auto make_op = [this, input, axis, gate_id, &output](auto dummy_arg) {
    using T = decltype(dummy_arg);
    auto tensor_op = std::make_unique<ArithmeticBEAVYTensorFlatten<T>>(
        gate_id, *this, axis, std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input));
    output = tensor_op->get_output_tensor();
    return tensor_op;
  };
  switch (bit_size) {
    case 32:
      gate = make_op(std::uint32_t{});
      break;
    case 64:
      gate = make_op(std::uint64_t{});
      break;
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
  gate_register_.register_gate(std::move(gate));
  return output;
}

tensor::TensorCP BEAVYProvider::make_tensor_conversion(MPCProtocol dst_proto,
                                                       const tensor::TensorCP input) {
  auto src_proto = input->get_protocol();
  if (src_proto == MPCProtocol::BooleanBEAVY && dst_proto == MPCProtocol::ArithmeticBEAVY) {
    return make_convert_boolean_to_arithmetic_beavy_tensor(input);
  }
  throw std::invalid_argument(fmt::format("BEAVYProvider: cannot convert tensor from {} to {}",
                                          ToString(src_proto), ToString(dst_proto)));
}

tensor::TensorCP BEAVYProvider::make_tensor_conv2d_op(const tensor::Conv2DOp& conv_op,
                                                      const tensor::TensorCP input,
                                                      const tensor::TensorCP kernel,
                                                      const tensor::TensorCP bias,
                                                      std::size_t fractional_bits) {
  if (!conv_op.verify()) {
    throw std::invalid_argument("invalid Conv2dOp");
  }
  if (input->get_dimensions() != conv_op.get_input_tensor_dims()) {
    throw std::invalid_argument("invalid input dimensions");
  }
  if (kernel->get_dimensions() != conv_op.get_kernel_tensor_dims()) {
    throw std::invalid_argument("invalid kernel dimensions");
  }
  auto bit_size = input->get_bit_size();
  if (bit_size != kernel->get_bit_size()) {
    throw std::invalid_argument("bit size mismatch");
  }
  if (bias != nullptr) {
    if (bias->get_dimensions().get_data_size() != conv_op.compute_bias_size()) {
      throw std::invalid_argument("invalid bias size");
    }
    if (bit_size != bias->get_bit_size()) {
      throw std::invalid_argument("bit size mismatch");
    }
  }
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  tensor::TensorCP output;
  const auto make_op = [this, input, conv_op, kernel, bias, fractional_bits, gate_id,
                        &output](auto dummy_arg) {
    using T = decltype(dummy_arg);
    auto input_ptr = std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input);
    auto kernel_ptr = std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(kernel);
    std::shared_ptr<const ArithmeticBEAVYTensor<T>> bias_ptr = nullptr;
    if (bias != nullptr) {
      bias_ptr = std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(bias);
      assert(bias_ptr);
    }
    auto tensor_op = std::make_unique<ArithmeticBEAVYTensorConv2D<T>>(
        gate_id, *this, conv_op, input_ptr, kernel_ptr, bias_ptr, fractional_bits);
    output = tensor_op->get_output_tensor();
    return tensor_op;
  };
  switch (bit_size) {
    case 32:
      gate = make_op(std::uint32_t{});
      break;
    case 64:
      gate = make_op(std::uint64_t{});
      break;
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
  gate_register_.register_gate(std::move(gate));
  return output;
}

tensor::TensorCP BEAVYProvider::make_tensor_gemm_op(const tensor::GemmOp& gemm_op,
                                                    const tensor::TensorCP input_A,
                                                    const tensor::TensorCP input_B,
                                                    std::size_t fractional_bits) {
  if (!gemm_op.verify()) {
    throw std::invalid_argument("invalid GemmOp");
  }
  if (input_A->get_dimensions() != gemm_op.get_input_A_tensor_dims()) {
    throw std::invalid_argument("invalid input_A dimensions");
  }
  if (input_B->get_dimensions() != gemm_op.get_input_B_tensor_dims()) {
    throw std::invalid_argument("invalid input_B dimensions");
  }
  auto bit_size = input_A->get_bit_size();
  if (bit_size != input_B->get_bit_size()) {
    throw std::invalid_argument("bit size mismatch");
  }
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  tensor::TensorCP output;
  const auto make_op = [this, input_A, gemm_op, input_B, fractional_bits, gate_id,
                        &output](auto dummy_arg) {
    using T = decltype(dummy_arg);
    auto tensor_op = std::make_unique<ArithmeticBEAVYTensorGemm<T>>(
        gate_id, *this, gemm_op, std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input_A),
        std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input_B), fractional_bits);
    output = tensor_op->get_output_tensor();
    return tensor_op;
  };
  switch (bit_size) {
    case 32:
      gate = make_op(std::uint32_t{});
      break;
    case 64:
      gate = make_op(std::uint64_t{});
      break;
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
  gate_register_.register_gate(std::move(gate));
  return output;
}

tensor::TensorCP BEAVYProvider::make_tensor_sqr_op(const tensor::TensorCP input,
                                                   std::size_t fractional_bits) {
  auto bit_size = input->get_bit_size();
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  tensor::TensorCP output;
  const auto make_op = [this, input, fractional_bits, gate_id, &output](auto dummy_arg) {
    using T = decltype(dummy_arg);
    auto tensor_op = std::make_unique<ArithmeticBEAVYTensorMul<T>>(
        gate_id, *this, std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input),
        std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input), fractional_bits);
    output = tensor_op->get_output_tensor();
    return tensor_op;
  };
  switch (bit_size) {
    case 32:
      gate = make_op(std::uint32_t{});
      break;
    case 64:
      gate = make_op(std::uint64_t{});
      break;
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
  gate_register_.register_gate(std::move(gate));
  return output;
}

tensor::TensorCP BEAVYProvider::make_tensor_avgpool_op(const tensor::AveragePoolOp& avgpool_op,
                                                       const tensor::TensorCP input,
                                                       std::size_t fractional_bits) {
  auto bit_size = input->get_bit_size();
  std::unique_ptr<NewGate> gate;
  auto gate_id = gate_register_.get_next_gate_id();
  tensor::TensorCP output;
  const auto make_op = [this, input, &avgpool_op, fractional_bits, gate_id,
                        &output](auto dummy_arg) {
    using T = decltype(dummy_arg);
    auto tensor_op = std::make_unique<ArithmeticBEAVYTensorAveragePool<T>>(
        gate_id, *this, avgpool_op,
        std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(input), fractional_bits);
    output = tensor_op->get_output_tensor();
    return tensor_op;
  };
  switch (bit_size) {
    case 32:
      gate = make_op(std::uint32_t{});
      break;
    case 64:
      gate = make_op(std::uint64_t{});
      break;
    default:
      throw std::logic_error(fmt::format("unexpected bit size {}", bit_size));
  }
  gate_register_.register_gate(std::move(gate));
  return output;
}

tensor::TensorCP BEAVYProvider::make_tensor_relu_op(const tensor::TensorCP in) {
  const auto input_tensor = std::dynamic_pointer_cast<const BooleanBEAVYTensor>(in);
  assert(input_tensor != nullptr);
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op = std::make_unique<BooleanBEAVYTensorRelu>(gate_id, *this, input_tensor);
  auto output = tensor_op->get_output_tensor();
  gate_register_.register_gate(std::move(tensor_op));
  return output;
}

template <typename T>
tensor::TensorCP BEAVYProvider::basic_make_tensor_relu_op(const tensor::TensorCP in_bool,
                                                          const tensor::TensorCP in_arith) {
  const auto input_bool_tensor = std::dynamic_pointer_cast<const BooleanBEAVYTensor>(in_bool);
  assert(input_bool_tensor != nullptr);
  const auto input_arith_tensor =
      std::dynamic_pointer_cast<const ArithmeticBEAVYTensor<T>>(in_arith);
  assert(input_arith_tensor != nullptr);
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op = std::make_unique<BooleanXArithmeticBEAVYTensorRelu<T>>(
      gate_id, *this, input_bool_tensor, input_arith_tensor);
  auto output = tensor_op->get_output_tensor();
  gate_register_.register_gate(std::move(tensor_op));
  return output;
}

tensor::TensorCP BEAVYProvider::make_tensor_relu_op(const tensor::TensorCP in_bool,
                                                    const tensor::TensorCP in_arith) {
  if (in_bool->get_protocol() != MPCProtocol::BooleanBEAVY ||
      in_arith->get_protocol() != MPCProtocol::ArithmeticBEAVY) {
    throw std::invalid_argument("expected Boolean and arithmetic BEAVY, respectively");
  }
  const auto bit_size = in_bool->get_bit_size();
  if (bit_size != in_arith->get_bit_size()) {
    throw std::invalid_argument("bit size mismatch");
  }
  switch (bit_size) {
    case 32:
      return basic_make_tensor_relu_op<std::uint32_t>(in_bool, in_arith);
      break;
    case 64:
      return basic_make_tensor_relu_op<std::uint64_t>(in_bool, in_arith);
      break;
    default:
      throw std::invalid_argument(fmt::format("unexpected bit size {}", bit_size));
  }
}

tensor::TensorCP BEAVYProvider::make_tensor_maxpool_op(const tensor::MaxPoolOp& maxpool_op,
                                                       const tensor::TensorCP in) {
  const auto input_tensor = std::dynamic_pointer_cast<const BooleanBEAVYTensor>(in);
  assert(input_tensor != nullptr);
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op =
      std::make_unique<BooleanBEAVYTensorMaxPool>(gate_id, *this, maxpool_op, input_tensor);
  auto output = tensor_op->get_output_tensor();
  gate_register_.register_gate(std::move(tensor_op));
  return output;
}

template <typename T>
tensor::TensorCP BEAVYProvider::basic_make_convert_boolean_to_arithmetic_beavy_tensor(
    const tensor::TensorCP in) {
  const auto input_tensor = std::dynamic_pointer_cast<const BooleanBEAVYTensor>(in);
  assert(input_tensor != nullptr);
  auto gate_id = gate_register_.get_next_gate_id();
  auto tensor_op =
      std::make_unique<BooleanToArithmeticBEAVYTensorConversion<T>>(gate_id, *this, input_tensor);
  auto output = tensor_op->get_output_tensor();
  gate_register_.register_gate(std::move(tensor_op));
  return output;
}

template tensor::TensorCP BEAVYProvider::basic_make_convert_boolean_to_arithmetic_beavy_tensor<
    std::uint64_t>(const tensor::TensorCP);

tensor::TensorCP BEAVYProvider::make_convert_boolean_to_arithmetic_beavy_tensor(
    const tensor::TensorCP in) {
  switch (in->get_bit_size()) {
    case 32: {
      return basic_make_convert_boolean_to_arithmetic_beavy_tensor<std::uint32_t>(std::move(in));
      break;
    }
    case 64: {
      return basic_make_convert_boolean_to_arithmetic_beavy_tensor<std::uint64_t>(std::move(in));
      break;
    }
    default: {
      throw std::logic_error("unsupported bit size");
    }
  }
}

void convert_pE_uint64_t(ZZ_pE a, uint64_t val[]){
  ZZ_pX temp;
  temp = conv<ZZ_pX>(a);
	for(int j = 0; j < d; ++j)
		val[j] = conv<uint64_t>(coeff(temp, j));
}

void convert_uint64_t_pE(uint64_t val[], ZZ_pE a){
  ZZ_pX temp;
	for(int j = 0; j < d; ++j)
    SetCoeff(temp, j, val[j]);
  conv(a, temp);
}

// void BEAVYProvider::set_cckt(std::size_t gate_id,
//                             std::vector<uint64_t>& ui,
//                             std::vector<uint64_t>& ui1,
//                             std::vector<uint64_t>& vi,
//                             std::vector<uint64_t>& vi1,
//                             std::vector<uint64_t>& zi,
//                             std::vector<uint64_t>& alphai) {
//     initiali();
//     std::cout<< " set_cckt:: u1 received "<<ui[0]<<std::endl;
//     _shares[0 + 6*_numgatesshared] = conv<ZZ_pE>(ui[0]);
//     std::cout<< " set_cckt:: _shares "<< _shares[0 + 6*_numgatesshared] <<std::endl;
//     std::cout<< " set_cckt:: u2 received "<<ui1[0]<<std::endl;
//     _shares[1 + 6*_numgatesshared] = conv<ZZ_pE>(ui1[0]);
//     std::cout<< " set_cckt:: _shares "<< _shares[1 + 6*_numgatesshared] <<std::endl;
//     std::cout<< " set_cckt:: v1 received "<<vi[0]<<std::endl;
//     _shares[2 + 6*_numgatesshared] = conv<ZZ_pE>(vi[0]);
//     std::cout<< " set_cckt:: _shares "<< _shares[2 + 6*_numgatesshared] <<std::endl;
//     std::cout<< " set_cckt:: v2 received "<<vi1[0]<<std::endl;
//     _shares[3 + 6*_numgatesshared] = conv<ZZ_pE>(vi1[0]);
//     std::cout<< " set_cckt:: _shares "<< _shares[3 + 6*_numgatesshared] <<std::endl;
//     std::cout<< " set_cckt:: alphai received "<<alphai[0]<<std::endl;
//     _shares[4 + 6*_numgatesshared] = conv<ZZ_pE>(alphai[0]);
//     std::cout<< " set_cckt:: _shares "<< _shares[4 + 6*_numgatesshared] <<std::endl;
//     std::cout<< " set_cckt:: zi received "<<zi[0]<<std::endl;
//     _shares[5 + 6*_numgatesshared] = conv<ZZ_pE>(zi[0]);
//     std::cout<< " set_cckt:: _shares "<< _shares[5 + 6*_numgatesshared] <<std::endl;
//
//     // uint64_t tmp6=_shares[5 + 6*_numgatesshared];
//     // uint64_t tmp=tmp1
//     //==================================CONSISTENCY CHECK====================================
//     //ui*vi + ui.v(i-1) + u(i-1).vi + alphai -zi
//     ZZ_pE temp= (_shares[0 + 6*_numgatesshared]*_shares[2 + 6*_numgatesshared]) + (_shares[0 + 6*_numgatesshared]*_shares[3 + 6*_numgatesshared]) + (_shares[1 + 6*_numgatesshared] * _shares[2 + 6*_numgatesshared]) + _shares[4 + 6*_numgatesshared]  - _shares[5 + 6*_numgatesshared] ;
//     // std::cout<<" set_cckt::: data type of temp " << typeid(temp).name()<<std::endl
//     std::cout<<" set_cckt::: value of temp "<<temp<<std::endl;
//
//     ++_numgatesshared;
//
//     // std::cout<< " CONSISTENCY CHECK ------- "<< temp <<std::endl;
//
//
//
//     //==================================CONSISTENCY CHECK====================================
//     std::cout<<"_numgatesshared"<<_numgatesshared<<std::endl;
//     std::cout<<"NUMMULGATES"<<NUMMULGATES<<std::endl;
// }
void BEAVYProvider::set_cckt(std::size_t gate_id, std::vector<uint64_t>& ui, std::vector<uint64_t>& ui1, std::vector<uint64_t>& vi, std::vector<uint64_t>& vi1, std::vector<uint64_t>& zi, std::vector<uint64_t>& zj, std::vector<uint64_t>& alphai, std::vector<uint64_t>& rowi, std::vector<uint64_t>& rowj) {
    initiali();
    std::cout<< " set_cckt:: u1 received "<<ui[0]<<std::endl;
    _shares[0 + 6*_numgatesshared] = conv<ZZ_pE>(ui[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[0 + 6*_numgatesshared] <<std::endl;
    std::cout<< " set_cckt:: u2 received "<<ui1[0]<<std::endl;
    _shares[1 + 6*_numgatesshared] = conv<ZZ_pE>(ui1[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[1 + 6*_numgatesshared] <<std::endl;
    std::cout<< " set_cckt:: v1 received "<<vi[0]<<std::endl;
    _shares[2 + 6*_numgatesshared] = conv<ZZ_pE>(vi[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[2 + 6*_numgatesshared] <<std::endl;
    std::cout<< " set_cckt:: v2 received "<<vi1[0]<<std::endl;
    _shares[3 + 6*_numgatesshared] = conv<ZZ_pE>(vi1[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[3 + 6*_numgatesshared] <<std::endl;

    std::cout<< " set_cckt:: zi received "<<zi[0]<<std::endl;
    _shares[4 + 6*_numgatesshared] = conv<ZZ_pE>(zi[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[4 + 6*_numgatesshared] <<std::endl;
    std::cout<< " set_cckt:: zj received "<<zj[0]<<std::endl;
    _shares[5 + 6*_numgatesshared] = conv<ZZ_pE>(zj[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[5 + 6*_numgatesshared] <<std::endl;

    std::cout<< " set_cckt:: alphai received "<<alphai[0]<<std::endl;
    _shares[6 + 6*_numgatesshared] = conv<ZZ_pE>(alphai[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[5 + 6*_numgatesshared] <<std::endl;

    std::cout<< " set_cckt:: row(i-1) received "<<rowi[0]<<std::endl;
    _shares[7 + 6*_numgatesshared] = conv<ZZ_pE>(rowi[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[7 + 6*_numgatesshared] <<std::endl;

    std::cout<< " set_cckt:: row(i+1) received "<<rowj[0]<<std::endl;
    _shares[8 + 6*_numgatesshared] = conv<ZZ_pE>(rowj[0]);
    std::cout<< " set_cckt:: _shares "<< _shares[8 + 6*_numgatesshared] <<std::endl;

    // uint64_t tmp6=_shares[5 + 6*_numgatesshared];
    // uint64_t tmp=tmp1
    //==================================CONSISTENCY CHECK====================================
    //ui*vi + ui.v(i-1) + u(i-1).vi + alphai -zi
    ZZ_pE temp= (_shares[0 + 6*_numgatesshared]*_shares[2 + 6*_numgatesshared]) + (_shares[0 + 6*_numgatesshared]*_shares[3 + 6*_numgatesshared]) + (_shares[1 + 6*_numgatesshared] * _shares[2 + 6*_numgatesshared]) + _shares[6 + 6*_numgatesshared]  - _shares[4 + 6*_numgatesshared] ;
    // std::cout<<" set_cckt::: data type of temp " << typeid(temp).name()<<std::endl
    std::cout<<" set_cckt::: value of temp "<<temp<<std::endl;


      ZZ_pX zero1;
      SetCoeff(zero1,0,0);
      ZZ_pE zero;
      conv(zero,zero1);

    std::cout<<" DIZK_verify:: reached here3"<<std::endl;

    //pi
    share_Round1[0 + 6*_numgatesshared]=_shares[0 + 6*_numgatesshared];
    share_Round1[1 + 6*_numgatesshared]=_shares[1 + 6*_numgatesshared];
    share_Round1[2 + 6*_numgatesshared]=_shares[2 + 6*_numgatesshared];
    share_Round1[3 + 6*_numgatesshared]=_shares[3 + 6*_numgatesshared];
    share_Round1[4 + 6*_numgatesshared]=_shares[6 + 6*_numgatesshared]; //alphai
    share_Round1[5 + 6*_numgatesshared]=_shares[4 + 6*_numgatesshared]; //zi

  std::cout<<" DIZK_verify:: reached here4"<<std::endl;
    //p_(i-1)
    share_Round2_1[0 + 6*_numgatesshared]=_shares[0 + 6*_numgatesshared];
    share_Round2_1[1 + 6*_numgatesshared]=zero;
    share_Round2_1[2 + 6*_numgatesshared]=_shares[2 + 6*_numgatesshared];
    share_Round2_1[3 + 6*_numgatesshared]=zero;
    share_Round2_1[4 + 6*_numgatesshared]=_shares[7 + 6*_numgatesshared];
    //share_Round2_1[5 + 6*_numgatesshared]=_shares[4 + 6*_numgatesshared]; //zi
    share_Round2_1[5 + 6*_numgatesshared]=_shares[5 + 6*_numgatesshared]; //z(i-1)

  std::cout<<" DIZK_verify:: reached here5"<<std::endl;
    //p_(i+1)
    share_Round2_2[0 + 6*_numgatesshared]=zero;
    share_Round2_2[1 + 6*_numgatesshared]=_shares[1 + 6*_numgatesshared];
    share_Round2_2[2 + 6*_numgatesshared]=zero;
    share_Round2_2[3 + 6*_numgatesshared]=_shares[3 + 6*_numgatesshared];
    share_Round2_2[4 + 6*_numgatesshared]=_shares[8 + 6*_numgatesshared];
    //share_Round2_1[5 + 6*_numgatesshared]=_shares[5 + 6*_numgatesshared]; //z(i-1)
    share_Round2_1[5 + 6*_numgatesshared]=zero;

  std::cout<<" DIZK_verify:: reached here6"<<std::endl;


    ++_numgatesshared;

    // std::cout<< " CONSISTENCY CHECK ------- "<< temp <<std::endl;



    //==================================CONSISTENCY CHECK====================================
    std::cout<<"_numgatesshared"<<_numgatesshared<<std::endl;
    std::cout<<"NUMMULGATES"<<NUMMULGATES<<std::endl;
}

// SUVI
void BEAVYProvider::DIZK_verify (std::size_t last_mult_gate_id) {

  initiali();
  std::size_t gate_id_next = 101;
  std::size_t gate_id_prev = 99;
  //
  int pid=my_id_;

  //auto share_future_next_array[10];
  ENCRYPTO::ReusableFiberFuture<std::vector<uint64_t>> share_future_next_array[(6*NUMcGATES + 2*NUMgGATES + 1)*3];
  ENCRYPTO::ReusableFiberFuture<std::vector<uint64_t>> share_future_prev_array[(6*NUMcGATES + 2*NUMgGATES + 1)*3];

 int counter=0;
  for(std::size_t i=0; i<(6*NUMcGATES + 2*NUMgGATES + 1)*3; i++){
      share_future_next_array[i]=register_for_ints_message<uint64_t>(((pid + 1)%3), gate_id_next, 1, i);
      share_future_prev_array[i]=register_for_ints_message<uint64_t>(((pid + 2)%3), gate_id_prev, 1, i);
      ++counter;
    }

  //
  // auto share_future_next = register_for_ints_message<uint64_t>(((pid + 1)%3), gate_id_next, 1, 1);
  // auto share_future_prev = register_for_ints_message<uint64_t>(((pid + 2)%3), gate_id_prev, 1, 1);

  // //------------------for Round 2-----------------------------------------
  // auto share_future_next1 = register_for_ints_message<uint64_t>(((pid + 1)%3), gate_id_next, 1, counter);
  // auto share_future_next2 = register_for_ints_message<uint64_t>(((pid + 1)%3), gate_id_next, 1, 3);
  // auto share_future_next3 = register_for_ints_message<uint64_t>(((pid + 1)%3), gate_id_next, 1, 4);
  //
  // auto share_future_prev1 = register_for_ints_message<uint64_t>(((pid + 2)%3), gate_id_prev, 1, 2);
  // auto share_future_prev2 = register_for_ints_message<uint64_t>(((pid + 2)%3), gate_id_prev, 1, 3);
  // auto share_future_prev3 = register_for_ints_message<uint64_t>(((pid + 2)%3), gate_id_prev, 1, 4);









  std::cout<<"suvi TEST:::----------------my id="<<my_id_<<" (my id + 2)%3 =" <<(my_id_+2)%3 << "(my_id+1) %3" <<(my_id_+1)%3 <<std::endl;

  //-----------------------initializing the Extended Ring, generating the THETA, generating the BETA


  ZZ_pE theta[NUMcGATES]; //prottek party has diff theta.
  //but they will be populated using the same value
  // ZZ_pE r;

  int j=0;
  if(my_id_==0){
    auto& rng5 = motion_base_provider_.get_my_randomness_generator(my_id_);
    auto t=rng5.GetUnsigned<uint64_t>(last_mult_gate_id, NUMcGATES);
    // conv(r,t[0]);
    // std::cout<< "DIZK_verify:: r for Round2 = "<< r <<std::endl;
    for(int i=0; i<NUMcGATES; i++){
        std::cout<<"t["<<i<<"]"<<t[i]<<std::endl;

        conv(theta[j],t[i]);
        std::cout<<"my_id"<<my_id_<<" value of theta " << theta[j] <<std::endl;
        j++;

    }
  }else if(my_id_==1){
    auto& rng5 = motion_base_provider_.get_our_randomness_generator(0);
    auto t=rng5.GetUnsigned<uint64_t>(last_mult_gate_id, NUMcGATES);
    // conv(r,t[0]);
    // std::cout<< "DIZK_verify:: r for Round2 = "<< r <<std::endl;
    for(int i=0; i<NUMcGATES; i++){
        std::cout<<"t["<<i<<"]"<<t[i]<<std::endl;

        conv(theta[j],t[i]);
        std::cout<<"my_id"<<my_id_<<" value of theta " << theta[j] <<std::endl;
        j++;

    }
  }else if(my_id_==2){
    auto& rng5 = motion_base_provider_.get_our_randomness_generator(0);
    auto t=rng5.GetUnsigned<uint64_t>(last_mult_gate_id, NUMcGATES);
    // conv(r, t[0]);
    // std::cout<< "DIZK_verify:: r for Round2 = "<< r <<std::endl;
    for(int i=0; i<NUMcGATES; i++){
        std::cout<<"t["<<i<<"]"<<t[i]<<std::endl;

        conv(theta[j],t[i]);
        std::cout<<"my _id"<<my_id_<<" value of theta " << theta[j] <<std::endl;
        j++;

    }
  }
  ZZ_pE Beta[NUMgGATES]; //prottek party has diff theta.
  //but they will be populated using the same value
  if(my_id_==1){
    auto& rng5=motion_base_provider_.get_my_randomness_generator(my_id_ );
    auto t=rng5.GetUnsigned<uint64_t>(last_mult_gate_id, NUMgGATES);
    for(int i=0; i<NUMgGATES; i++){
        std::cout<<"t["<<i<<"]"<<t[i]<<std::endl;

        conv(Beta[i],t[i]);
        std::cout<<"my_id"<<my_id_ <<" value of Beta " << Beta[i] <<std::endl;

    }
  }else if(my_id_==0){
    auto& rng5 = motion_base_provider_.get_our_randomness_generator(1);
    auto t=rng5.GetUnsigned<uint64_t>(last_mult_gate_id, NUMgGATES);
    for(int i=0; i<NUMgGATES; i++){
        std::cout<<"t["<<i<<"]"<<t[i]<<std::endl;

        conv(Beta[i],t[i]);
        std::cout<<"my_id"<<my_id_<<" value of Beta " << Beta[i] <<std::endl;

    }
  }else if(my_id_==2){
    auto& rng5 = motion_base_provider_.get_our_randomness_generator(1);
    auto t=rng5.GetUnsigned<uint64_t>(last_mult_gate_id, NUMgGATES);
    for(int i=0; i<NUMgGATES; i++){
        std::cout<<"t["<<i<<"]"<<t[i]<<std::endl;

        conv(Beta[i],t[i]);
        std::cout<<"my _id"<<my_id_<<" value of Beta " << Beta[i] <<std::endl;

    }
  }

  GF2X f;

  SetCoeff(f, 3, 1);
  SetCoeff(f, 2, 1);
  SetCoeff(f, 0, 1);

  std::cout<<"polynomial f in DIZK " <<f<<std::endl;
  ZZ_pE pi[6*NUMcGATES + 2*NUMgGATES + 1];
	ZZ_pE pi1[6*NUMcGATES + 2*NUMgGATES + 1];
	ZZ_pE pi2[6*NUMcGATES + 2*NUMgGATES + 1];
  //BEAVYProvider::Round1(share, f,theta, pi, pi1, pi2);
  for(int i=0;  i < 6 * NUMMULGATES; i++)
    std::cout<<" shares = " <<_shares[i]<<std::endl;
  Round1(share_Round1, f, theta, pi, pi1, pi2);
  std::cout<<"\n ---------------------------- end of ROUND 1------------------------\n"<<std::endl;

  uint64_t pi_64[6*NUMcGATES + 2*NUMgGATES + 1][d];
  for(int i=0; i<6*NUMcGATES + 2*NUMgGATES + 1; i++){
    std::cout<<"pi = "<<pi[i]<<std::endl;
  }
  for(int i=0; i<6*NUMcGATES + 2*NUMgGATES + 1; i++){
    std::cout<<"pi1 = "<<pi1[i]<<std::endl;
  }
  for(int i=0; i<6*NUMcGATES + 2*NUMgGATES + 1; i++){
    std::cout<<"pi2 = "<<pi2[i]<<std::endl;
  }

  uint64_t vp1[6*NUMcGATES + 2*NUMgGATES + 1][d], vp2[6*NUMcGATES + 2*NUMgGATES + 1][d];

	ZZ_pX temp, temp2;
	for(int i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
			temp = conv<ZZ_pX>(pi1[i]);
      temp2 = conv<ZZ_pX>(pi2[i]);
			for(int j = 0; j < 3; ++j){
				vp1[i][j] = conv<uint64_t>(coeff(temp, j));
        vp2[i][j] = conv<uint64_t>(coeff(temp2, j));
				std::cout<<"val["<<i<<"]["<<j<<"] ="<<vp1[i][j]<<" ";
			}
		std::cout<<std::endl;
	}
  // send pi1 -> myID+1, pi2-> myID-1
  std::cout<<" \n --- inside DIZK, before send_ints_message \n "<<std::endl;
  for(std::size_t i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		for(std::size_t j = 0; j < 3; ++j){
        std::vector<uint64_t> tm;
        tm.push_back(vp1[i][j]);
        std::cout<<" SENDING   "<<tm[0]<<"\t"<<vp1[i][j]<<std::endl;
				send_ints_message((my_id_ + 1)%3, gate_id_prev, tm, (3*i)+j);
    }
	}
  std::cout<<" \n --- inside DIZK, after 1st send_ints_message \n "<<std::endl;
  for(std::size_t i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		for(std::size_t j = 0; j < 3; ++j){
      std::vector<uint64_t> tm;
      tm.push_back(vp2[i][j]);
        std::cout<<" SENDING   "<<tm[0]<<"\t " <<vp2[i][j]<<std::endl;
				send_ints_message((my_id_ + 2)%3, gate_id_next, tm, (3*i)+j);
    }
	}
std::cout<<" \n --- inside DIZK, after 2nd send_ints_message \n "<<std::endl;
  // send_ints_message((my_id_ + 1)%3, gate_id_prev, t1, 1);


  //send_ints_message((my_id_ - 1)%3, gate_id_next, t2);
  // send_ints_message((my_id_ + 2)%3, gate_id_next, t2, 1);
  uint64_t vp1_rx[6*NUMcGATES + 2*NUMgGATES + 1][d], vp2_rx[6*NUMcGATES + 2*NUMgGATES + 1][d];

  std::cout<<" \n --- inside DIZK, before .get() \n "<<std::endl;
  for(std::size_t i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		for(std::size_t j = 0; j < 3; ++j){
      auto t2 = share_future_next_array[(3*i)+j].get();
      vp1_rx[i][j]=t2[0];
    }
  }
  std::cout<<" 1st message received "<<std::endl;
  for(int i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		for(int j = 0; j < 3; ++j){
      std::cout<<"array of received message from round1    ===== \n",vp1_rx[i][j];
    }
  }
  std::cout<<" \n --- inside DIZK, after .get() \n "<<std::endl;

  for(std::size_t i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		for(std::size_t j = 0; j < 3; ++j){
      auto t2 = share_future_prev_array[(3*i)+j].get();
      vp2_rx[i][j]=t2[0];
    }
  }
  std::cout<<" 1st message received "<<std::endl;
  for(int i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		for(int j = 0; j < 3; ++j){
      std::cout<<"array of received message from round1    ===== \n",vp2_rx[i][j];
    }
  }

  // // receive from my_id-1 : pi3, my_id+1: pi4
  ZZ_pE pi3[6*NUMcGATES + 2*NUMgGATES + 1];
  ZZ_pE pi4[6*NUMcGATES + 2*NUMgGATES + 1];

  ZZ_pX temp9, temp10;
  for(int i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){

		for(int j = 0; j < 3; ++j){
  // for (int i=0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i) {
      SetCoeff(temp9, j, vp1_rx[i][j]);
      SetCoeff(temp10, j, vp2_rx[i][j]);

  }
  pi3[i] = conv<ZZ_pE>(temp9);
  pi4[i] = conv<ZZ_pE>(temp10);
}
std::cout<<" \n--------pi3 received = ------\n"<<std::endl;
for(int i=0; i< 6*NUMcGATES + 2*NUMgGATES + 1; i++)
  std::cout<<pi3[i]<<std::endl;

  std::cout<<" \n--------pi4 received = ------\n"<<std::endl;
  for(int i=0; i< 6*NUMcGATES + 2*NUMgGATES + 1; i++)
    std::cout<<pi4[i]<<std::endl;




  std::cout << "IN DIZKVERIFY NIGAAAAAAAAAAAAAAAAAa" << std::endl;

}

void BEAVYProvider::set_cckt(std::size_t gate_id, std::vector<uint8_t>& ui, std::vector<uint8_t>& ui1, std::vector<uint8_t>& vi, std::vector<uint8_t>& vi1, std::vector<uint8_t>& zi, std::vector<uint8_t>& zj, std::vector<uint8_t>& alphai, std::vector<uint8_t>& rowi, std::vector<uint8_t>& rowj){};

void BEAVYProvider::set_cckt(std::size_t gate_id, std::vector<uint16_t>& ui, std::vector<uint16_t>& ui1, std::vector<uint16_t>& vi, std::vector<uint16_t>& vi1, std::vector<uint16_t>& zi, std::vector<uint16_t>& zj, std::vector<uint16_t>& alphai, std::vector<uint16_t>& rowi, std::vector<uint16_t>& rowj){};

void BEAVYProvider::set_cckt(std::size_t gate_id, std::vector<uint32_t>& ui, std::vector<uint32_t>& ui1, std::vector<uint32_t>& vi, std::vector<uint32_t>& vi1, std::vector<uint32_t>& zi, std::vector<uint32_t>& zj, std::vector<uint32_t>& alphai, std::vector<uint32_t>& rowi, std::vector<uint32_t>& rowj){};

//
//
// //--------------------------------------
// #define N 6 // NUMSHARES
// #define d 4 // DEGREE_POLY//d = number of coefficients of the polynomial. //(d-1) degree polynomial has d number of coefficients
// #define k 64 // RINGSIZE// Z_2^k is the k here. Attenuate the value according to how big a Ring you want
//
// int m = NUMgGATES * NUMcGATES;
// using namespace std;
// using namespace NTL;



			ZZ_pE inverseE(ZZ_pE p, GF2X f, int deg1, int deg2){ // we find the inverse of g polynomial here, passed as p polynomial, in the extended quotient ring quotiented by f poly
				//std::cout<<"p in inverseE" << p << std::endl;
				ZZ_pX g;
				conv(g,p);
				//std::cout<< "g poly " <<g<<std::endl;
				GF2X f2; // since no modulus operation over GF2X. Hence jst copying the poly f into f2.
				conv(f2, f);
				//std::cout<<"polynomial f2 " <<f2<<std::endl;

			    GF2X g2;

				ZZ_pX g1; //g_cap

			    for(int i= 0; i< deg1; i++)
			    {
			    	long c1;
			    	conv(c1, coeff(g,i));
			    	//std::cout<< " coefficients of g " <<c1<<std::endl;
			    	SetCoeff(g2, i, (c1%((long)2)));
			    	long tmp= c1- (c1%((long)2));
			    	SetCoeff(g1, i, tmp);	 //g1 = g - g2
			    }

			  	//std::cout<<"g2\t"<<g2<<std::endl;
			  	//std::cout<<"g1\t"<<g1<<std::endl;

			  	GF2X gcd;
				GF2X a; //a
				GF2X b; //b
				XGCD(gcd, a, b, f2, g2);
				//std::cout<< " a= "<< a << std::endl;
				//std::cout<< " b= "<< b << std::endl;
				//std::cout<< " d= "<< d << std::endl;

				ZZ_pX b_p, a_p, f2_p, g2_p, h_p;

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(b,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(b_p, i, (c1%((long)2)));
				}

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(a,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(a_p, i, (c1%((long)2)));
				}

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(f2,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(f2_p, i, (c1%((long)2)));
				}

				for(int i = 0; i < deg1; ++i){
					long c1;
			    	conv(c1, coeff(g2,i));
			    	//std::cout<< " coefficients of b " <<c1<<std::endl;
			    	SetCoeff(g2_p, i, (c1%((long)2)));
				}

				//std::cout<<"b_p\t"<<b_p<<std::endl;
				//std::cout<<"a_p\t"<<a_p<<std::endl;
				//std::cout<<"f2_p\t"<<f2_p<<std::endl;
				//std::cout<<"g2_p\t"<<g2_p<<std::endl;

				h_p = a_p*f2_p + b_p*g2_p - 1;
				//std::cout<<"h_p\t"<<h_p<<std::endl;

				ZZ_pE b_E;
				conv(b_E, b_p);
				//std::cout<<"b_E\t"<<b_E<<std::endl;

				ZZ_pE g1_p;
				conv(g1_p, g1);

				//std::cout<<"g1_p\t"<<g1_p<<std::endl;

				ZZ_pE h;
				conv(h, h_p);
				h = h + (b_E * g1_p);
				//std::cout<<"h\t"<<h<<std::endl;

				ZZ_pE B_x;
				B_x=0;
				for(int i =0; i< deg2; i++) //k=10
				{
					ZZ_pE tm1=-h;
					ZZ_pE tm2=power(tm1,i);
					B_x+= tm2;
				}
				B_x = B_x * b_E;

				//std::cout<< " B(x) = " << B_x <<std::endl;

				return(B_x);

			}
			void getCfactor(ZZ_pE Mat[N][N], ZZ_pE t[N][N], int p, int q, int n) {
			   int i = 0, j = 0;
			   for (int r= 0; r< n; r++) {
			      for (int c = 0; c< n; c++) //Copy only those elements which are not in given row r and column c:
			      {
			         if (r != p && c != q) {
			         	t[i][j++] = Mat[r][c]; //If row is filled increase r index and reset c index
			            if (j == n - 1) {
			               j = 0;
			               i++;
			            }
			         }
			      }
			   }
			}

ZZ_pE DET(ZZ_pE Mat[N][N], int n)
{
   ZZ_pE D ;
   if (n == 1)
      return Mat[0][0];
   ZZ_pE t[N][N], s;
   ZZ_pX s_X;
   SetCoeff(s_X, 0, 1);
   conv(s, s_X);
   // std::cout<<"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@22"<<std::endl;
   for (int f = 0; f < n; f++) {
      getCfactor(Mat, t, 0, f, n);
      D += s * Mat[0][f] * DET(t, n - 1);
      s = -s;
   }
   return D;
}
			void ADJ(ZZ_pE Mat[N][N],ZZ_pE adj[N][N])
			//to find adjoint matrix
			{
			   if (N == 1) {
			      adj[0][0] = 1; return;
			   }
			   ZZ_pE s, t[N][N];
			   ZZ_pX s1;

			   for (int i=0; i<N; i++) {
			      for (int j=0; j<N; j++) {
			         //To get cofactor of M[i][j]
			         getCfactor(Mat, t, i, j, N);
			         if ((i+j)%2==0)
			         	SetCoeff(s1, 0, 1);
			         else
			         	SetCoeff(s1, 0, -1);//sign of adj[j][i] positive if sum of row and column indexes is even.
			         conv(s,s1);
			         //std::cout<< "s =" <<s<<std::endl;
			         adj[j][i] = (s)*(DET(t, N-1)); //Interchange rows and columns to get the transpose of the cofactor matrix
			      }
			   }
			}

			int INV(ZZ_pE Mat[N][N], ZZ_pE inv[N][N], GF2X f)
			{
        //int N= NUMgGATES+1;
			   ZZ_pE det = DET(Mat, N); //this is a valu0
			   std::cout<< "det\t" << det <<std::endl;

			   ZZ_pX d1;
			   conv(d1, det);

			   int flag = 0;
			   long d0;
			   for(int i = 0; i < d; ++i){
			   		conv(d0, coeff(d1, i));
			   		if((d0 % 2) == 1){
			   			flag = 1;
			   			break;
			   		}
			   }

			   if (flag == 0) {
			      cout << "can't find its inverse";
			      return 0;
			      //return false;
			   }

			   ZZ_pE adj[N][N];
			   ADJ(Mat, adj);


			   ZZ_pE dInv = inverseE(det, f, d, k);
			   std::cout<< "dInv = " << dInv <<std::endl;
			   std::cout<< "dInv * det = " << dInv * det <<std::endl;

			   for (int i=0; i<N; i++) {
			   		for (int j=0; j<N; j++){

			   			inv[i][j] = adj[i][j]*dInv;
			   		}
			   }

				return(1);
			}

void interpolation(ZZ_pE evaluations[N], GF2X f, ZZ_pE coefficients[N]){

        int i, j, l, temp;

        ZZ_pE A[N][N]; //A= Van mat
        for(i = 0; i < N; ++i){ //Binary equivalent of the evaluation points
                temp = i;
                ZZ_pX eval_pt_X;
                SetCoeff(eval_pt_X, 0, 0);



                j = 0;
                while(temp != 0){ //converting temp to binary equivalent
                        SetCoeff(eval_pt_X, j, temp%2); //
                        temp = temp / 2;
                        ++j;
                } //eval_pt_X is the polynomial having the binary equivalent of the evaluation points

                ZZ_pE eval_pt;
                conv(eval_pt, eval_pt_X); //storing the bonary equivalent of the coefficients

                for(j = 0; j < N; ++j)
                        A[i][j] = power(eval_pt, j); //populating the VAN mat
        }

        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j)
                        std::cout<<A[i][j]<<" ";
                std::cout<<"\n";
        }
        std::cout<<"\n\n";

        ZZ_pE invA[N][N];
        INV(A, invA, f);


        std::cout<<"\n";
        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j)
                        std::cout<<" \n  inverse mat "<<invA[i][j]<<" ";
                std::cout<<"\n";
        }

        ZZ_pX zero;
        SetCoeff(zero, 0, 0);

        ZZ_pE prod[N][N];
        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j){
                        conv(prod[i][j], zero); //initialisiing the polynomial to zero
                        for(l = 0; l < N; ++l)
                                prod[i][j] += invA[i][l] * A[l][j];
                }
        }

        std::cout<<"\n";
        for(i = 0; i < N; ++i){
                for(j = 0; j < N; ++j)
                        std::cout<<prod[i][j]<<" ";
                std::cout<<"\n";
        }

        for(i = 0; i < N; ++i){
                conv(coefficients[i], zero);
                for(j = 0;  j < N; ++j)
                        coefficients[i] += invA[i][j] * evaluations[j];
        }
}//end of interpolation func


void BEAVYProvider::Round3( ZZ_pE fp_r[], ZZ_pE p_r_t, ZZ_pE b_t, ZZ_pE fp_r_prime[], ZZ_pE p_r_t_prime, ZZ_pE b_t_prime, ZZ_pE theta[] ){
    std::cout<<"\n --------------------ROUND 3--------- \n "<<std::endl;
    std::cout<<"received shares from Round 2"<<std::endl;
    for(int i=0; i<(6*NUMcGATES); i++){
      std::cout<<" fp_r is = "<<fp_r[i];
    }

      std::cout<<" p_r_t ="<<p_r_t<<std::endl;

      std::cout<< "b_t ="<<b_t<<std::endl;

		ZZ_pE f_prime_j_r[6*NUMcGATES];
		for(int j=0; j<(6*NUMcGATES); j++){
			f_prime_j_r[j]=fp_r_prime[j] + fp_r[j];
    }

		ZZ_pE p_r;
		p_r=p_r_t + p_r_t_prime;

		ZZ_pE b;
		b=b_t+b_t_prime;

		//check
		ZZ_pX zero;
	  SetCoeff(zero, 0, 0);

		ZZ_pE P_check;
		conv(P_check, zero);
		for(int i = 0; i < NUMcGATES; ++i){
			P_check += theta[i] * (fp_r_prime[6*i + 0]*fp_r_prime[6*i + 2] + fp_r_prime[6*i + 0]*fp_r_prime[6*i + 3] + fp_r_prime[6*i + 1]*fp_r_prime[6*i + 3] + fp_r_prime[6*i + 4] - fp_r_prime[6*i + 5]);
		} //


		if ((p_r==P_check) && (b==0))
			std::cout<<"ACCEPT"<<std::endl;
		else{
			std::cout<<"ABORT"<<std::endl;
      if (p_r!=P_check)
      std::cout<< " Pr condition fails"<<std::endl;
      if (b!=0)
        std::cout<<"b condition fails"<<std::endl;
    }

}




void BEAVYProvider::Round2(ZZ_pE share[], ZZ_pE Beta[], ZZ_pE DIZK_share[], GF2X f, ZZ_pE fp_r[], ZZ_pE& P_r_t, ZZ_pE& b_t)
{

  // std::cout<<" \n the r recieved in Round 2 \n "<<r <<std::endl;
  ZZ_pX zero;
  SetCoeff(zero, 0, 0);
  std::cout<<" P(i-1), P(i+1) each do the below by themselves" <<std::endl;
  //sample random r from the extended ring

  ZZ_pX r1;
  ZZ_pE r;
  // random(r);
  // SetCoeff(r1, 0, 11094380486151696959);
  // SetCoeff(r1, 1, 5686881901046385085);
  // SetCoeff(r1, 2, 14448528186403186649);
  SetCoeff(r1, 0, 11094380486151696969);
  SetCoeff(r1, 1, 5686881901046385086);
  SetCoeff(r1, 2, 14448528186403186659);
  conv(r,r1);
  std::cout<<"r="<<r<<std::endl;



	//-----------------------each party part-----------------
  //get the w from the shares
  ZZ_pE w[6*NUMcGATES];
  for(int j = 0; j < 6*NUMcGATES; ++j)
    w[j]=DIZK_share[j];


  //get the rest from the shares as the shares of the coefficient of the polynomial p
  ZZ_pE a_coeff[(2*NUMgGATES)+1];
  std::cout<<6*NUMcGATES<<"\t"<<m<<"\n"<<std::endl;

	int k1=0;
  for(int j = 0; j < (2*NUMgGATES+1); ++j){
    a_coeff[k1]=DIZK_share[j];
    std::cout<<"a["<<k1<<"]="<<a_coeff[k1]<<std::endl;
		k1++;
  }

  //each element in the ring is a polynomial.
  //On top of that, the fi is a polynomial over polynomials
  //with the desired values and the evaluated points, interpolate to get the 6L polynomials.
  ZZ_pEX fp[6*NUMcGATES]; //each poly has M+1 coefficients. And, how many such polynomials are there 6*L. //this is the f_i. //this is polynomial of polynomials.
  //this is ZZ_PEX -- it represents polynomials over polynomials
  for(int j = 0; j < 6*NUMcGATES; ++j){
      		ZZ_pE c[NUMgGATES+1]; //Evaluation Vectors //Evaluated dPolynomials
      		c[0] = w[j]; // i_th poly will have i_th w as const
          for(int l = 1; l < NUMgGATES ; ++l){ //rest of them are the shares
      			std::cout<<l<<std::endl;
      			c[l] = share[6*NUMcGATES*(l - 1) + j];
      		}
          //shares and the constant terms have been set //now interp[olate  //make the Vandermonde matrix
          ZZ_pE y[NUMgGATES+1];
          interpolation(c,f,y);

      		std::cout<<"Reached Here 3"<<std::endl;
      		for(int l = 0; l < NUMgGATES+1; ++l)
      			SetCoeff(fp[j], l, y[l]); //at lth degree put y[l] bcz y is the coefficient vector for the polynomial

      		std::cout<<"P["<<j<<"]"<< fp[j]<<std::endl;
  	} //end of making polynomials

  //verify at the random r point on the field
  //---verify at random r point

  //ZZ_pE eval_at_r = eval(fp[0], r);


    for(int i=0; i<(6*NUMcGATES); i++){
      std::cout<<"reached here" <<std::endl;
        fp_r[i] = eval(fp[i], r);
        std::cout<<" fi polynomials evaluated at random r" <<fp_r[i]<<std::endl;
    }

  //------------using the shares of the coeffficient of polynomial p  --- a coefiicients
  int j=0; //j should run till 6*L
  //share of p_r

  conv(P_r_t, zero); //initialise the polynomial to 0 polynomial
  for(int i=0; i<(2*NUMgGATES);  i++ ){
      P_r_t+=a_coeff[i]*power(r,j);
  }
  std::cout<<" polynomial evaluated at random point r "<<P_r_t<<std::endl;

  //calculate the Beta round 2 step 3

  for(int j=0; j<NUMgGATES; j++){

        ZZ_pE sum;
      for(int k1=0; k1< (2*NUMgGATES); k1++){
        int temp = j;
        ZZ_pX eval_pt_X;
        SetCoeff(eval_pt_X, 0, 0);



        int i = 0;
        while(temp != 0){ //converting temp to binary equivalent
                SetCoeff(eval_pt_X, i, temp%2); //
                temp = temp / 2;
                ++i;
        } //eval_pt_X is the polynomial having the binary equivalent of the evaluation points

        ZZ_pE eval_pt;
        conv(eval_pt, eval_pt_X); //storing the bonary equivalent of the coefficients
        auto temp1=a_coeff[j]*(power(eval_pt,k1)); //this is inclusive of modulus f(x)
        sum+=temp1;
				std::cout<<"sum ="<<sum <<std::endl;
            // j++;
      }
      //b_t=Beta[j]*sum; //Beta[j] is ZZ_pE. sum is ZZ_pE.
      std::cout<<"Beta["<<j<<"]="<<Beta[j]<<std::endl;
      b_t=Beta[j]*sum;
      std::cout << "IN ROUND 2 LOOP " << Beta[j] << " \t" << j << " \t" << sum << " \t" << b_t << std::endl;
  }

  std::cout << " the b_t needed = " <<b_t <<std::endl;

}//end of Round 2







// len of pi1, pi2, pi3 is 6*NUMcGATES + 2*NUMgGATES + 1
void BEAVYProvider::Round1(ZZ_pE share[], GF2X f, ZZ_pE theta[], ZZ_pE pi[], ZZ_pE pi2[], ZZ_pE pi3[]){

	int i, j, l, k1;

	ZZ_pX zero;
	SetCoeff(zero, 0, 0);



	ZZ_pE w[6*NUMcGATES];
	for(i = 0; i < 6*NUMcGATES; ++i)
		random(w[i]);

	std::cout<<"Reached Here"<<std::endl;
  //insert correctn netwwen
  ZZ_pEX fp[6*NUMcGATES]; //each poly has M+1 coefficients. And, how many such polynomials are there 6*L.
      for(j = 0; j < 6*NUMcGATES; ++j){
        ZZ_pE c[NUMgGATES+1]; //Evaluation Vectors //Evaluated dPolynomials
        c[0] = w[j]; // i_th poly will have i_th w as const
          for(l = 1; l < NUMgGATES ; ++l){ //rest of them are the shares
            std::cout<<l<<std::endl;
            c[l] = share[6*NUMcGATES*(l - 1) + j];
          }

          ZZ_pE y[NUMgGATES+1]; //Coefficient Matrix
          std::cout<<"Reached Here 1"<<std::endl;
          interpolation(c, f, y);

		std::cout<<"Reached Here 3"<<std::endl;
		for(l = 0; l < NUMgGATES+1; ++l)
			SetCoeff(fp[j], l, y[l]); //at lth degree put y[l] bcz y is the coefficient vector for the polynomial

		std::cout<<"P["<<j<<"]"<< fp[j]<<std::endl;
	}

	ZZ_pEX P;
	SetCoeff(P, 0, 0);

	for(i = 0; i < NUMcGATES; ++i){
		P += theta[i] * (fp[6*i + 0]*fp[6*i + 2] + fp[6*i + 0]*fp[6*i + 3] + fp[6*i + 1]*fp[6*i + 3] + fp[6*i + 4] - fp[6*i + 5]);
	} // p is the small g circuit

  //val[i]=eval(P, evaluations[i])
  //P has at 0, the wj, so consider evluations starting from 1 only
      for(i = 1; i < N; ++i){ //Binary equivalent of the evaluation points
              int temp = i;
              ZZ_pX eval_pt_X;
              SetCoeff(eval_pt_X, 0, 0);



              j = 0;
              while(temp != 0){ //converting temp to binary equivalent
                      SetCoeff(eval_pt_X, j, temp%2); //
                      temp = temp / 2;
                      ++j;
              } //eval_pt_X is the polynomial having the binary equivalent of the evaluation points

              ZZ_pE eval_pt;
              conv(eval_pt, eval_pt_X); //storing the bonary equivalent of the coefficients
              auto vl=eval(P, eval_pt);
              std::cout<<" P evaluated at evaluation points "<< vl<<std::endl;
              if(vl!=0)
                std::cout<<" ABORT "<<std::endl;
              std::cout<<" N "<<N<< " i " << i<<std::endl;
      }


	for(i = 0; i < 6*NUMcGATES; ++i)
		pi[i] = w[i];

	for(i = 0; i < 2*NUMgGATES + 1; ++i)
		pi[6*NUMcGATES + i] = coeff(P, i);

	//pi is the share of the party Pi


	for(i = 0; i < 6*NUMcGATES + 2*NUMgGATES + 1; ++i){
		random(pi2[i]);
		pi3[i] = pi[i] - pi2[i];
	}

	for (int i=0; i<(6*NUMcGATES+2*NUMgGATES +1); i++)
			std::cout<<"the share of pi "<<pi[i] << std::endl;
}



//----------------here we are declaring the
//all parties together receive Beta1, Beta......, BetaM  From The extended Ring. and r from the the Extened Ring.
//here we are sampling through random function-----------------

//-------------global values-----------------------------

//------------P_i+1 and P_(i-1) do the following-------------------

//------------parse the p() share received as below----------------
//here we are sampling the share as our own.




  //Step c. Party P_(i-1) sends f1, f2, .....  to P_(i+1)


void BEAVYProvider::initiali(){
  //---------------------parameters for defining the ring------------
  GF2X f;

  SetCoeff(f, 3, 1);
  SetCoeff(f, 2, 1);
  SetCoeff(f, 0, 1);

  std::cout<<"polynomial f " <<f<<std::endl;

unsigned long modulus = (unsigned long) pow(2, k); // long can store only 64 bit number. Therefore, the largest number it can store is 2^{64} - 1
std::cout<<"k="<<k<<std::endl;
std::cout<<"modulus="<<modulus<<std::endl;
ZZ_p::init(conv<ZZ>(modulus) + 1); //adding 1 so that the p modulus is 2^{64} //
std::cout<<"ZZ_modulus="<<ZZ_p::modulus()<<std::endl;
std::cout<<"\n\n";


  ZZ_pX fZ;
  for(int i = 0; i < d; ++i){ // f is in G_2[x], so fZ is in Z_p[x]
    long c1;
      conv(c1, coeff(f,i));
      //std::cout<< " coeff	icients of f " <<c1<<std::endl;
      SetCoeff(fZ, i, (c1%((long)2)));
  }

  ZZ_pE::init((const ZZ_pX) fZ);
  //
  // ZZ_pX t11;
	// uint64_t num_t = (uint64_t) pow(2, 63);
	// t11 = num_t;
	// std::cout<<"Checking for k"<<t11<<std::endl;
  // std::cout<<"Testing inverseE function"<<std::endl;
  // std::cout<<"------------------------------------------------------------------------"<<std::endl;
  // ZZ_pE temp_inverse_check, temp_inverse_check2;
  // for(int i = 0; i < 10; ++i){
  //         random(temp_inverse_check);
  //         std::cout<<temp_inverse_check<<std::endl;
  //         temp_inverse_check2 = inverseE(temp_inverse_check, f, 4, k);
  //         std::cout<<temp_inverse_check2<<std::endl;
  //         std::cout<<temp_inverse_check2 * temp_inverse_check<<std::endl;
  //         std::cout<<std::endl;
  // }
  // std::cout<<"------------------------------------------------------------------------\n"<<std::endl;

}



}  // namespace MOTION::proto::beavy

