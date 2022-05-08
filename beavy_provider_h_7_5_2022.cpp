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

#pragma once

#include <memory>
#include <vector>

#include "base/gate_factory.h"
#include "protocols/common/comm_mixin.h"
#include "tensor/tensor_op.h"
#include "tensor/tensor_op_factory.h"
#include "utility/bit_vector.h"
#include "utility/enable_wait.h"
#include "utility/type_traits.hpp"

#include <type_traits>
#include <iostream>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h> //z_2^k[x]
#include <NTL/ZZ_pE.h> // z_2^k[x] / f[x]
#include <NTL/ZZ_pEX.h>
#include <NTL/GF2.h>  //F_2
#include <NTL/GF2X.h>
#include <NTL/vec_GF2.h>

//the below notations of DIZK are in coherence with https://eprint.iacr.org/2019/1390.pdf


#define NUMgGATES 1 //  M
//degree of the polynomial is d-1. we are using x^3 + x^2 +1 as the f(x). degree=3. But we take d=4. Needed to assign the coefficients for operations.

#define NUMcGATES  1//  L
#define NUMMULGATES NUMcGATES*NUMgGATES //m=M*L

namespace ENCRYPTO::ObliviousTransfer {
class OTProviderManager;
}

namespace MOTION {

using namespace NTL;

struct cckt {
  std::size_t gate_id;
  std::vector<std::uint64_t> ui, ui1, vi, vi1, alphai, zi;
};

class CircuitLoader;
class ArithmeticProviderManager;
class GateRegister;
class Logger;
class NewGate;
using NewGateP = std::unique_ptr<NewGate>;
class NewWire;
using NewWireP = std::shared_ptr<NewWire>;
using WireVector = std::vector<NewWireP>;

namespace Communication {
class CommunicationLayer;
}

namespace Crypto {
class MotionBaseProvider;
}  // namespace Crypto

namespace proto::gmw {
class BooleanGMWWire;
using BooleanGMWWireVector = std::vector<std::shared_ptr<BooleanGMWWire>>;
template <typename T>
class ArithmeticGMWWire;
template <typename T>
using ArithmeticGMWWireP = std::shared_ptr<ArithmeticGMWWire<T>>;
}  // namespace proto::gmw

namespace proto::beavy {

enum class OutputRecipient : std::uint8_t { garbler, evaluator, both };

class BooleanBEAVYWire;
using BooleanBEAVYWireP = std::shared_ptr<BooleanBEAVYWire>;
using BooleanBEAVYWireVector = std::vector<BooleanBEAVYWireP>;

class BEAVYProvider : public GateFactory,
                      public ENCRYPTO::enable_wait_setup,
                      public CommMixin,
                      public tensor::TensorOpFactory {
 public:
  enum class Role { garbler, evaluator };
  struct my_input_t {};

  BEAVYProvider(Communication::CommunicationLayer&, GateRegister&, CircuitLoader&,
                Crypto::MotionBaseProvider&, ENCRYPTO::ObliviousTransfer::OTProviderManager&,
                ArithmeticProviderManager&, std::shared_ptr<Logger>, bool fake_setup = false);
  ~BEAVYProvider();

  std::string get_provider_name() const noexcept override { return "BEAVYProvider"; }

  void setup();
  Crypto::MotionBaseProvider& get_motion_base_provider() noexcept { return motion_base_provider_; }

  //Crypto::MotionBaseProvider& get_motion_base_provider() noexcept { return motion_base_provider_; }
  ENCRYPTO::ObliviousTransfer::OTProviderManager& get_ot_manager() noexcept { return ot_manager_; }
  ArithmeticProviderManager& get_arith_manager() noexcept { return arith_manager_; }
  CircuitLoader& get_circuit_loader() noexcept { return circuit_loader_; }
  std::shared_ptr<Logger> get_logger() const noexcept { return logger_; }
  bool is_my_job(std::size_t gate_id) const noexcept;
  std::size_t get_my_id() const noexcept { return my_id_; }
  std::size_t get_num_parties() const noexcept { return num_parties_; }

  std::size_t get_next_input_id(std::size_t num_inputs) noexcept;

  bool get_fake_setup() const noexcept { return fake_setup_; }

  // Implementation of GateFactors interface

  // Boolean inputs
  std::pair<ENCRYPTO::ReusableFiberPromise<BitValues>, WireVector> make_boolean_input_gate_my(
      std::size_t input_owner, std::size_t num_wires, std::size_t num_simd) override;
  WireVector make_boolean_input_gate_other(std::size_t input_owner, std::size_t num_wires,
                                           std::size_t num_simd) override;

  // arithmetic inputs
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint8_t>>, WireVector>
  //binding the share with the wire --- @Arithmetic
  make_arithmetic_8_input_gate_my(std::size_t input_owner, std::size_t num_simd) override;
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint16_t>>, WireVector>
  make_arithmetic_16_input_gate_my(std::size_t input_owner, std::size_t num_simd) override;
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint32_t>>, WireVector>
  make_arithmetic_32_input_gate_my(std::size_t input_owner, std::size_t num_simd) override;
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint64_t>>, WireVector>
  make_arithmetic_64_input_gate_my(std::size_t input_owner, std::size_t num_simd) override;

  WireVector make_arithmetic_8_input_gate_other(std::size_t input_owner,
                                                std::size_t num_simd) override;
  WireVector make_arithmetic_16_input_gate_other(std::size_t input_owner,
                                                 std::size_t num_simd) override;
  WireVector make_arithmetic_32_input_gate_other(std::size_t input_owner,
                                                 std::size_t num_simd) override;
  WireVector make_arithmetic_64_input_gate_other(std::size_t input_owner,
                                                 std::size_t num_simd) override;

  // Boolean outputs
  ENCRYPTO::ReusableFiberFuture<BitValues> make_boolean_output_gate_my(std::size_t output_owner,const WireVector&) override;
  void make_boolean_output_gate_other(std::size_t output_owner, const WireVector&) override;

  // arithmetic outputs
  ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint8_t>> make_arithmetic_8_output_gate_my(
      std::size_t output_owner, const WireVector&) override;
  ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint16_t>> make_arithmetic_16_output_gate_my(
      std::size_t output_owner, const WireVector&) override;
  ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint32_t>> make_arithmetic_32_output_gate_my(
      std::size_t output_owner, const WireVector&) override;
  ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint64_t>> make_arithmetic_64_output_gate_my(
      std::size_t output_owner, const WireVector&) override;

  void make_arithmetic_output_gate_other(std::size_t output_owner, const WireVector&) override;

  // function gates
  WireVector make_unary_gate(ENCRYPTO::PrimitiveOperationType op, const WireVector&) override;

  WireVector make_binary_gate(ENCRYPTO::PrimitiveOperationType op, const WireVector&,
                              const WireVector&) override;

  std::pair<NewGateP, WireVector> construct_unary_gate(ENCRYPTO::PrimitiveOperationType op,
                                                       const WireVector&);

  std::pair<NewGateP, WireVector> construct_binary_gate(ENCRYPTO::PrimitiveOperationType op,
                                                        const WireVector&, const WireVector&);

  // conversions
  WireVector convert(MPCProtocol dst_protocol, const WireVector&) override;
// #define N 6
// #define d 4 //d = number of coefficients of the polynomial. //(d-1) degree polynomial has d number of coefficients
// #define k 20 // Z_2^k is the k here. Attenuate the value according to how big a Ring you want
// #define M 5
// //degree of the polynomial is d-1. we are using x^3 + x^2 +1 as the f(x). degree=3. But we take d=4. Needed to assign the coefficients for operations.
//
// #define L 1
  // implementation of TensorOpFactory
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint32_t>>, tensor::TensorCP>
  make_arithmetic_32_tensor_input_my(const tensor::TensorDimensions&) override;
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<std::uint64_t>>, tensor::TensorCP>
  make_arithmetic_64_tensor_input_my(const tensor::TensorDimensions&) override;

  tensor::TensorCP make_arithmetic_32_tensor_input_other(const tensor::TensorDimensions&) override;
  tensor::TensorCP make_arithmetic_64_tensor_input_other(const tensor::TensorDimensions&) override;

  // arithmetic outputs
  ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint32_t>> make_arithmetic_32_tensor_output_my(
      const tensor::TensorCP&) override;
  ENCRYPTO::ReusableFiberFuture<IntegerValues<std::uint64_t>> make_arithmetic_64_tensor_output_my(
      const tensor::TensorCP&) override;

  // conversions
  tensor::TensorCP make_tensor_conversion(MPCProtocol, const tensor::TensorCP input) override;

  void make_arithmetic_tensor_output_other(const tensor::TensorCP&) override;

  tensor::TensorCP make_tensor_flatten_op(const tensor::TensorCP input, std::size_t axis) override;
  tensor::TensorCP make_tensor_conv2d_op(const tensor::Conv2DOp& conv_op,
                                         const tensor::TensorCP input,
                                         const tensor::TensorCP kernel, const tensor::TensorCP bias,
                                         std::size_t fractional_bits = 0) override;
  using tensor::TensorOpFactory::make_tensor_conv2d_op;
  tensor::TensorCP make_tensor_gemm_op(const tensor::GemmOp& conv_op,
                                       const tensor::TensorCP input_A,
                                       const tensor::TensorCP input_B,
                                       std::size_t fractional_bits = 0) override;
  tensor::TensorCP make_tensor_sqr_op(const tensor::TensorCP input,
                                      std::size_t fractional_bits = 0) override;
  tensor::TensorCP make_tensor_relu_op(const tensor::TensorCP) override;
  template <typename T>
  tensor::TensorCP basic_make_tensor_relu_op(const tensor::TensorCP, const tensor::TensorCP);
  tensor::TensorCP make_tensor_relu_op(const tensor::TensorCP, const tensor::TensorCP) override;
  tensor::TensorCP make_tensor_maxpool_op(const tensor::MaxPoolOp&,
                                          const tensor::TensorCP) override;
  tensor::TensorCP make_tensor_avgpool_op(const tensor::AveragePoolOp&, const tensor::TensorCP,
                                          std::size_t fractional_bits = 0) override;
  template <typename T>
  tensor::TensorCP basic_make_convert_boolean_to_arithmetic_beavy_tensor(const tensor::TensorCP);
  tensor::TensorCP make_convert_boolean_to_arithmetic_beavy_tensor(const tensor::TensorCP);

// private:
public:
  enum class mixed_gate_mode_t { arithmetic, boolean, plain };
  template <typename T>
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<T>>, WireVector>
  basic_make_arithmetic_input_gate_my(std::size_t input_owner, std::size_t num_simd);
  template <typename T>
  WireVector basic_make_arithmetic_input_gate_other(std::size_t input_owner, std::size_t num_simd);
  template <typename T>
  ENCRYPTO::ReusableFiberFuture<IntegerValues<T>> basic_make_arithmetic_output_gate_my(
      std::size_t output_owner, const WireVector& in);
  template <typename BinaryGate, bool plain = false>
  WireVector make_boolean_binary_gate(const WireVector& in_a, const WireVector& in_b);
  WireVector make_inv_gate(const WireVector& in_a);
  WireVector make_xor_gate(const WireVector& in_a, const WireVector& in_b);
  WireVector make_and_gate(const WireVector& in_a, const WireVector& in_b);
  template <typename BinaryGate, bool plain = false>
  std::pair<NewGateP, WireVector> construct_boolean_binary_gate(const WireVector& in_a,
                                                                const WireVector& in_b);
  std::pair<NewGateP, WireVector> construct_inv_gate(const WireVector& in_a);
  std::pair<NewGateP, WireVector> construct_xor_gate(const WireVector& in_a,
                                                     const WireVector& in_b);
  std::pair<NewGateP, WireVector> construct_and_gate(const WireVector& in_a,
                                                     const WireVector& in_b);

  template <template <typename> class BinaryGate, typename T>
  WireVector make_arithmetic_unary_gate(const NewWireP& in_a);
  template <template <typename> class BinaryGate>
  WireVector make_arithmetic_unary_gate(const WireVector& in_a);
  template <template <typename> class BinaryGate, typename T, mixed_gate_mode_t mgm>
  WireVector make_arithmetic_binary_gate(const NewWireP& in_a, const NewWireP& in_b);
  template <template <typename> class BinaryGate,
            mixed_gate_mode_t mgm = mixed_gate_mode_t::arithmetic>
  WireVector make_arithmetic_binary_gate(const WireVector& in_a, const WireVector& in_b);
  WireVector make_neg_gate(const WireVector& in_a);
  WireVector make_add_gate(const WireVector& in_a, const WireVector& in_b);
  WireVector make_mul_gate(const WireVector& in_a, const WireVector& in_b);
  WireVector make_sqr_gate(const WireVector& in_a);
  template <typename T>
  WireVector basic_make_convert_to_arithmetic_beavy_gate(BooleanBEAVYWireVector&& in_a);
  WireVector make_convert_to_arithmetic_beavy_gate(BooleanBEAVYWireVector&& in_a);

 public:
  // TODO: design API for bit x integer operations
  template <typename T>
  WireVector basic_make_convert_bit_to_arithmetic_beavy_gate(BooleanBEAVYWireP in_a);

 private:
  WireVector make_convert_to_boolean_gmw_gate(BooleanBEAVYWireVector&& in_a);
  BooleanBEAVYWireVector make_convert_from_boolean_gmw_gate(const WireVector& in);
  template <typename T>
  WireVector basic_make_convert_to_arithmetic_gmw_gate(const NewWireP& in_a);
  WireVector make_convert_to_arithmetic_gmw_gate(const WireVector& in_a);
  template <typename T>
  WireVector basic_make_convert_from_arithmetic_gmw_gate(const NewWireP& in_a);
  WireVector make_convert_from_arithmetic_gmw_gate(const WireVector& in_a);
  WireVector convert_from_arithmetic_beavy(MPCProtocol dst_protocol, const WireVector&);
  WireVector convert_from_boolean_beavy(MPCProtocol dst_protocol, const WireVector&);
  WireVector convert_from_other_to_beavy(MPCProtocol dst_protocol, const WireVector&);
  WireVector convert_from_other_to_arithmetic_beavy(const WireVector&);
  WireVector convert_from_other_to_boolean_beavy(const WireVector&);

  // tensor stuff
  template <typename T>
  std::pair<ENCRYPTO::ReusableFiberPromise<IntegerValues<T>>, tensor::TensorCP>
  basic_make_arithmetic_tensor_input_my(const tensor::TensorDimensions&);
  template <typename T>
  tensor::TensorCP basic_make_arithmetic_tensor_input_other(const tensor::TensorDimensions&);
  template <typename T>
  ENCRYPTO::ReusableFiberFuture<IntegerValues<T>> basic_make_arithmetic_tensor_output_my(
      const tensor::TensorCP&);





 //private:
public:
  Communication::CommunicationLayer& communication_layer_;
  GateRegister& gate_register_;
  CircuitLoader& circuit_loader_;
  Crypto::MotionBaseProvider& motion_base_provider_;
  ENCRYPTO::ObliviousTransfer::OTProviderManager& ot_manager_;
  ArithmeticProviderManager& arith_manager_;
  std::size_t my_id_;
  std::size_t num_parties_;
  std::size_t next_input_id_;
  std::shared_ptr<Logger> logger_;
  bool fake_setup_;

  ZZ_pE _shares[6 * NUMMULGATES];
  int _numgatesshared = 0;

  void set_cckt(std::size_t gate_id, std::vector<uint8_t>& ui, std::vector<uint8_t>& ui1, std::vector<uint8_t>& vi, std::vector<uint8_t>& vi1, std::vector<uint8_t>& alphai, std::vector<uint8_t>& zi);

  void set_cckt(std::size_t gate_id, std::vector<uint16_t>& ui, std::vector<uint16_t>& ui1, std::vector<uint16_t>& vi, std::vector<uint16_t>& vi1, std::vector<uint16_t>& alphai, std::vector<uint16_t>& zi);

  void set_cckt(std::size_t gate_id, std::vector<uint32_t>& ui, std::vector<uint32_t>& ui1, std::vector<uint32_t>& vi, std::vector<uint32_t>& vi1, std::vector<uint32_t>& alphai, std::vector<uint32_t>& zi);

  void set_cckt(std::size_t gate_id, std::vector<uint64_t>& ui, std::vector<uint64_t>& ui1, std::vector<uint64_t>& vi, std::vector<uint64_t>& vi1, std::vector<uint64_t>& alphai, std::vector<uint64_t>& zi);

  void Round1(ZZ_pE share[], GF2X f, ZZ_pE theta[], ZZ_pE pi[], ZZ_pE pi2[], ZZ_pE pi3[]);
  void Round2(ZZ_pE share[],ZZ_pE Beta[], ZZ_pE DIZK_share[], GF2X f, ZZ_pE fp_r[], ZZ_pE& P_r_t, ZZ_pE& b_t);
  void Round3(ZZ_pE fp_r[], ZZ_pE p_r_t, ZZ_pE b_t, ZZ_pE fp_r_prime[], ZZ_pE p_r_t_prime, ZZ_pE b_t_prime, ZZ_pE theta[]);

  void DIZK_verify(std::size_t last_mult_gate_id);
  void initiali();

};

}  // namespace proto::beavy
}  // namespace MOTION

