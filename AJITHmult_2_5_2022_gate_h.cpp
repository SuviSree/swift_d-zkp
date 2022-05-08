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

#include <cstddef>

#include "gate/new_gate.h"
#include "utility/bit_vector.h"
#include "utility/reusable_future.h"
#include "utility/type_traits.hpp"
#include "wire.h"
#include "crypto/sharing_randomness_generator.h"
#include <iostream>
#include <string>
#include <sstream>

namespace ENCRYPTO::ObliviousTransfer {
class XCOTBitSender;
class XCOTBitReceiver;
}  // namespace ENCRYPTO::ObliviousTransfer

namespace MOTION {
template <typename T>
class BitIntegerMultiplicationBitSide;
template <typename T>
class BitIntegerMultiplicationIntSide;
template <typename T>
class IntegerMultiplicationSender;
template <typename T>
class IntegerMultiplicationReceiver;
}  // namespace MOTION

namespace MOTION::proto::beavy {

namespace detail {

class BasicBooleanBEAVYBinaryGate : public NewGate {
 public:
  BasicBooleanBEAVYBinaryGate(std::size_t gate_id, BooleanBEAVYWireVector&&,
                              BooleanBEAVYWireVector&&);
  BooleanBEAVYWireVector& get_output_wires() noexcept { return outputs_; }

 protected:
  std::size_t num_wires_;
  const BooleanBEAVYWireVector inputs_a_;
  const BooleanBEAVYWireVector inputs_b_;
  BooleanBEAVYWireVector outputs_;
};

class BasicBooleanBEAVYUnaryGate : public NewGate {
 public:
  BasicBooleanBEAVYUnaryGate(std::size_t gate_id, BooleanBEAVYWireVector&&, bool forward);
  BooleanBEAVYWireVector& get_output_wires() noexcept { return outputs_; }

 protected:
  std::size_t num_wires_;
  const BooleanBEAVYWireVector inputs_;
  BooleanBEAVYWireVector outputs_;
};

}  // namespace detail

class BEAVYProvider;
class BooleanBEAVYWire;
using BooleanBEAVYWireVector = std::vector<std::shared_ptr<BooleanBEAVYWire>>;

// using namespace std;

class BooleanBEAVYInputGateSender : public NewGate {
 public:
  BooleanBEAVYInputGateSender(std::size_t gate_id, BEAVYProvider&, std::size_t num_wires,
                              std::size_t num_simd,
                              ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  BooleanBEAVYWireVector& get_output_wires() noexcept { return outputs_; }

 private:
  BEAVYProvider& beavy_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_id_;
  ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>> input_future_;
  BooleanBEAVYWireVector outputs_;
};

class BooleanBEAVYInputGateReceiver : public NewGate {
 public:
  BooleanBEAVYInputGateReceiver(std::size_t gate_id, BEAVYProvider&, std::size_t num_wires,
                                std::size_t num_simd, std::size_t input_owner);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  BooleanBEAVYWireVector& get_output_wires() noexcept { return outputs_; }

 private:
  BEAVYProvider& beavy_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_owner_;
  std::size_t input_id_;
  BooleanBEAVYWireVector outputs_;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> public_share_future_;
};

class BooleanBEAVYOutputGate : public NewGate {
 public:
  BooleanBEAVYOutputGate(std::size_t gate_id, BEAVYProvider&, BooleanBEAVYWireVector&&,
                         std::size_t output_owner);
  ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>> get_output_future();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  BEAVYProvider& beavy_provider_;
  std::size_t num_wires_;
  std::size_t output_owner_;
  ENCRYPTO::ReusableFiberPromise<std::vector<ENCRYPTO::BitVector<>>> output_promise_;
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>> share_futures_;
  const BooleanBEAVYWireVector inputs_;
  ENCRYPTO::BitVector<> my_secret_share_;
};

class BooleanBEAVYINVGate : public detail::BasicBooleanBEAVYUnaryGate {
 public:
  BooleanBEAVYINVGate(std::size_t gate_id, const BEAVYProvider&, BooleanBEAVYWireVector&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  bool is_my_job_;
};

class BooleanBEAVYXORGate : public detail::BasicBooleanBEAVYBinaryGate {
 public:
  BooleanBEAVYXORGate(std::size_t gate_id, BEAVYProvider&, BooleanBEAVYWireVector&&,
                      BooleanBEAVYWireVector&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

class BooleanBEAVYANDGate : public detail::BasicBooleanBEAVYBinaryGate {
 public:
  BooleanBEAVYANDGate(std::size_t gate_id, BEAVYProvider&, BooleanBEAVYWireVector&&,
                      BooleanBEAVYWireVector&&);
  ~BooleanBEAVYANDGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  BEAVYProvider& beavy_provider_;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> share_future_;
  ENCRYPTO::BitVector<> delta_a_share_;
  ENCRYPTO::BitVector<> delta_b_share_;
  ENCRYPTO::BitVector<> Delta_y_share_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::XCOTBitSender> ot_sender_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::XCOTBitReceiver> ot_receiver_;
};

using namespace std;

template <typename T>
class ArithmeticBEAVYInputGateSender : public NewGate {
 public:
  ArithmeticBEAVYInputGateSender(std::size_t gate_id, BEAVYProvider&, std::size_t num_simd,
                                 ENCRYPTO::ReusableFiberFuture<std::vector<T>>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  ArithmeticBEAVYWireP<T>& get_output_wire() noexcept { return output_; }
  //added
  //std::vector<T> Pass(int party_id, auto party_key, std::size_t num_simd, std::size_t input_id_);
  void Pass(int party_id, std::size_t num_simd, std::size_t input_id_); //input_id = gate_id
  std::string sha256(std::string st);

  //MAKE this Pass Func override somehow in Mult
  std::vector<T> P0_key, P1_key, P2_key; //added

//input_id_ is the gate_id
 private:
  BEAVYProvider& beavy_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_id_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> input_future_;
  //suvi
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
  ArithmeticBEAVYWireP<T> output_;
  //added
  //ArithmeticBEAVYWireP<T> P0_key_;
  //ArithmeticBEAVYWireP<T> P1_key_;
  //ArithmeticBEAVYWireP<T> P2_key_;

  //added
};


template <typename T>
class ArithmeticBEAVYInputGateReceiver : public NewGate {
 public:
  ArithmeticBEAVYInputGateReceiver(std::size_t gate_id, BEAVYProvider&, std::size_t num_simd,
                                   std::size_t input_owner);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  ArithmeticBEAVYWireP<T>& get_output_wire() noexcept { return output_; }
  // std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> share_futures_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> public_share_future_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> public_share_future2_;
  // std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> public_share_future_;
  std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> share_futures_;

 private:
  BEAVYProvider& beavy_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_owner_;
  std::size_t input_id_;
  ArithmeticBEAVYWireP<T> output_;

  //SUVI
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_0;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_1;



  ArithmeticBEAVYWireP<T> hold0_;
  ArithmeticBEAVYWireP<T> hold1_;


};

template <typename T>
class ArithmeticBEAVYOutputGate : public NewGate {
 public:
  ArithmeticBEAVYOutputGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&,
                            std::size_t output_owner);
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> get_output_future();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  BEAVYProvider& beavy_provider_;
  std::size_t num_wires_;
  std::size_t output_owner_;
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> output_promise_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future0_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future1_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future2_;
  const ArithmeticBEAVYWireP<T> input_;
};

template <typename T>
class ArithmeticBEAVYOutputShareGate : public NewGate {
 public:
  ArithmeticBEAVYOutputShareGate(std::size_t gate_id, ArithmeticBEAVYWireP<T>&&);
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> get_public_share_future();
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> get_secret_share_future();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> public_share_promise_;
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> secret_share_promise_;
  const ArithmeticBEAVYWireP<T> input_;
};

namespace detail {

  // namespace Crypto {
  // class MotionBaseProvider;
  // }  // namespace Crypto

template <typename T>
class BasicArithmeticBEAVYBinaryGate : public NewGate {
 public:
  BasicArithmeticBEAVYBinaryGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&,
                                 ArithmeticBEAVYWireP<T>&&);
  ArithmeticBEAVYWireP<T>& get_output_wire() noexcept { return output_; }
  // void evaluate_setup() override; //added

  //added
  //void Pass(int party_id, std::size_t num_simd, std::size_t input_id_);
  //added

 protected:
  std::size_t num_wires_;
  const ArithmeticBEAVYWireP<T> input_a_;
  const ArithmeticBEAVYWireP<T> input_b_;
  ArithmeticBEAVYWireP<T> output_;
  // BEAVYProvider& beavy_provider_;
};

template <typename T>
class BasicArithmeticBEAVYUnaryGate : public NewGate {
 public:
  BasicArithmeticBEAVYUnaryGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&);
  ArithmeticBEAVYWireP<T>& get_output_wire() noexcept { return output_; }

 protected:
  std::size_t num_wires_;
  const ArithmeticBEAVYWireP<T> input_;
  ArithmeticBEAVYWireP<T> output_;
};

template <typename T>
class BasicBooleanXArithmeticBEAVYBinaryGate : public NewGate {
 public:
  BasicBooleanXArithmeticBEAVYBinaryGate(std::size_t gate_id, BEAVYProvider&, BooleanBEAVYWireP&&,
                                         ArithmeticBEAVYWireP<T>&&);
  ArithmeticBEAVYWireP<T>& get_output_wire() noexcept { return output_; }
  //added


 protected:
  const BooleanBEAVYWireP input_bool_;
  const ArithmeticBEAVYWireP<T> input_arith_;
  ArithmeticBEAVYWireP<T> output_;
};

}  // namespace detail

template <typename T>
class ArithmeticBEAVYNEGGate : public detail::BasicArithmeticBEAVYUnaryGate<T> {
 public:
  ArithmeticBEAVYNEGGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
};

template <typename T>
class ArithmeticBEAVYADDGate : public detail::BasicArithmeticBEAVYBinaryGate<T> {
 public:
  ArithmeticBEAVYADDGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&,
                         ArithmeticBEAVYWireP<T>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  protected:
    BEAVYProvider& beavy_provider_;
    //ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
};

//template <typename T>class ArithmeticBEAVYMULGate : public detail::BasicArithmeticBEAVYBinaryGate<T>, public MOTION::proto::beavy::ArithmeticBEAVYInputGateSender<T>  {
template <typename T>class ArithmeticBEAVYMULGate : public detail::BasicArithmeticBEAVYBinaryGate<T> {
 public:
  ArithmeticBEAVYMULGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&,
                         ArithmeticBEAVYWireP<T>&&);
  ~ArithmeticBEAVYMULGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  //added
  void Pass(int party_id, std::size_t num_simd, std::size_t input_id_);
  //added
  // std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> Setupshare_futures_;
//std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> share_futures_;

// ENCRYPTO::ReusableFiberFuture<std::vector<T>> Setup_share_futures_;

ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_online_;
// ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_futures00_;
// ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_futures01_;
// std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> share_futures1_;
// std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> share_futures2_;
// ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_futures2_;
//ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_futures0_;
//ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_futures1_;
ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future0_;
ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future1_;
ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future2_;


ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future00_;
ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future11_;
ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future01_;
ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future10_;
std::vector<T> delta_ab_share1;
// std::vector<T> d_;
// std::vector<T> e_;




 private:
  BEAVYProvider& beavy_provider_;

  //std::vector<T> Delta_y_share_;
  std::vector<T> Delta_y_share0_;
  std::vector<T> Delta_y_share1_;
  std::vector<T> Delta_y_share2_;

  std::vector<T> lambda_x0;
  std::vector<T> lambda_y0;
  std::vector<T> lambda_x1;
  std::vector<T> lambda_y1;

  std::vector<T> lambda_x2;
  std::vector<T> lambda_y2;
  // std::vector<T> lambda_z0;
  // std::vector<T> lambda_z1;
  // std::vector<T> lambda_z2;


  // std::vector<T> z0(num_simd_);
  // std::vector<T> z1(num_simd_);
  // std::vector<T> z2(num_simd_);




  //added


protected: //suvi
  std::size_t input_id_;
  std::size_t num_simd_;
  //suvi
  beavy::ArithmeticBEAVYWireP<T> temp_;
  //MOTION::proto::beavy::ArithmeticBEAVYInputGateSender<T>&& ArithSend_;
  // std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> Setup_share_futures_;


};

template <typename T>
class ArithmeticBEAVYSQRGate : public detail::BasicArithmeticBEAVYUnaryGate<T> {
 public:
  ArithmeticBEAVYSQRGate(std::size_t gate_id, BEAVYProvider&, ArithmeticBEAVYWireP<T>&&);
  ~ArithmeticBEAVYSQRGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  BEAVYProvider& beavy_provider_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
  std::vector<T> Delta_y_share_;
  std::unique_ptr<MOTION::IntegerMultiplicationSender<T>> mult_sender_;
  std::unique_ptr<MOTION::IntegerMultiplicationReceiver<T>> mult_receiver_;
};

template <typename T>
class BooleanXArithmeticBEAVYMULGate : public detail::BasicBooleanXArithmeticBEAVYBinaryGate<T> {
 public:
  BooleanXArithmeticBEAVYMULGate(std::size_t gate_id, BEAVYProvider&, BooleanBEAVYWireP&&,
                                 ArithmeticBEAVYWireP<T>&&);
  ~BooleanXArithmeticBEAVYMULGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  BEAVYProvider& beavy_provider_;
  std::unique_ptr<MOTION::BitIntegerMultiplicationBitSide<T>> mult_bit_side_;
  std::unique_ptr<MOTION::BitIntegerMultiplicationIntSide<T>> mult_int_side_;
  std::vector<T> delta_b_share_;
  std::vector<T> delta_b_x_delta_n_share_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
};

}  // namespace MOTION::proto::beavy

