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

#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"

namespace MOTION {

class Logger;

namespace Communication {
class CommunicationLayer;
enum class MessageType : std::uint8_t;
}  // namespace Communication

namespace proto {

class CommMixin {
 public:
  CommMixin(Communication::CommunicationLayer&, Communication::MessageType,
            std::shared_ptr<Logger>);
  ~CommMixin();

  void broadcast_bits_message(std::size_t gate_id, const ENCRYPTO::BitVector<>& message,
                              std::size_t msg_num = 0) const;
  void send_bits_message(std::size_t party_id, std::size_t gate_id,
                         const ENCRYPTO::BitVector<>& message, std::size_t msg_num = 0) const;
  [[nodiscard]] std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>>
  register_for_bits_messages(std::size_t gate_id, std::size_t num_bits, std::size_t msg_num = 0);
  [[nodiscard]] ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> register_for_bits_message(
      std::size_t party_id, std::size_t gate_id, std::size_t num_bits, std::size_t msg_num = 0);

  void broadcast_blocks_message(std::size_t gate_id, const ENCRYPTO::block128_vector& message,
                                std::size_t msg_num = 0) const;
  void send_blocks_message(std::size_t party_id, std::size_t gate_id,
                           const ENCRYPTO::block128_vector& message, std::size_t msg_num = 0) const;
  [[nodiscard]] std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>>
  register_for_blocks_messages(std::size_t gate_id, std::size_t num_bits, std::size_t msg_num = 0);
  [[nodiscard]] ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>
  register_for_blocks_message(std::size_t party_id, std::size_t gate_id, std::size_t num_bits,
                              std::size_t msg_num = 0);

  template <typename T>
  void broadcast_ints_message(std::size_t gate_id, const std::vector<T>& message,
                              std::size_t msg_num = 0) const;
  template <typename T>
  void send_ints_message(std::size_t party_id, std::size_t gate_id, const std::vector<T>& message,
                         std::size_t msg_num = 0) const;
  template <typename T>
  [[nodiscard]] std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>>
  register_for_ints_messages(std::size_t gate_id, std::size_t num_elements,
                             std::size_t msg_num = 0);
  template <typename T>
  [[nodiscard]] ENCRYPTO::ReusableFiberFuture<std::vector<T>> register_for_ints_message(
      std::size_t party_id, std::size_t gate_id, std::size_t num_elements, std::size_t msg_num = 0);

  template <typename T>
  void joint_send_ints_message(std:: size_t party_i, std::size_t party_j, std::size_t party_k, std::size_t gate_id, const std::vector<T>& hashed_value, std::size_t num_elements, std::size_t msg_num);

  template <typename T>
  void joint_verify_ints_message(std:: size_t party_i, std::size_t party_j, std::size_t party_k, std::size_t gate_id, const std::vector<T>& hashed_value, std::size_t num_elements, std::size_t msg_num);

 // private:
public:
  flatbuffers::FlatBufferBuilder build_gate_message(std::size_t gate_id, std::size_t msg_num,
                                                    const std::uint8_t* message,
                                                    std::size_t size) const;
  template <typename T>
  flatbuffers::FlatBufferBuilder build_gate_message(std::size_t gate_id, std::size_t msg_num,
                                                    const std::vector<T>& vector) const;
  flatbuffers::FlatBufferBuilder build_gate_message(std::size_t gate_id, std::size_t msg_num,
                                                    const ENCRYPTO::BitVector<>& message) const;
  flatbuffers::FlatBufferBuilder build_gate_message(std::size_t gate_id, std::size_t msg_num,
                                                    const ENCRYPTO::block128_vector& message) const;

  struct GateMessageHandler;
  Communication::CommunicationLayer& communication_layer_;
  Communication::MessageType gate_message_type_;
  std::size_t my_id_;
  std::size_t num_parties_;
  std::shared_ptr<GateMessageHandler> message_handler_;
  std::shared_ptr<Logger> logger_;
  ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>> share_future_;


};

}  // namespace proto
}  // namespace MOTION
