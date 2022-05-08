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

#include "comm_mixin.h"

#include <cstdint>
#include <type_traits>
#include <unordered_map>

#include <boost/functional/hash.hpp>

#include "communication/communication_layer.h"
#include "communication/fbs_headers/comm_mixin_gate_message_generated.h"
#include "communication/message.h"
#include "communication/message_handler.h"
#include "utility/constants.h"
#include "utility/logger.h"
#include "openssl/sha.h"
#include <sstream>
#include <string>
#include <iomanip>
#include <stdio.h> /* C standard io header file */
// #include "ntl-11.5.1/include/NTL/ZZ_p.h" /* Include all GFL header files */
// #include "ntl-11.5.1/include/NTL/ZZ_pX.h"
// #include "ntl-11.5.1/include/NTL/ZZ_pE.h"
// #include "GFL/ALL.h"
// #include <utility/bigint.h>
// #include <NTL/ZZ_pXFactoring.h>
//
// #include <NTL/ZZ_p.h>
// #include <NTL/ZZ_pX.h>
// #include <NTL/ZZ_pE.h>

namespace {

struct SizeTPairHash {
  std::size_t operator()(const std::pair<std::size_t, std::size_t>& p) const {
    std::size_t seed = 0;
    boost::hash_combine(seed, p.first);
    boost::hash_combine(seed, p.second);
    return seed;
  }
};

}  // namespace

namespace MOTION::proto {

struct CommMixin::GateMessageHandler : public Communication::MessageHandler {
  GateMessageHandler(std::size_t num_parties, Communication::MessageType gate_message_type,
                     std::shared_ptr<Logger> logger);
  void received_message(std::size_t, std::vector<std::uint8_t>&& raw_message) override;

  enum class MsgValueType { bit, block, uint8, uint16, uint32, uint64 };

  template <typename T>
  constexpr static CommMixin::GateMessageHandler::MsgValueType get_msg_value_type();

  // KeyType = (gate_id, msg_num)
  using KeyType = std::pair<std::size_t, std::size_t>;

  // KeyType -> (size, type)
  std::unordered_map<KeyType, std::pair<std::size_t, MsgValueType>, SizeTPairHash>
      expected_messages_;

  // [KeyType -> promise]
  std::vector<std::unordered_map<KeyType, ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>>,
                                 SizeTPairHash>>
      bits_promises_;
  std::vector<std::unordered_map<KeyType, ENCRYPTO::ReusableFiberPromise<ENCRYPTO::block128_vector>,
                                 SizeTPairHash>>
      blocks_promises_;
  std::vector<std::unordered_map<KeyType, ENCRYPTO::ReusableFiberPromise<std::vector<std::uint8_t>>,
                                 SizeTPairHash>>
      uint8_promises_;
  std::vector<std::unordered_map<
      KeyType, ENCRYPTO::ReusableFiberPromise<std::vector<std::uint16_t>>, SizeTPairHash>>
      uint16_promises_;
  std::vector<std::unordered_map<
      KeyType, ENCRYPTO::ReusableFiberPromise<std::vector<std::uint32_t>>, SizeTPairHash>>
      uint32_promises_;
  std::vector<std::unordered_map<
      KeyType, ENCRYPTO::ReusableFiberPromise<std::vector<std::uint64_t>>, SizeTPairHash>>
      uint64_promises_;

  template <typename T>
  std::vector<
      std::unordered_map<KeyType, ENCRYPTO::ReusableFiberPromise<std::vector<T>>, SizeTPairHash>>&
  get_promise_map();

  Communication::MessageType gate_message_type_;
  std::shared_ptr<Logger> logger_;
};

template <typename T>
constexpr CommMixin::GateMessageHandler::MsgValueType
CommMixin::GateMessageHandler::get_msg_value_type() {
  if constexpr (std::is_same_v<T, std::uint8_t>) {
    return CommMixin::GateMessageHandler::MsgValueType::uint8;
  } else if constexpr (std::is_same_v<T, std::uint16_t>) {
    return CommMixin::GateMessageHandler::MsgValueType::uint16;
  } else if constexpr (std::is_same_v<T, std::uint32_t>) {
    return CommMixin::GateMessageHandler::MsgValueType::uint32;
  } else if constexpr (std::is_same_v<T, std::uint64_t>) {
    return CommMixin::GateMessageHandler::MsgValueType::uint64;
  }
}

template <>
std::vector<
    std::unordered_map<CommMixin::GateMessageHandler::KeyType,
                       ENCRYPTO::ReusableFiberPromise<std::vector<std::uint8_t>>, SizeTPairHash>>&
CommMixin::GateMessageHandler::get_promise_map() {
  return uint8_promises_;
}
template <>
std::vector<
    std::unordered_map<CommMixin::GateMessageHandler::KeyType,
                       ENCRYPTO::ReusableFiberPromise<std::vector<std::uint16_t>>, SizeTPairHash>>&
CommMixin::GateMessageHandler::get_promise_map() {
  return uint16_promises_;
}
template <>
std::vector<
    std::unordered_map<CommMixin::GateMessageHandler::KeyType,
                       ENCRYPTO::ReusableFiberPromise<std::vector<std::uint32_t>>, SizeTPairHash>>&
CommMixin::GateMessageHandler::get_promise_map() {
  return uint32_promises_;
}
template <>
std::vector<
    std::unordered_map<CommMixin::GateMessageHandler::KeyType,
                       ENCRYPTO::ReusableFiberPromise<std::vector<std::uint64_t>>, SizeTPairHash>>&
CommMixin::GateMessageHandler::get_promise_map() {
  return uint64_promises_;
}

CommMixin::GateMessageHandler::GateMessageHandler(std::size_t num_parties,
                                                  Communication::MessageType gate_message_type,
                                                  std::shared_ptr<Logger> logger)
    : bits_promises_(num_parties),
      blocks_promises_(num_parties),
      uint8_promises_(num_parties),
      uint16_promises_(num_parties),
      uint32_promises_(num_parties),
      uint64_promises_(num_parties),
      gate_message_type_(gate_message_type),
      logger_(logger) {}

void CommMixin::GateMessageHandler::received_message(std::size_t party_id,
                                                     std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = Communication::GetMessage(raw_message.data());
  {
    flatbuffers::Verifier verifier(raw_message.data(), raw_message.size());
    if (!message->Verify(verifier)) {
      throw std::runtime_error("received malformed Message");
      // TODO: log and drop instead
    }
  }

  auto message_type = message->message_type();
  if (message_type != gate_message_type_) {
    throw std::logic_error(
        fmt::format("CommMixin::GateMessageHandler: received unexpected message of type {}",
                    EnumNameMessageType(message_type)));
  }

  auto gate_message =
      flatbuffers::GetRoot<MOTION::Communication::CommMixinGateMessage>(message->payload()->data());
  {
    flatbuffers::Verifier verifier(message->payload()->data(), message->payload()->size());
    if (!gate_message->Verify(verifier)) {
      throw std::runtime_error(
          fmt::format("received malformed {}", EnumNameMessageType(gate_message_type_)));
      // TODO: log and drop instead
    }
  }
  auto gate_id = gate_message->gate_id();
  auto msg_num = gate_message->msg_num();
  auto payload = gate_message->payload();
  auto it = expected_messages_.find({gate_id, msg_num});
  if (it == expected_messages_.end()) {
    logger_->LogError(fmt::format("received unexpected {} for gate {}, dropping",
                                  EnumNameMessageType(gate_message_type_), gate_id));
    return;
  }
  auto expected_size = it->second.first;
  auto type = it->second.second;

  auto set_value_helper = [this, party_id, gate_id, msg_num, expected_size, payload](
                              auto& map_vec, auto type_tag) {
    auto byte_size = expected_size * sizeof(type_tag);
    if (byte_size != payload->size()) {
      logger_->LogError(fmt::format(
          "received {} for gate {} (msg_num {}) of size {} while expecting size {}, dropping",
          EnumNameMessageType(gate_message_type_), gate_id, msg_num, payload->size(), byte_size));
      return;
    }
    auto& promise_map = map_vec[party_id];
    std::cout << "inside comm mixing: "<<"gate_id: " << gate_id << "\tmsg_num: " << msg_num << "\tParty " << party_id << std::endl;
    // for (auto x : promise_map) {
    //   std::cout << x.first << "  /* message */  " << x.second << std::endl;
    // }
    std::cout << " size of promise map inside comm_mixing " << promise_map.size() << "GATE ID " << gate_id << "MSGNUM " << msg_num << "PID " << party_id << std::endl; // ALANNN
    auto& promise = promise_map.at({gate_id, msg_num});
    auto ptr = reinterpret_cast<const decltype(type_tag)*>(payload->data());
    try {
      promise.set_value(std::vector(ptr, ptr + expected_size));
    } catch (std::future_error& e) {
      logger_->LogError(fmt::format(
          "unable to fulfill promise ({}) for {} (ints) for gate {} (msg_num {}), dropping",
          e.what(), EnumNameMessageType(gate_message_type_), gate_id, msg_num));
    }
  };

  switch (type) {
    case MsgValueType::bit: {
      auto byte_size = Helpers::Convert::BitsToBytes(expected_size);
      if (byte_size != payload->size()) {
        logger_->LogError(fmt::format(
            "received {} for gate {} (msg_num {}) of size {} while expecting size {}, dropping",
            EnumNameMessageType(gate_message_type_), gate_id, msg_num, payload->size(), byte_size));
        return;
      }
      auto& promise = bits_promises_[party_id].at({gate_id, msg_num});
      try {
        promise.set_value(ENCRYPTO::BitVector(payload->data(), expected_size));
      } catch (std::future_error& e) {
        logger_->LogError(fmt::format(
            "unable to fulfill promise ({}) for {} (bits) for gate {} (msg_num {}), dropping",
            e.what(), EnumNameMessageType(gate_message_type_), gate_id, msg_num));
      }
      break;
    }
    case MsgValueType::block: {
      auto byte_size = 16 * expected_size;
      if (byte_size != payload->size()) {
        logger_->LogError(fmt::format(
            "received {} for gate {} (msg_num {}) of size {} while expecting size {}, dropping",
            EnumNameMessageType(gate_message_type_), gate_id, msg_num, payload->size(), byte_size));
        return;
      }
      auto& promise = blocks_promises_[party_id].at({gate_id, msg_num});
      try {
        promise.set_value(ENCRYPTO::block128_vector(expected_size, payload->data()));
      } catch (std::future_error& e) {
        logger_->LogError(fmt::format(
            "unable to fulfill promise ({}) for {} (blocks) for gate {} (msg_num {}), dropping",
            e.what(), EnumNameMessageType(gate_message_type_), gate_id, msg_num));
      }
      break;
    }
    case MsgValueType::uint8: {
      set_value_helper(uint8_promises_, std::uint8_t{});
      break;
    }
    case MsgValueType::uint16: {
      set_value_helper(uint16_promises_, std::uint16_t{});
      break;
    }
    case MsgValueType::uint32: {
      set_value_helper(uint32_promises_, std::uint32_t{});
      break;
    }
    case MsgValueType::uint64: {
      set_value_helper(uint64_promises_, std::uint64_t{});
      break;
    }
  }
}

CommMixin::CommMixin(Communication::CommunicationLayer& communication_layer,
                     Communication::MessageType gate_message_type, std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      gate_message_type_(gate_message_type),
      my_id_(communication_layer.get_my_id()),
      num_parties_(communication_layer.get_num_parties()),
      message_handler_(std::make_unique<GateMessageHandler>(communication_layer_.get_num_parties(),
                                                            gate_message_type, logger)),
      logger_(std::move(logger)) {
  // TODO
  communication_layer_.register_message_handler([this](auto) { return message_handler_; },
                                                {gate_message_type});
}

CommMixin::~CommMixin() { communication_layer_.deregister_message_handler({gate_message_type_}); }

flatbuffers::FlatBufferBuilder CommMixin::build_gate_message(std::size_t gate_id,
                                                             std::size_t msg_num,
                                                             const std::uint8_t* message,
                                                             std::size_t size) const {
  flatbuffers::FlatBufferBuilder builder;
  auto vector = builder.CreateVector(message, size);
  auto root = Communication::CreateCommMixinGateMessage(builder, gate_id, msg_num, vector);
  builder.Finish(root);
  return Communication::BuildMessage(gate_message_type_, builder.GetBufferPointer(),
                                     builder.GetSize());
}

template <typename T>
flatbuffers::FlatBufferBuilder CommMixin::build_gate_message(std::size_t gate_id,
                                                             std::size_t msg_num,
                                                             const std::vector<T>& vector) const {
  return build_gate_message(gate_id, msg_num, reinterpret_cast<const std::uint8_t*>(vector.data()),
                            sizeof(T) * vector.size());
}

flatbuffers::FlatBufferBuilder CommMixin::build_gate_message(
    std::size_t gate_id, std::size_t msg_num, const ENCRYPTO::BitVector<>& message) const {
  auto vector = message.GetData();
  return build_gate_message(gate_id, msg_num, reinterpret_cast<const std::uint8_t*>(vector.data()),
                            vector.size());
}

flatbuffers::FlatBufferBuilder CommMixin::build_gate_message(
    std::size_t gate_id, std::size_t msg_num, const ENCRYPTO::block128_vector& message) const {
  auto data = message.data();
  return build_gate_message(gate_id, msg_num, reinterpret_cast<const std::uint8_t*>(data),
                            16 * message.size());
}

void CommMixin::broadcast_bits_message(std::size_t gate_id, const ENCRYPTO::BitVector<>& message,
                                       std::size_t msg_num) const {
  communication_layer_.broadcast_message(build_gate_message(gate_id, msg_num, message));
}

void CommMixin::send_bits_message(std::size_t party_id, std::size_t gate_id,
                                  const ENCRYPTO::BitVector<>& message, std::size_t msg_num) const {
  communication_layer_.send_message(party_id, build_gate_message(gate_id, msg_num, message));
}

[[nodiscard]] std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>>
CommMixin::register_for_bits_messages(std::size_t gate_id, std::size_t num_bits,
                                      std::size_t msg_num) {
  auto& mh = *message_handler_;
  std::vector<ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>>> promises(num_parties_);
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>> futures;
  std::transform(std::begin(promises), std::end(promises), std::back_inserter(futures),
                 [](auto& p) { return p.get_future(); });
  auto [_, success] = mh.expected_messages_.insert(
      {std::make_pair(gate_id, msg_num),
       std::make_pair(num_bits, GateMessageHandler::MsgValueType::bit)});
  if (!success) {
    throw std::logic_error(fmt::format("tried to register twice for message for gate {}", gate_id));
  }
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& promise_map = mh.bits_promises_.at(party_id);
    auto [_, success] =
        promise_map.insert({std::make_pair(gate_id, msg_num), std::move(promises.at(party_id))});
    assert(success);
  }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    if (logger_) {
      logger_->LogTrace(
          fmt::format("Gate {}: registered for bits messages of size {}", gate_id, num_bits));
    }
  }
  return futures;
}

[[nodiscard]] ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>
CommMixin::register_for_bits_message(std::size_t party_id, std::size_t gate_id,
                                     std::size_t num_bits, std::size_t msg_num) {
  assert(party_id != my_id_);
  auto& mh = *message_handler_;
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>> promise;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> future = promise.get_future();
  auto [_, success] = mh.expected_messages_.insert(
      {std::make_pair(gate_id, msg_num),
       std::make_pair(num_bits, GateMessageHandler::MsgValueType::bit)});
  if (!success) {
    throw std::logic_error(fmt::format("tried to register twice for message for gate {}", gate_id));
  }
  {
    auto& promise_map = mh.bits_promises_.at(party_id);
    auto [_, success] = promise_map.insert({std::make_pair(gate_id, msg_num), std::move(promise)});
    assert(success);
  }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    if (logger_) {
      logger_->LogTrace(
          fmt::format("Gate {}: registered for bits message of size {}", gate_id, num_bits));
    }
  }
  return future;
}

void CommMixin::broadcast_blocks_message(std::size_t gate_id,
                                         const ENCRYPTO::block128_vector& message,
                                         std::size_t msg_num) const {
  communication_layer_.broadcast_message(build_gate_message(gate_id, msg_num, message));
}

void CommMixin::send_blocks_message(std::size_t party_id, std::size_t gate_id,
                                    const ENCRYPTO::block128_vector& message,
                                    std::size_t msg_num) const {
  communication_layer_.send_message(party_id, build_gate_message(gate_id, msg_num, message));
}

[[nodiscard]] std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>>
CommMixin::register_for_blocks_messages(std::size_t gate_id, std::size_t num_blocks,
                                        std::size_t msg_num) {
  auto& mh = *message_handler_;
  std::vector<ENCRYPTO::ReusableFiberPromise<ENCRYPTO::block128_vector>> promises(num_parties_);
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>> futures;
  std::transform(std::begin(promises), std::end(promises), std::back_inserter(futures),
                 [](auto& p) { return p.get_future(); });
  auto [_, success] = mh.expected_messages_.insert(
      {std::make_pair(gate_id, msg_num),
       std::make_pair(num_blocks, GateMessageHandler::MsgValueType::block)});
  if (!success) {
    throw std::logic_error(fmt::format("tried to register twice for message for gate {}", gate_id));
  }
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& promise_map = mh.blocks_promises_.at(party_id);
    auto [_, success] =
        promise_map.insert({std::make_pair(gate_id, msg_num), std::move(promises.at(party_id))});
    assert(success);
  }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    if (logger_) {
      logger_->LogTrace(
          fmt::format("Gate {}: registered for blocks messages of size {}", gate_id, num_blocks));
    }
  }
  return futures;
}

[[nodiscard]] ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>
CommMixin::register_for_blocks_message(std::size_t party_id, std::size_t gate_id,
                                       std::size_t num_blocks, std::size_t msg_num) {
  assert(party_id != my_id_);
  auto& mh = *message_handler_;
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::block128_vector> promise;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector> future = promise.get_future();
  auto [_, success] = mh.expected_messages_.insert(
      {std::make_pair(gate_id, msg_num),
       std::make_pair(num_blocks, GateMessageHandler::MsgValueType::block)});
  if (!success) {
    throw std::logic_error(fmt::format("tried to register twice for message for gate {}", gate_id));
  }
  {
    auto& promise_map = mh.blocks_promises_.at(party_id);
    auto [_, success] = promise_map.insert({std::make_pair(gate_id, msg_num), std::move(promise)});
    assert(success);
  }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    if (logger_) {
      logger_->LogTrace(
          fmt::format("Gate {}: registered for blocks message of size {}", gate_id, num_blocks));
    }
  }
  return future;
}

template <typename T>
void CommMixin::broadcast_ints_message(std::size_t gate_id, const std::vector<T>& message,
                                       std::size_t msg_num) const {
  communication_layer_.broadcast_message(build_gate_message(gate_id, msg_num, message));
}

template void CommMixin::broadcast_ints_message(std::size_t, const std::vector<std::uint8_t>&,
                                                std::size_t) const;
template void CommMixin::broadcast_ints_message(std::size_t, const std::vector<std::uint16_t>&,
                                                std::size_t) const;
template void CommMixin::broadcast_ints_message(std::size_t, const std::vector<std::uint32_t>&,
                                                std::size_t) const;
template void CommMixin::broadcast_ints_message(std::size_t, const std::vector<std::uint64_t>&,
                                                std::size_t) const;

template <typename T>
void CommMixin::send_ints_message(std::size_t party_id, std::size_t gate_id,
                                  const std::vector<T>& message, std::size_t msg_num) const {
  communication_layer_.send_message(party_id, build_gate_message(gate_id, msg_num, message));
}

template void CommMixin::send_ints_message(std::size_t, std::size_t,
                                           const std::vector<std::uint8_t>&, std::size_t) const;
template void CommMixin::send_ints_message(std::size_t, std::size_t,
                                           const std::vector<std::uint16_t>&, std::size_t) const;
template void CommMixin::send_ints_message(std::size_t, std::size_t,
                                           const std::vector<std::uint32_t>&, std::size_t) const;
template void CommMixin::send_ints_message(std::size_t, std::size_t,
                                           const std::vector<std::uint64_t>&, std::size_t) const;

template <typename T>
[[nodiscard]] std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>>
CommMixin::register_for_ints_messages(std::size_t gate_id, std::size_t num_elements,
                                      std::size_t msg_num) {
  auto& mh = *message_handler_;
  std::vector<ENCRYPTO::ReusableFiberPromise<std::vector<T>>> promises(num_parties_);
  std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<T>>> futures;
  std::transform(std::begin(promises), std::end(promises), std::back_inserter(futures),
                 [](auto& p) { return p.get_future(); });
  auto type = GateMessageHandler::get_msg_value_type<T>();
  auto [_, success] = mh.expected_messages_.insert(
      {std::make_pair(gate_id, msg_num), std::make_pair(num_elements, type)});
  if (!success) {
    throw std::logic_error(
        fmt::format("tried to register twice for message {} for gate {}", msg_num, gate_id));
  }
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    auto& promise_map = mh.get_promise_map<T>().at(party_id);
    auto [_, success] =
        promise_map.insert({std::make_pair(gate_id, msg_num), std::move(promises.at(party_id))});
    assert(success);
  }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    if (logger_) {
      logger_->LogTrace(fmt::format("Gate {}: registered for int messages {} of size {}", gate_id,
                                    msg_num, num_elements));
    }
  }
  return futures;
}

template std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>>
    CommMixin::register_for_ints_messages(std::size_t, std::size_t, std::size_t);
template std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint16_t>>>
    CommMixin::register_for_ints_messages(std::size_t, std::size_t, std::size_t);
template std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint32_t>>>
    CommMixin::register_for_ints_messages(std::size_t, std::size_t, std::size_t);
template std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>>>
    CommMixin::register_for_ints_messages(std::size_t, std::size_t, std::size_t);

template <typename T>
[[nodiscard]] ENCRYPTO::ReusableFiberFuture<std::vector<T>> CommMixin::register_for_ints_message(
    std::size_t party_id, std::size_t gate_id, std::size_t num_elements, std::size_t msg_num) {
  // assert(party_id != my_id_); //suvi
  auto& mh = *message_handler_;
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> promise;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> future = promise.get_future();
  auto type = GateMessageHandler::get_msg_value_type<T>();
  auto [_, success] = mh.expected_messages_.insert(
      {std::make_pair(gate_id, msg_num), std::make_pair(num_elements, type)});
  if (!success) {
    throw std::logic_error(
        fmt::format("tried to register twice for message {} for gate {}", msg_num, gate_id));
  }
  {
    std::cout << " REGISTER GATEID " << gate_id << " MSGNUM " << msg_num << "PARTYID " << party_id << std::endl;
    auto& promise_map = mh.get_promise_map<T>().at(party_id);
    auto [_, success] = promise_map.insert({std::make_pair(gate_id, msg_num), std::move(promise)});
    assert(success);
  } // ALANNN
  if constexpr (MOTION_VERBOSE_DEBUG) {
    if (logger_) {
      logger_->LogTrace(fmt::format("Gate {}: registered for int message {} of size {}", gate_id,
                                    msg_num, num_elements));
    }
  }
  return future;
}

template ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>
    CommMixin::register_for_ints_message(std::size_t, std::size_t, std::size_t, std::size_t);
template ENCRYPTO::ReusableFiberFuture<std::vector<std::uint16_t>>
    CommMixin::register_for_ints_message(std::size_t, std::size_t, std::size_t, std::size_t);
template ENCRYPTO::ReusableFiberFuture<std::vector<std::uint32_t>>
    CommMixin::register_for_ints_message(std::size_t, std::size_t, std::size_t, std::size_t);
template ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>>
    CommMixin::register_for_ints_message(std::size_t, std::size_t, std::size_t, std::size_t);
/*
template <typename T>
void CommMixin::joint_send_ints_message(std:: size_t party_i, std::size_t party_j, std::size_t party_k, std::size_t gate_id, const std::vector<T>& message, std::size_t num_elements, std::size_t msg_num)
{
    ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
    if(my_id_ == party_i){

      communication_layer_.send_message(party_k, build_gate_message(gate_id, msg_num, message));
    }
    else if(my_id_ ==party_j){

    }else if(my_id_ == party_k){

        share_future_ = register_for_ints_message<T>(party_i, gate_id, num_elements);
        std::cout<<"inside Joint_send_ints_message data type of share future = " << typeid(share_future_).name() << std::endl;
    }
}


template void
    CommMixin::joint_send_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint8_t>&, std::size_t, std::size_t);
template void
    CommMixin::joint_send_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint16_t>&, std::size_t, std::size_t);
template void
    CommMixin::joint_send_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint32_t>&, std::size_t, std::size_t);
template void
    CommMixin::joint_send_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint64_t>&, std::size_t, std::size_t);




template <typename T>
void CommMixin::joint_verify_ints_message(std:: size_t party_i, std::size_t party_j, std::size_t party_k, std::size_t gate_id, const std::vector<T>& hashed_value, std::size_t num_elements, std::size_t msg_num)
{
    std::vector<T> b;
    ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
    ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_verify;

    if(my_id_ == party_i)
    {

    }else if(my_id_ == party_j){

        communication_layer_.send_message(party_k, build_gate_message(gate_id, msg_num, hashed_value));

    }else if(my_id_ == party_k ){

        share_future_verify = register_for_ints_message<T>(party_j, gate_id, num_elements);
        std::vector<T> message;
        message[0]= share_future_.get()[0];
        //to do -- VERIFY  share_future_  with  share_future_verify
        std::cout<<"data type of message[0]" << typeid(message[0]).name() <<std::endl;
        // std::cout<<"data type of hashed_value" << typeid(hashed_value).name() <<std::endl;

        // bool is_equal = false;
        // if ( message[0].size() < hashed_value.size() ) {
        //     is_equal = std::equal ( message[0].begin(), message[0].end(), hashed_value.begin() );
        // }else{
        //     is_equal = std::equal ( hashed_value.begin(), hashed_value.end(), message[0].begin() );
        // }
        // if(is_equal == true)
        // {
        //     std::cout<<"\n \n The message is verified \n \n "<<std::endl;
        // }

    }

}

template void
    CommMixin::joint_verify_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint8_t>&, std::size_t, std::size_t);
template void
    CommMixin::joint_verify_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint16_t>&, std::size_t, std::size_t);
template void
    CommMixin::joint_verify_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint32_t>&, std::size_t, std::size_t);
template void
    CommMixin::joint_verify_ints_message(std::size_t, std::size_t, std::size_t, std::size_t, const std::vector<uint64_t>&, std::size_t, std::size_t);
*/
std::string _sha256(std::string st)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, st.c_str(), st.size());
  SHA256_Final(hash, &sha256);
  std::stringstream ss;
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }
  return ss.str();
}

// const std::vector<T>& message

template <typename T>
void CommMixin::joint_send_verify_ints_message (std:: size_t party_i, std::size_t party_j, std::size_t party_k, std::size_t gate_id, const std::vector<T>& message, std::size_t num_elements, std::size_t msg_num)
{
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_8;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_verify_8;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_16;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_verify_16;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_32;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_verify_32;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_64;
  // ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_verify_64;

  // share_future_8 = new ENCRYPTO::ReusableFiberFuture<std::vector<T>>;
  // share_future_verify_8 = new ENCRYPTO::ReusableFiberFuture<std::vector<T>>

  // share_future_8 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>;
  // share_future_verify_8 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>;
  // share_future_16 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint16_t>>;
  // share_future_verify_16 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint16_t>>;
  // share_future_32 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint32_t>>;
  // share_future_verify_32 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint32_t>>;
  share_future_64 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>>;
  share_future_verify_64 = new ENCRYPTO::ReusableFiberFuture<std::vector<std::uint64_t>>;


  std::cout<<"inside the joint_send_verify_ints_message" <<std::endl;
  // gate_id_ = gate_id;
  std::cout<<"inside the joint_send_verify_ints_message party 0" << " received gate id= "<< gate_id << "\t "<<std::endl;

    if (my_id_ == party_i) {
      communication_layer_.send_message(party_k, build_gate_message(0 , 1, message));
      //for party 0, the gate_id was coming to be something as absurd as 1784944556768769879. WTF !! Was coming correct for other parties. Hence hardcoded it
      std::cout<<"inside the joint_send_verify_ints_message party 0" << "gate id= "<< gate_id << "\t "<<std::endl;

      for(int i = 0; i < message.size(); i++) {
        std::cout <<" common message sent joint_send_verify_ints_message :: my_id= "<< my_id_ << "  common message sent == "<< message[i]<<" " <<std::endl;
      }

    } else if (my_id_ == party_j) {

      joint_message_verify_64_1 = new std::vector<std::uint64_t>;





      *joint_message_verify_64_1->insert(joint_message_verify_64_1->begin(), message.begin(), message.end());

      std::stringstream shash;
      std::copy(message.begin(), message.end(), std::ostream_iterator<int>(shash, " "));
      std::string s = _sha256(shash.str());
      std::vector<T> hashed_value(s.begin(), s.end());
      std::cout<<"inside the joint_send_verify_ints_message party " << "gate id= "<< gate_id <<std::endl;

      for(int i = 0; i < hashed_value.size(); i++) {
        std::cout <<" message sending joint_send_verify_ints_message :: my_id= "<< my_id_ << "  HASH of common value sent == "<< hashed_value[i]<<" " <<std::endl;
      }

      communication_layer_.send_message(party_k, build_gate_message(gate_id,2, hashed_value));
      std::cout<<"inside the joint_send_verify_ints_message party 1" << "gate id= "<< gate_id <<std::endl;
    } else if (my_id_ == party_k) {

      joint_message_verify_64_2 = new std::vector<std::uint64_t>;

      if (std::is_same<T, std::uint64_t>::value) {  //P2 now goes inside
        // *share_future_8(std::move(register_for_ints_message<T>(party_i, gate_id, num_elements)));
        // *share_future_verify_8(std::move(register_for_ints_message<T>(party_j, gate_id, num_elements)));
        std::cout<< "inside the joint_send_verify_ints_message *share_future_64" << typeid(*share_future_64).name()<< std::endl;

        // *share_future_64 = register_for_ints_message<T>(party_i, gate_id, num_elements);
        // *share_future_verify_64 = register_for_ints_message<T>(party_j, gate_id, num_elements);
        //std::vector<std::uint64_t>
        *share_future_64 = register_for_ints_message<std::uint64_t>(party_i, gate_id, num_elements,1);
        std::cout<<" joint_send_verify_ints_message " << "gate id-1 = "<<(gate_id) << std::endl;
        *share_future_verify_64 = register_for_ints_message<std::uint64_t>(party_j, gate_id, num_elements,2);
        std::cout<<" joint_send_verify_ints_message " << "gate id-1 = "<<(gate_id) << std::endl;

        std::vector<T> *msg;
        // auto temp;
        // *msg[0]= share_future_64->get()[0];
        std::cout<<"joint_send_verify_ints_message: just before get() " <<std::endl;
        std::cout<<" joint_send_verify_ints_message " << "gate id-1 = "<<(gate_id) << std::endl;

        auto temp = share_future_64->get();


        std::cout<<"joint_send_verify_ints_message: data type of temp = "<< typeid(temp).name() <<std::endl;
        for(int i = 0; i < temp.size(); i++) {
          std::cout <<" message received joint_send_verify_ints_message :: my_id= "<< my_id_ << "  common value received == "<< temp[i]<<" " <<std::endl;
        }

        // *joint_message_verify_64_2->push_back(temp);
        *joint_message_verify_64_2->insert(joint_message_verify_64_2->begin(), temp.begin(), temp.end());

        //COMMON VALUE is SENT And RECEIVED
        //to do -- VERIFY  share_future_  with  share_future_verify
        //hash
        //do hash of the message and computation cost would be accounted for.
        //Do not need to do equality check
        std::stringstream shash;
        // std::copy((*msg[0]).begin(), (*msg[0]).end(), std::ostream_iterator<int>(shash, " "));
        std::copy(temp.begin(), temp.end(), std::ostream_iterator<int>(shash, " "));
        std::string s = _sha256(shash.str());
        std::vector<T> hashed_value2(s.begin(), s.end());
        for(int i = 0; i < hashed_value2.size(); i++) {
          std::cout <<" message received joint_send_verify_ints_message :: my_id= "<< my_id_ << "  HASH of common value received == "<< hashed_value2[i]<<" " <<std::endl;
        }



      }
      // else if(std::is_same<T, std::uint16_t>::value){
      //   *share_future_16 = register_for_ints_message<T>(party_ijk[0], gate_id, num_elements) ;
      //   *share_future_verify_16 = register_for_ints_message<T>(party_ijk[1], gate_id, num_elements);
      //   std::vector<T> msg;
      //   msg[0]= share_future_16->get()[0];
      //   //to do -- VERIFY  share_future_  with  share_future_verify
      // }
      // else if(std::is_same<T, std::uint32_t>::value){
      //   *share_future_32 = register_for_ints_message<T>(party_ijk[0], gate_id, num_elements);
      //   *share_future_verify_32 = register_for_ints_message<T>(party_ijk[1], gate_id, num_elements);
      //   std::vector<T> msg;
      //   msg[0]= share_future_32->get()[0];
      //   //to do -- VERIFY  share_future_  with  share_future_verify
      // }else if(std::is_same<T, std::uint64_t>::value){
      //   *share_future_64 = register_for_ints_message<T>(party_ijk[0], gate_id, num_elements);
      //   *share_future_verify_64 = register_for_ints_message<T>(party_ijk[1], gate_id, num_elements);
      //   std::vector<T> msg;
      //   msg[0]= share_future_64->get()[0];
      //   //to do -- VERIFY  share_future_  with  share_future_verify
      // }

    }
}

template void CommMixin::joint_send_verify_ints_message(std:: size_t , std::size_t , std::size_t, std::size_t, const std::vector<uint8_t>&, std::size_t, std::size_t);
template void CommMixin::joint_send_verify_ints_message(std:: size_t , std::size_t , std::size_t, std::size_t, const std::vector<std::uint16_t>&, std::size_t, std::size_t);
template void CommMixin::joint_send_verify_ints_message(std:: size_t , std::size_t , std::size_t, std::size_t, const std::vector<std::uint32_t>&, std::size_t, std::size_t);
template void CommMixin::joint_send_verify_ints_message(std:: size_t , std::size_t , std::size_t  , std::size_t, const std::vector<std::uint64_t>&, std::size_t, std::size_t);


/*
 * share_1 = u_i for Party 0, v_i for Party 1
 * share_0 = u_i-1 for Party 0, v_i-1 for Party 1
 * both args are dummy for Party 2.
 */
// using namespace std;
// using namespace NTL;

template <typename T>
void CommMixin::DIZK(std::vector<T> share_1, std::vector<T> share_0)
{
  if (my_id_ == 2) {
    // receive all shares into u1, u0, v1, v0
    // f = init_field(BIG_MODULUS)
    // pu1, pu0, pv1, pv2 = init_poly(f, u1) ...

    // bigint bg;

  // ZZ_p::init((const ZZ) 2);

	// ZZ_pX f;
	// SetCoeff(f, 2, 1);
	// SetCoeff(f, 3, 1);
  //
	// ZZ_pX g;
	// SetCoeff(g, 4, 1);
  //
	// cout<<f<<endl;
	// cout<<g<<endl;
  //
  //
	// ZZ_pE::init((const ZZ_pX) f);
	// ZZ_pE h;
  //
	// conv(h, g);

	// cout<<h<<endl;


  }
}
template void CommMixin::DIZK(std::vector<uint8_t> share_1, std::vector<uint8_t> share_0);
template void CommMixin::DIZK(std::vector<uint16_t> share_1, std::vector<uint16_t> share_0);
template void CommMixin::DIZK(std::vector<uint32_t> share_1, std::vector<uint32_t> share_0);
template void CommMixin::DIZK(std::vector<uint64_t> share_1, std::vector<uint64_t> share_0);



}  // namespace MOTION::proto
