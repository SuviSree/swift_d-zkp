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

#include "motion_base_provider.h"

#include "communication/communication_layer.h"
#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/suvi_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/hello_message.h"
#include "communication/message_handler.h"
#include "output_message_handler.h"
#include "sharing_randomness_generator.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"
#include "utility/reusable_future.h"

namespace MOTION::Crypto {

// Handler for messages of type HelloMessage
struct HelloMessageHandler : public Communication::MessageHandler {
  // Create a handler object for a given party
  HelloMessageHandler(std::size_t num_parties, std::shared_ptr<Logger> logger, std::size_t my_id)
    : logger_(logger),
      my_id_(my_id),
      fixed_key_aes_seed_promises_(num_parties),
      randomness_sharing_seed_promises_(num_parties) {
  std::transform(std::begin(fixed_key_aes_seed_promises_), std::end(fixed_key_aes_seed_promises_),
                 std::back_inserter(fixed_key_aes_seed_futures_),
                 [](auto& p) { return p.get_future(); });
  std::transform(std::begin(randomness_sharing_seed_promises_),
                 std::end(randomness_sharing_seed_promises_),
                 std::back_inserter(randomness_sharing_seed_futures_),
                 [](auto& p) { return p.get_future(); });
}

  // Method which is called on received messages.
  void received_message(std::size_t party_id, std::vector<std::uint8_t>&& message) override;

  ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>> get_randomness_sharing_seed_future();

  std::size_t my_id_;
  std::shared_ptr<Logger> logger_;

  std::vector<ENCRYPTO::ReusablePromise<std::vector<std::uint8_t>>> fixed_key_aes_seed_promises_;
  std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>> fixed_key_aes_seed_futures_;

  std::vector<ENCRYPTO::ReusablePromise<std::vector<std::uint8_t>>>
      randomness_sharing_seed_promises_;  //added //made it a vector of vector
  std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>>  randomness_sharing_seed_futures_; //added //made it a vector of vector
};

// Handler for messages of type HelloMessage
struct SUVIMessageHandler : public Communication::MessageHandler {
  // Create a handler object for a given party
  SUVIMessageHandler(std::size_t num_parties, std::shared_ptr<Logger> logger, std::size_t my_id)
    : logger_(logger),
      my_id_(my_id),
      fixed_key_aes_seed_promises_(num_parties),
      randomness_sharing_seed_promises_(num_parties) {
  std::transform(std::begin(fixed_key_aes_seed_promises_), std::end(fixed_key_aes_seed_promises_),
                 std::back_inserter(fixed_key_aes_seed_futures_),
                 [](auto& p) { return p.get_future(); });
  std::transform(std::begin(randomness_sharing_seed_promises_),
                 std::end(randomness_sharing_seed_promises_),
                 std::back_inserter(randomness_sharing_seed_futures_),
                 [](auto& p) { return p.get_future(); });
}

  // Method which is called on received messages.
  void received_message(std::size_t party_id, std::vector<std::uint8_t>&& message) override;

  ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>> get_randomness_sharing_seed_future();

  std::size_t my_id_;
  std::shared_ptr<Logger> logger_;

  std::vector<ENCRYPTO::ReusablePromise<std::vector<std::uint8_t>>> fixed_key_aes_seed_promises_;
  std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>> fixed_key_aes_seed_futures_;

  std::vector<ENCRYPTO::ReusablePromise<std::vector<std::uint8_t>>>
      randomness_sharing_seed_promises_;  //added //made it a vector of vector
  std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>>  randomness_sharing_seed_futures_; //added //made it a vector of vector
};

void HelloMessageHandler::received_message(std::size_t party_id,
                                           std::vector<std::uint8_t>&& hello_message) {
  assert(!hello_message.empty());
  auto message = Communication::GetMessage(reinterpret_cast<std::uint8_t*>(hello_message.data()));
  auto hello_message_ptr = Communication::GetHelloMessage(message->payload()->data());

  auto* fb_vec = hello_message_ptr->input_sharing_seed(); //fb_vec will have the aes key final

    std::cout << "RECEIVED MESSAGE FIRST " << party_id << std::endl;
    randomness_sharing_seed_promises_.at(party_id).set_value(  //setting the received value at the desired pos of my
      std::vector(std::begin(*fb_vec), std::end(*fb_vec))); //
    std::cout << "RECEIVED MESSAGE FIRST POST " << party_id << std::endl;

    fb_vec = hello_message_ptr->fixed_key_aes_seed(); //received the fixed key aes key from hello_message_ptr
    fixed_key_aes_seed_promises_.at(party_id).set_value(        //setting the fixed key aes key at the my vector of that party
        std::vector(std::begin(*fb_vec), std::end(*fb_vec)));
}

void SUVIMessageHandler::received_message(std::size_t party_id,
                                           std::vector<std::uint8_t>&& hello_message) {
  assert(!hello_message.empty());
  auto message = Communication::GetMessage(reinterpret_cast<std::uint8_t*>(hello_message.data()));
  auto hello_message_ptr = Communication::GetSUVIMessage(message->payload()->data());

  auto* fb_vec = hello_message_ptr->input_sharing_seed(); //fb_vec will have the aes key final

std::cout << "RECEIVED MESSAGE FIRST SUVI " << party_id << std::endl;
randomness_sharing_seed_promises_.at(party_id).set_value(  //setting the received value at the desired pos of my
  std::vector(std::begin(*fb_vec), std::end(*fb_vec))); //
std::cout << "RECEIVED MESSAGE FIRST POST SUVI " << party_id << std::endl;

fb_vec = hello_message_ptr->fixed_key_aes_seed(); //received the fixed key aes key from hello_message_ptr
fixed_key_aes_seed_promises_.at(party_id).set_value(        //setting the fixed key aes key at the my vector of that party
    std::vector(std::begin(*fb_vec), std::end(*fb_vec)));
std::cout << "RECEIVED MESSAGE AES KEY FIRST POST SUVI " << party_id << std::endl;
}


MotionBaseProvider::MotionBaseProvider(Communication::CommunicationLayer& communication_layer,
                                       std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      logger_(std::move(logger)),
      num_parties_(communication_layer_.get_num_parties()),
      my_id_(communication_layer_.get_my_id()),
      my_randomness_generators_(num_parties_),
      their_randomness_generators_(num_parties_),
      our_randomness_generators_(num_parties_), //suvi
      hello_message_handler_(std::make_shared<HelloMessageHandler>(num_parties_, logger_, my_id_)),
      suvi_message_handler_(std::make_shared<SUVIMessageHandler>(num_parties_, logger_, my_id_)),
      output_message_handlers_(num_parties_) {
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    output_message_handlers_.at(party_id) =
        std::make_shared<OutputMessageHandler>(party_id, nullptr);
  }
  // register handler
  communication_layer_.register_message_handler([this](auto) { return hello_message_handler_; },
                                                {Communication::MessageType::HelloMessage});

  communication_layer_.register_message_handler([this](auto) { return suvi_message_handler_; },
                                                {Communication::MessageType::SUVIMessage});

  communication_layer_.register_message_handler(
      [this](std::size_t party_id) { return output_message_handlers_.at(party_id); },
      {Communication::MessageType::OutputMessage});
}

MotionBaseProvider::~MotionBaseProvider() {
  communication_layer_.deregister_message_handler(
      {Communication::MessageType::HelloMessage, Communication::MessageType::OutputMessage, Communication::MessageType::SUVIMessage});
}

void MotionBaseProvider::setup(int i) {
  if (i == 0) {
    bool setup_started = execute_setup_flag_.test_and_set();
    if (setup_started) {
      if constexpr (MOTION_DEBUG) {
        if (logger_) {
          logger_->LogDebug("MotionBaseProvider::setup: waiting for setup being completed");
        }
      }
      wait_setup();
      return;
    }
    if constexpr (MOTION_DEBUG) {
      if (logger_) {
        logger_->LogDebug("MotionBaseProvider::setup: running setup");
      }
    }
  }

  // generate share, broadcast, wait for messages, xor
  aes_fixed_key_ = Helpers::RandomVector<std::uint8_t>(16);
  std::vector<std::vector<std::uint8_t>> my_seeds;
  std::generate_n(std::back_inserter(my_seeds), num_parties_,
                  [] { return Helpers::RandomVector<std::uint8_t>(32); });

  // prepare and send HelloMessage
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      //send the 0my0 and 1my1 to 1ou0 and 2our0 respectively
      auto msg_builder = Communication::BuildSUVIMessage(
          my_id_, party_id, num_parties_, &my_seeds.at(party_id), &aes_fixed_key_,
          /* TODO: config_->GetOnlineAfterSetup()*/ true, MOTION_VERSION);
      communication_layer_.broadcast_message(std::move(msg_builder));
      std::cout << "JUST SENT SUVI " << party_id << std::endl;
      continue;
    }
    auto msg_builder = Communication::BuildHelloMessage(
        my_id_, party_id, num_parties_, &my_seeds.at(party_id), &aes_fixed_key_,
        /* TODO: config_->GetOnlineAfterSetup()*/ true, MOTION_VERSION);
    communication_layer_.send_message(party_id, std::move(msg_builder));
    std::cout << "JUST SENT HELLO " << party_id << std::endl;

  } //communicate the fixed key that you created

  // initialize my randomness generators
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    their_randomness_generators_.at(party_id) =
        std::make_unique<SharingRandomnessGenerator>(party_id);
    our_randomness_generators_.at(party_id) =
        std::make_unique<SharingRandomnessGenerator>(party_id);

    // if (party_id == my_id_) { // now we are using 0my0, 1my1, so party_id=my_id wala check cannot stay
    //   continue;
    // } // P1 er my er 1 will be uninitialised  //P0 er 0 will be uninitialised // but p2 er 2 is initialised
    //p2 er my er 2 will be initialised using the seed that we broadcasted
    // /*
    // if (my_id_ != 2) {
    my_randomness_generators_.at(party_id) = std::make_unique<SharingRandomnessGenerator>(party_id);
    std::cout << "\t size of my seed \t " << sizeof(my_seeds.at(party_id).data()) << "\t Party id= \t" << party_id << "\t my_id_ = \t"<< my_id_<< std::endl;
    std::cout << "INIT 1" << std::endl;


    my_randomness_generators_.at(party_id)->Initialize(
        reinterpret_cast<const std::byte*>(my_seeds.at(party_id).data()));

  }

  // receive HelloMessages from other and initialize
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {

      if (my_id_ == party_id)
        continue;

        //initialise 1their0 with 0my1, initialise 0their1 with 1my0, initialise 2their0 with 0my2
        auto aes_key = hello_message_handler_->fixed_key_aes_seed_futures_.at(party_id).get(); //receive the aes key
        // add received share to the fixed aes key
        std::transform(std::begin(aes_fixed_key_), std::end(aes_fixed_key_), std::begin(aes_key),
                       std::begin(aes_fixed_key_), [](auto a, auto b) { return a ^ b; });
        auto their_seed = hello_message_handler_->randomness_sharing_seed_futures_.at(party_id).get(); //receive the common seed
        // initialize randomness generator of the other party


        their_randomness_generators_.at(party_id)->Initialize(
            reinterpret_cast<const std::byte*>(their_seed.data()));
  }

  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (my_id_ == party_id)
      continue;

    auto aes_key = suvi_message_handler_->fixed_key_aes_seed_futures_.at(party_id).get();
    std::transform(std::begin(aes_fixed_key_), std::end(aes_fixed_key_), std::begin(aes_key),
                   std::begin(aes_fixed_key_), [](auto a, auto b) { return a ^ b; });

    auto our_seed = suvi_message_handler_->randomness_sharing_seed_futures_.at(party_id).get();

    std::cout << "____________________________________________________Gonna INITIALIZE " << party_id << "\t" << sizeof(our_seed.data()) << std::endl;

    our_randomness_generators_.at(party_id)->Initialize(
      reinterpret_cast<const std::byte*>(our_seed.data()));
  }

  std::cout << "INIT 4" << std::endl;

  if (i == 0) {
    set_setup_ready();

    if constexpr (MOTION_DEBUG) {
      if (logger_) {
        logger_->LogDebug("MotionBaseProvider::setup: setup completed");
      }
    }
  }
}

std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>>
MotionBaseProvider::register_for_output_messages(std::size_t gate_id) {
  std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>> futures(num_parties_);
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    futures.at(party_id) =
        output_message_handlers_.at(party_id)->register_for_output_message(gate_id);
  }
  return futures;
}

}  // namespace MOTION::Crypto
