// MIT License
//
// Copyright (c) 2021 Lennart Braun
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

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>

#include <boost/algorithm/string.hpp>
#include <boost/json/serialize.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include "algorithm/circuit_loader.h"
#include "base/gate_factory.h"
#include "base/two_party_backend.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/logger.h"

namespace po = boost::program_options;

struct Options {
  std::size_t threads;
  bool json;
  std::size_t num_repetitions;
  std::size_t num_simd;
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::uint64_t input_value;
  std::size_t my_id;
  MOTION::Communication::tcp_parties_config tcp_config;
  bool no_run = false;
};

std::optional<Options> parse_program_options(int argc, char* argv[]) {
  Options options;
  boost::program_options::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false),"produce help message")
    ("config-file", po::value<std::string>(), "config file containing options")
    ("my-id", po::value<std::size_t>()->required(), "my party id")
    ("party", po::value<std::vector<std::string>>()->multitoken(),
     "(party id, IP, port), e.g., --party 1,127.0.0.1,7777")
    ("threads", po::value<std::size_t>()->default_value(0), "number of threads to use for gate evaluation")
    ("json", po::bool_switch()->default_value(false), "output data in JSON format")
    ("arithmetic-protocol", po::value<std::string>()->required(), "2PC protocol (GMW or BEAVY)")
    ("boolean-protocol", po::value<std::string>()->required(), "2PC protocol (Yao, GMW or BEAVY)")
    ("input-value", po::value<std::uint64_t>()->required(), "input value for Yao's Millionaires' Problem")
    ("repetitions", po::value<std::size_t>()->default_value(1), "number of repetitions")
    ("num-simd", po::value<std::size_t>()->default_value(1), "number of SIMD values")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
     "run a synchronization protocol before the online phase starts")
    ("no-run", po::bool_switch()->default_value(false), "just build the circuit, but not execute it")
    ;
  // clang-format on

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  bool help = vm["help"].as<bool>();
  if (help) {
    std::cerr << desc << "\n";
    return std::nullopt;
  }
  if (vm.count("config-file")) {
    std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
    po::store(po::parse_config_file(ifs, desc), vm);
  }
  try {
    po::notify(vm);
  } catch (std::exception& e) {
    std::cerr << "error:" << e.what() << "\n\n";
    std::cerr << desc << "\n";
    return std::nullopt;
  }

  std::cout << "/* parse options */" << '\n';

  options.my_id = vm["my-id"].as<std::size_t>();
  options.threads = vm["threads"].as<std::size_t>();
  options.json = vm["json"].as<bool>();
  options.num_repetitions = vm["repetitions"].as<std::size_t>();
  options.num_simd = vm["num-simd"].as<std::size_t>();
  options.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
  options.no_run = vm["no-run"].as<bool>();
  if (options.my_id > 2) {
    std::cerr << "my-id must be one of 0, 1 and 2\n";
    return std::nullopt;
  }

  std::cout << "/* parse protocol */" << '\n';

  auto arithmetic_protocol = vm["arithmetic-protocol"].as<std::string>();
  boost::algorithm::to_lower(arithmetic_protocol);
  if (arithmetic_protocol == "gmw") {
    options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticGMW;
  } else if (arithmetic_protocol == "beavy") {
    options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticBEAVY;
  } else {
    std::cerr << "invalid protocol: " << arithmetic_protocol << "\n";
    return std::nullopt;
  }
  auto boolean_protocol = vm["boolean-protocol"].as<std::string>();
  boost::algorithm::to_lower(boolean_protocol);
  if (boolean_protocol == "yao") {
    options.boolean_protocol = MOTION::MPCProtocol::Yao;
  } else if (boolean_protocol == "gmw") {
    options.boolean_protocol = MOTION::MPCProtocol::BooleanGMW;
  } else if (boolean_protocol == "beavy") {
    options.boolean_protocol = MOTION::MPCProtocol::BooleanBEAVY;
  } else {
    std::cerr << "invalid protocol: " << boolean_protocol << "\n";
    return std::nullopt;
  }

  options.input_value = vm["input-value"].as<std::uint64_t>();

  std::cout << "/* parse partyargs */" << '\n';

  const auto parse_party_argument =
      [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([012]),([^,]+),(\\d{1,5})");
    std::smatch match;
    if (!std::regex_match(s, match, party_argument_re)) {
      throw std::invalid_argument("invalid party argument");
    }
    auto id = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]);
    return {id, {host, port}};
  };

  const std::vector<std::string> party_infos = vm["party"].as<std::vector<std::string>>();
  if (party_infos.size() != 3) {
    std::cerr << "expecting three --party options\n";
    return std::nullopt;
  }

  options.tcp_config.resize(3);
  std::size_t other_id = 2;

  const auto [id0, conn_info0] = parse_party_argument(party_infos[0]);
  const auto [id1, conn_info1] = parse_party_argument(party_infos[1]);
  const auto [id2, conn_info2] = parse_party_argument(party_infos[2]);
  if (id0 == id1 || id0 == id2 || id1 == id2) {
    std::cerr << "need party arguments for party 0, 1 and 2\n";
    return std::nullopt;
  }
  options.tcp_config[id0] = conn_info0;
  options.tcp_config[id1] = conn_info1;
  options.tcp_config[id2] = conn_info2;

  return options;
}

std::unique_ptr<MOTION::Communication::CommunicationLayer> setup_communication(
    const Options& options) {
  MOTION::Communication::TCPSetupHelper helper(options.my_id, options.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(options.my_id,
                                                                     helper.setup_connections());
}


auto create_composite_circuit(const Options& options, MOTION::TwoPartyBackend& backend) {
  // retrieve the gate factories for the chosen protocols
  auto& gate_factory_arith = backend.get_gate_factory(options.arithmetic_protocol); //gmw
  //auto& gate_factory_bool = backend.get_gate_factory(options.boolean_protocol); //beavy

  // share the inputs using the arithmetic protocol
  // NB: the inputs need to always be specified in the same order:
  // here we first specify the input of party 0, then that of party 1
  ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint64_t>> input_promise;
  ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint64_t>> nullp;
  //amar shudhu ektai input, so ektai input promise
  MOTION::WireVector input_x_arith, input_y_arith; //input_0_arith=x, input_1_arith=y
  ENCRYPTO::ReusableFiberFuture<MOTION::IntegerValues<std::uint64_t>> output_future;
  if (options.my_id == 0) { //P0
    auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1); //P0's input gate
    std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_my" <<std::endl;
    input_promise = std::move(pair.first); //wait for the actual input
    input_x_arith = std::move(pair.second); // randomness of P0
    input_y_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1 - options.my_id, 1); // share of y
    std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_other" <<std::endl;

    //auto output1 = gate_factory_arith.make_binary_gate( //ONLine Phase
    //      ENCRYPTO::PrimitiveOperationType::MUL, input_x_arith, input_y_arith); //x.y
    /*auto output = gate_factory_arith.make_binary_gate(
                      ENCRYPTO::PrimitiveOperationType::MUL, input_x_arith, input_y_arith); //x.y +y
                      std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_binary_gate" <<std::endl;

    output_future = gate_factory_arith.make_arithmetic_64_output_gate_my(MOTION::ALL_PARTIES, output); //RECONSTRUCTION
    std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_output_gate_my" <<std::endl;*/
    // return std::make_pair(std::move(input_promise), std::move(output_future));
  } else if (options.my_id == 1){ //P1
    input_x_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1-options.my_id, 1); //share of x //share of P0's input //receiver er output wire   //RECEIVERGATE
    std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_other" <<std::endl;
    auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1); //make my won gate //P1's input gate   //SENDERGATE
    std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_my" <<std::endl;

    input_promise = std::move(pair.first); //wait for my input
    input_y_arith = std::move(pair.second); //randomness of P1
    //auto output1 = gate_factory_arith.make_binary_gate( //ONLine Phase
    //      ENCRYPTO::PrimitiveOperationType::MUL, input_x_arith, input_y_arith); //x.y

   // return std::make_pair(std::move(input_promise), std::move(output_future));
  } else if (options.my_id == 2){

    std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_my" <<std::endl;
   input_x_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(0, 1);
   std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_other" <<std::endl;
    input_y_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1, 1);
     auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(2, 1);

   std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_input_gate_other" <<std::endl;


   input_promise = std::move(pair.first); //wait for my input

   //auto output = gate_factory_arith.make_binary_gate(
                     //ENCRYPTO::PrimitiveOperationType::ADD, input_x_arith, input_y_arith); //x.y +y
   /*auto output = gate_factory_arith.make_binary_gate(
        ENCRYPTO::PrimitiveOperationType::MUL, input_x_arith, input_y_arith); //x.y +y
        std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_binary_gate" <<std::endl;


   output_future = gate_factory_arith.make_arithmetic_64_output_gate_my(MOTION::ALL_PARTIES, output);
   std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_output_gate_my" <<std::endl; */

// return std::make_pair(std::move(input_promise), std::move(output_future));
  }
  auto output = gate_factory_arith.make_binary_gate(
                    ENCRYPTO::PrimitiveOperationType::MUL, input_x_arith, input_y_arith);
 std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_binary_gate" <<std::endl;

 output_future = gate_factory_arith.make_arithmetic_64_output_gate_my(MOTION::ALL_PARTIES, output); //RECONSTRUCTION //broadcast the result to everyone   //OUTPUTGATE
 std::cout<<"APP level::" << "Party id =" << options.my_id << " func = make_arithmetic_64_output_gate_my" <<std::endl;

  std::cout<<"inside mill.cpp"<<"party id="<< options.my_id << "after output gate"<<std::endl;

// return promise and future to allow setting inputs and retrieving outputs
// return std::make_pair(std::move(nullptr), std::move(nullptr));
  return std::make_pair(std::move(input_promise), std::move(output_future));
}

void run_composite_circuit(const Options& options, MOTION::TwoPartyBackend& backend) {
  // build the circuit and gets promise/future for the input/output
  auto [input_promise, output_future] = create_composite_circuit(options, backend);
std::cout<<"Composite Ciruit created"<<std::endl;
  //auto [input_promise] = std::move(input_promises);

  if (options.no_run) {
    return;
  }

  // set the promise with our input value

  input_promise.set_value({options.input_value}); //1 input


  std::cout<<"up and untill backend.run()"<<std::endl; //P0 and P1 is here
  // execute the protocol
  backend.run();
  std::cout << "reached end of backend.run() for party id " << options.my_id <<std::endl;
  // retrieve the result from the future
  auto comp_result=0;
  if (options.my_id !=2)
  {
    auto bvs = output_future.get();
    comp_result = bvs.at(0);
  }
  else if (options.my_id ==2){
      comp_result=0;
  }
  if (!options.json) {
     std::cout << "The composite result is:- " << comp_result << std::endl;
  }
}


void print_stats(const Options& options,
                 const MOTION::Statistics::AccumulatedRunTimeStats& run_time_stats,
                 const MOTION::Statistics::AccumulatedCommunicationStats& comm_stats) {
  if (options.json) {
    auto obj = MOTION::Statistics::to_json("millionaires_problem", run_time_stats, comm_stats);
    obj.emplace("party_id", options.my_id);
    obj.emplace("arithmetic_protocol", MOTION::ToString(options.arithmetic_protocol));
    obj.emplace("boolean_protocol", MOTION::ToString(options.boolean_protocol));
    obj.emplace("simd", options.num_simd);
    obj.emplace("threads", options.threads);
    obj.emplace("sync_between_setup_and_online", options.sync_between_setup_and_online);
    std::cout << obj << "\n";
  } else {
    std::cout << MOTION::Statistics::print_stats("millionaires_problem", run_time_stats,
                                                 comm_stats);
  }
}

int main(int argc, char* argv[]) {
  int x = 0;
  std::cout << "/* SUVI parse? */" << '\n';
  auto options = parse_program_options(argc, argv);
  if (!options.has_value()) {
    return EXIT_FAILURE;
  }
  std::cout << "/* SUVI just woke up */" << '\n';
  try {
    auto comm_layer = setup_communication(*options);
    std::cout << "/* SUVI set up comms */" << '\n';
    auto logger = std::make_shared<MOTION::Logger>(options->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);
    std::cout << "/* SUVI set logger */" << '\n';
    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
    std::cout << "/* SUVI in main */" << '\n';
    for (std::size_t i = 0; i < options->num_repetitions; ++i) {
      MOTION::TwoPartyBackend backend(*comm_layer, options->threads,
                                    options->sync_between_setup_and_online, logger);
      std::cout << "/* SUVI in main after TwoPartyBackend */" << '\n';

      // std::cin >> x;
      //run_circuit(*options, backend);
      //if (options->my_id == 0 || options->my_id == 1)
       run_composite_circuit(*options, backend);
       std::cout<<"run_composite circuit is finished"<<std::endl;
      comm_layer->sync();
      comm_stats.add(comm_layer->get_transport_statistics());
      comm_layer->reset_transport_statistics();
      run_time_stats.add(backend.get_run_time_stats());
    }
    comm_layer->shutdown();
    print_stats(*options, run_time_stats, comm_stats);
  } catch (std::runtime_error& e) {
    std::cerr << "ERROR OCCURRED: " << e.what() << "\n";
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}


// // MIT License
// //
// // Copyright (c) 2021 Lennart Braun
// //
// // Permission is hereby granted, free of charge, to any person obtaining a copy
// // of this software and associated documentation files (the "Software"), to deal
// // in the Software without restriction, including without limitation the rights
// // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// // copies of the Software, and to permit persons to whom the Software is
// // furnished to do so, subject to the following conditions:
// //
// // The above copyright notice and this permission notice shall be included in all
// // copies or substantial portions of the Software.
// //
// // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// // SOFTWARE.
//
// #include <algorithm>
// #include <cmath>
// #include <filesystem>
// #include <fstream>
// #include <iostream>
// #include <random>
// #include <regex>
// #include <stdexcept>
//
// #include <boost/algorithm/string.hpp>
// #include <boost/json/serialize.hpp>
// #include <boost/lexical_cast.hpp>
// #include <boost/log/trivial.hpp>
// #include <boost/program_options.hpp>
//
// #include "algorithm/circuit_loader.h"
// #include "base/gate_factory.h"
// #include "base/two_party_backend.h"
// #include "communication/communication_layer.h"
// #include "communication/tcp_transport.h"
// #include "statistics/analysis.h"
// #include "utility/logger.h"
//
// namespace po = boost::program_options;
//
// struct Options {
//   std::size_t threads;
//   bool json;
//   std::size_t num_repetitions;
//   std::size_t num_simd;
//   bool sync_between_setup_and_online;
//   MOTION::MPCProtocol arithmetic_protocol;
//   MOTION::MPCProtocol boolean_protocol;
//   std::uint64_t input_value;
//   std::size_t my_id;
//   MOTION::Communication::tcp_parties_config tcp_config;
//   bool no_run = false;
// };
//
// std::optional<Options> parse_program_options(int argc, char* argv[]) {
//   Options options;
//   boost::program_options::options_description desc("Allowed options");
//   // clang-format off
//   desc.add_options()
//     ("help,h", po::bool_switch()->default_value(false),"produce help message")
//     ("config-file", po::value<std::string>(), "config file containing options")
//     ("my-id", po::value<std::size_t>()->required(), "my party id")
//     ("party", po::value<std::vector<std::string>>()->multitoken(),
//      "(party id, IP, port), e.g., --party 1,127.0.0.1,7777")
//     ("threads", po::value<std::size_t>()->default_value(0), "number of threads to use for gate evaluation")
//     ("json", po::bool_switch()->default_value(false), "output data in JSON format")
//     ("arithmetic-protocol", po::value<std::string>()->required(), "2PC protocol (GMW or BEAVY)")
//     ("boolean-protocol", po::value<std::string>()->required(), "2PC protocol (Yao, GMW or BEAVY)")
//     ("input-value", po::value<std::uint64_t>()->required(), "input value for Yao's Millionaires' Problem")
//     ("repetitions", po::value<std::size_t>()->default_value(1), "number of repetitions")
//     ("num-simd", po::value<std::size_t>()->default_value(1), "number of SIMD values")
//     ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
//      "run a synchronization protocol before the online phase starts")
//     ("no-run", po::bool_switch()->default_value(false), "just build the circuit, but not execute it")
//     ;
//   // clang-format on
//
//   po::variables_map vm;
//   po::store(po::parse_command_line(argc, argv, desc), vm);
//   bool help = vm["help"].as<bool>();
//   if (help) {
//     std::cerr << desc << "\n";
//     return std::nullopt;
//   }
//   if (vm.count("config-file")) {
//     std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
//     po::store(po::parse_config_file(ifs, desc), vm);
//   }
//   try {
//     po::notify(vm);
//   } catch (std::exception& e) {
//     std::cerr << "error:" << e.what() << "\n\n";
//     std::cerr << desc << "\n";
//     return std::nullopt;
//   }
//
//   std::cout << "/* parse options */" << '\n';
//
//   options.my_id = vm["my-id"].as<std::size_t>();
//   options.threads = vm["threads"].as<std::size_t>();
//   options.json = vm["json"].as<bool>();
//   options.num_repetitions = vm["repetitions"].as<std::size_t>();
//   options.num_simd = vm["num-simd"].as<std::size_t>();
//   options.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
//   options.no_run = vm["no-run"].as<bool>();
//   if (options.my_id > 2) {
//     std::cerr << "my-id must be one of 0, 1 and 2\n";
//     return std::nullopt;
//   }
//
//   std::cout << "/* parse protocol */" << '\n';
//
//   auto arithmetic_protocol = vm["arithmetic-protocol"].as<std::string>();
//   boost::algorithm::to_lower(arithmetic_protocol);
//   if (arithmetic_protocol == "gmw") {
//     options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticGMW;
//   } else if (arithmetic_protocol == "beavy") {
//     options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticBEAVY;
//   } else {
//     std::cerr << "invalid protocol: " << arithmetic_protocol << "\n";
//     return std::nullopt;
//   }
//   auto boolean_protocol = vm["boolean-protocol"].as<std::string>();
//   boost::algorithm::to_lower(boolean_protocol);
//   if (boolean_protocol == "yao") {
//     options.boolean_protocol = MOTION::MPCProtocol::Yao;
//   } else if (boolean_protocol == "gmw") {
//     options.boolean_protocol = MOTION::MPCProtocol::BooleanGMW;
//   } else if (boolean_protocol == "beavy") {
//     options.boolean_protocol = MOTION::MPCProtocol::BooleanBEAVY;
//   } else {
//     std::cerr << "invalid protocol: " << boolean_protocol << "\n";
//     return std::nullopt;
//   }
//
//   options.input_value = vm["input-value"].as<std::uint64_t>();
//
//   std::cout << "/* parse partyargs */" << '\n';
//
//   const auto parse_party_argument =
//       [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
//     const static std::regex party_argument_re("([012]),([^,]+),(\\d{1,5})");
//     std::smatch match;
//     if (!std::regex_match(s, match, party_argument_re)) {
//       throw std::invalid_argument("invalid party argument");
//     }
//     auto id = boost::lexical_cast<std::size_t>(match[1]);
//     auto host = match[2];
//     auto port = boost::lexical_cast<std::uint16_t>(match[3]);
//     return {id, {host, port}};
//   };
//
//   const std::vector<std::string> party_infos = vm["party"].as<std::vector<std::string>>();
//   if (party_infos.size() != 3) {
//     std::cerr << "expecting three --party options\n";
//     return std::nullopt;
//   }
//
//   options.tcp_config.resize(3);
//   std::size_t other_id = 2;
//
//   const auto [id0, conn_info0] = parse_party_argument(party_infos[0]);
//   const auto [id1, conn_info1] = parse_party_argument(party_infos[1]);
//   const auto [id2, conn_info2] = parse_party_argument(party_infos[2]);
//   if (id0 == id1 || id0 == id2 || id1 == id2) {
//     std::cerr << "need party arguments for party 0, 1 and 2\n";
//     return std::nullopt;
//   }
//   options.tcp_config[id0] = conn_info0;
//   options.tcp_config[id1] = conn_info1;
//   options.tcp_config[id2] = conn_info2;
//
//   return options;
// }
//
// std::unique_ptr<MOTION::Communication::CommunicationLayer> setup_communication(
//     const Options& options) {
//   MOTION::Communication::TCPSetupHelper helper(options.my_id, options.tcp_config);
//   return std::make_unique<MOTION::Communication::CommunicationLayer>(options.my_id,
//                                                                      helper.setup_connections());
// }
//
// void print_stats(const Options& options,
//                  const MOTION::Statistics::AccumulatedRunTimeStats& run_time_stats,
//                  const MOTION::Statistics::AccumulatedCommunicationStats& comm_stats) {
//   if (options.json) {
//     auto obj = MOTION::Statistics::to_json("millionaires_problem", run_time_stats, comm_stats);
//     obj.emplace("party_id", options.my_id);
//     obj.emplace("arithmetic_protocol", MOTION::ToString(options.arithmetic_protocol));
//     obj.emplace("boolean_protocol", MOTION::ToString(options.boolean_protocol));
//     obj.emplace("simd", options.num_simd);
//     obj.emplace("threads", options.threads);
//     obj.emplace("sync_between_setup_and_online", options.sync_between_setup_and_online);
//     std::cout << obj << "\n";
//   } else {
//     std::cout << MOTION::Statistics::print_stats("millionaires_problem", run_time_stats,
//                                                  comm_stats);
//   }
// }
//
// auto create_mult_circuit(const Options& options, MOTION::TwoPartyBackend& backend) {
//   // retrieve the gate factories for the chosen protocols
//   auto& gate_factory_arith = backend.get_gate_factory(options.arithmetic_protocol);//gmw
//   auto& gate_factory_bool = backend.get_gate_factory(options.boolean_protocol);// beavy
//
//   // share the inputs using the arithmetic protocol
//   // NB: the inputs need to always be specified in the same order:
//   // here we first specify the input of party 0, then that of party 1
//   ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint64_t>> input_promise;
//   MOTION::WireVector input_0_arith, input_1_arith;
//   if (options.my_id == 0) {
//     auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1);
//     input_promise = std::move(pair.first);
//     input_0_arith = std::move(pair.second);
//     input_1_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1 - options.my_id, 1);
//   } else {
//     input_0_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1 - options.my_id, 1);
//     auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1);
//     input_promise = std::move(pair.first);
//     input_1_arith = std::move(pair.second);
//   }
//
//   // convert the arithmetic shares into Boolean shares
//   auto input_0_bool = backend.convert(options.boolean_protocol, input_0_arith);
//   auto input_1_bool = backend.convert(options.boolean_protocol, input_1_arith);
//
//   // load a boolean circuit for to compute 'greater-than'
//   MOTION::CircuitLoader circuit_loader;
//
//
//   auto& gt_circuit =
//       circuit_loader.load_circuit(fmt::format("int_mul{}_{}.bristol", 64, "depth"),
//                    MOTION::CircuitFormat::Bristol);
//   // apply the circuit to the Boolean sahres
//   auto output = backend.make_circuit(gt_circuit, input_0_bool, input_1_bool);
//
//   // create an output gates of the result
//   auto output_future = gate_factory_bool.make_boolean_output_gate_my(MOTION::ALL_PARTIES, output);
//
//   // return promise and future to allow setting inputs and retrieving outputs
//   return std::make_pair(std::move(input_promise), std::move(output_future));
// }
//
// void run_mult_circuit(const Options& options, MOTION::TwoPartyBackend& backend){
//   // build the circuit and gets promise/future for the input/output
//   auto [input_promise, output_future] = create_mult_circuit(options, backend);
//
//   if (options.no_run) {
//     return;
//   }
//
//   // set the promise with our input value
//   input_promise.set_value({options.input_value});
//
//   // execute the protocol
//   backend.run();
//
//   // retrieve the result from the future
//   auto bvs = output_future.get();
//   auto mult_result = 0;
//
//   // Conversion of result to readable arithmetic format
//   for(int i=63;i>=0;i--)
//   {
//     mult_result = mult_result + bvs.at(i).Get(0);
//     // left shift is easier to implement
//     mult_result = mult_result << 1;
//   }
//   mult_result = mult_result >> 1;
//
//   if (!options.json) {
//     std::cout << "The multiplication result is:- " << mult_result << std::endl;
//   }
// }
//
// auto create_arith_add_circuit(const Options& options, MOTION::TwoPartyBackend& backend) {
//   // if (options.my_id == 2) return std::make_pair(nullptr, nullptr);
//   // retrieve the gate factories for the chosen protocols
//   auto& gate_factory_arith = backend.get_gate_factory(options.arithmetic_protocol);//gmw
//   auto& gate_factory_bool = backend.get_gate_factory(options.boolean_protocol);// beavy
//
//   // share the inputs using the arithmetic protocol
//   // NB: the inputs need to always be specified in the same order:
//   // here we first specify the input of party 0, then that of party 1
//   ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint64_t>> input_promise;
//   MOTION::WireVector input_0_arith, input_1_arith;
//   if (options.my_id == 0) {
//     auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1);
//     input_promise = std::move(pair.first);
//     input_0_arith = std::move(pair.second);
//     input_1_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1 - options.my_id, 1);
//   } else if (options.my_id == 1) {
//     input_0_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1 - options.my_id, 1);
//     auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1);
//     input_promise = std::move(pair.first);
//     input_1_arith = std::move(pair.second);
//   } else {
//     auto pair = gate_factory_arith.make_arithmetic_64_input_gate_my(options.my_id, 1);
//
//
//     input_1_arith = gate_factory_arith.make_arithmetic_64_input_gate_other(1, 1);
//   }
//
//   std::cout << "/* create_arith_add_circuit --message */" << '\n';
//
//   // // create arithmetic gate to compute multiplication
//   auto output = gate_factory_arith.make_binary_gate(
//       ENCRYPTO::PrimitiveOperationType::MUL, input_0_arith, input_1_arith);
//
//   std::cout << "/* create_arith_add_circuit ++++++ message */" << '\n';
//
//   // create an output gates of the result
//   auto output_future = gate_factory_arith.make_arithmetic_64_output_gate_my(MOTION::ALL_PARTIES, output);
//
//   std::cout << "/* create_arith_add_circuit ***** message */" << '\n';
//
//
//
//
//   // return promise and future to allow setting inputs and retrieving outputs
//   return std::make_pair(std::move(input_promise), std::move(output_future));
// }
//
// void run_add_circuit(const Options& options, MOTION::TwoPartyBackend& backend){
//   // build the circuit and gets promise/future for the input/output
//   auto [input_promise, output_future] = create_arith_add_circuit(options, backend);
//
//   if (options.no_run) {
//     return;
//   }
//
//   std::cout << "We ARE here \n";
//
//   // set the promise with our input value
//   input_promise.set_value({options.input_value});
//
//   // execute the protocol
//   backend.run();
//
//   // retrieve the result from the future
//   auto bvs = output_future.get();
//   auto add_result = bvs.at(0);
//
//   if (!options.json) {
//     std::cout << "The addition result is:- " << add_result << std::endl;
//   }
// }
//
// int main(int argc, char* argv[]) {
//   std::cout << "/* SUVI parse? */" << '\n';
//   auto options = parse_program_options(argc, argv);
//   if (!options.has_value()) {
//     return EXIT_FAILURE;
//   }
//
//   std::cout << "/* SUVI just woke up */" << '\n';
//
//   try {
//     auto comm_layer = setup_communication(*options);
//     std::cout << "/* SUVI set up comms */" << '\n';
//     auto logger = std::make_shared<MOTION::Logger>(options->my_id,
//                                                    boost::log::trivial::severity_level::trace);
//     comm_layer->set_logger(logger);
//     std::cout << "/* SUVI set logger */" << '\n';
//     MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
//     MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
//     std::cout << "/* SUVI in main */" << '\n';
//     for (std::size_t i = 0; i < options->num_repetitions; ++i) {
//       MOTION::TwoPartyBackend backend(*comm_layer, options->threads, options->sync_between_setup_and_online, logger);
//
//       std::cout << "/* SUVI in main after TwoPartyBackend */" << '\n';
//       run_add_circuit(*options, backend);
//
//       //if (options->my_id == 0 || options->my_id == 1)
//       //  run_add_circuit(*options, backend);
//       std::cout << "/* SUVI in main after run_add_circuit */" << '\n';
//
//       comm_layer->sync();
//       comm_stats.add(comm_layer->get_transport_statistics());
//       comm_layer->reset_transport_statistics();
//       //run_time_stats.add(backend.get_run_time_stats());
//     }
//     comm_layer->shutdown();
//     print_stats(*options, run_time_stats, comm_stats);
//   } catch (std::runtime_error& e) {
//     std::cerr << "ERROR OCCURRED: " << e.what() << "\n";
//     return EXIT_FAILURE;
//   }
//
//   return EXIT_SUCCESS;
// }
