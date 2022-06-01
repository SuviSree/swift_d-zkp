
#pragma once

#include <memory>
#include <unordered_map>

#include "circuit_builder.h"
#include "gate_factory.h"

namespace ENCRYPTO::ObliviousTransfer {
class OTProviderManager;
}

namespace MOTION {

class ArithmeticProviderManager;
class BaseOTProvider;
class CircuitLoader;
class GateFactory;
class GateRegister;
class Logger;
class MTProvider;
class NewGateExecutor;
class SBProvider;
class SPProvider;
enum class MPCProtocol : unsigned int;

namespace Communication {
class CommunicationLayer;
}

namespace Crypto {
class MotionBaseProvider;
}

namespace proto {
namespace beavy {
class BEAVYProvider;
}
namespace gmw {
class GMWProvider;
}
namespace yao {
class YaoProvider;
}
}  // namespace proto

namespace Statistics {
struct RunTimeStats;
}

class TwoPartyBackend : public CircuitBuilder {
 public:
  TwoPartyBackend(Communication::CommunicationLayer&, std::size_t num_threads,
                  bool sync_between_setup_and_online, std::shared_ptr<Logger>);
  ~TwoPartyBackend();

  void run_preprocessing();
  void run();

  std::optional<MPCProtocol> convert_via(MPCProtocol src_proto, MPCProtocol dst_proto) override;
  GateFactory& get_gate_factory(MPCProtocol proto) override;

  const Statistics::RunTimeStats& get_run_time_stats() const noexcept;

 //private:
public:
  Communication::CommunicationLayer& comm_layer_;
  std::size_t my_id_;
  std::shared_ptr<Logger> logger_;
  std::unique_ptr<GateRegister> gate_register_;
  std::unique_ptr<NewGateExecutor> gate_executor_;
  std::unique_ptr<CircuitLoader> circuit_loader_;
  std::unordered_map<MPCProtocol, std::reference_wrapper<GateFactory>> gate_factories_;
  std::vector<Statistics::RunTimeStats> run_time_stats_;

  std::unique_ptr<Crypto::MotionBaseProvider> motion_base_provider_;
  std::unique_ptr<BaseOTProvider> base_ot_provider_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::OTProviderManager> ot_manager_;
  std::unique_ptr<ArithmeticProviderManager> arithmetic_manager_;
  std::unique_ptr<MTProvider> mt_provider_;
  std::unique_ptr<SPProvider> sp_provider_;
  std::unique_ptr<SBProvider> sb_provider_;

  std::unique_ptr<proto::beavy::BEAVYProvider> beavy_provider_;
  std::unique_ptr<proto::gmw::GMWProvider> gmw_provider_;
  std::unique_ptr<proto::yao::YaoProvider> yao_provider_;
};

}  // namespace MOTION
