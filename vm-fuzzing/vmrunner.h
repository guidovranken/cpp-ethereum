#pragma once

#include <test/tools/libtesteth/TestHelper.h>
#include <libdevcore/Log.h>
#include <libdevcore/CommonIO.h>
#include <libevm/ExtVMFace.h>
#include <libevm/VM.h>
#include <libethereum/Transaction.h>
#include <libethereum/ExtVM.h>
#include <libethereum/State.h>

namespace dev
{
namespace eth
{
class LastBlockHashesFace;
}

namespace test
{

class FakeExtVM: public eth::ExtVMFace
{
public:
	FakeExtVM() = delete;
	FakeExtVM(eth::EnvInfo const& _envInfo, unsigned _depth = 0);

	virtual u256 store(u256 _n) override { return std::get<2>(addresses[myAddress])[_n]; }
	virtual void setStore(u256 _n, u256 _v) override { std::get<2>(addresses[myAddress])[_n] = _v; }
	virtual bool exists(Address _a) override { return !!addresses.count(_a); }
	virtual u256 balance(Address _a) override { return std::get<0>(addresses[_a]); }
	virtual void suicide(Address _a) override { std::get<0>(addresses[_a]) += std::get<0>(addresses[myAddress]); addresses.erase(myAddress); }
	virtual bytes const& codeAt(Address _a) override { return std::get<3>(addresses[_a]); }
	virtual size_t codeSizeAt(Address _a) override { return std::get<3>(addresses[_a]).size(); }
	virtual std::pair<h160, eth::owning_bytes_ref> create(u256 _endowment, u256& io_gas, bytesConstRef _init, eth::Instruction _op, u256 _salt, eth::OnOpFunc const&) override;
	virtual std::pair<bool, eth::owning_bytes_ref> call(eth::CallParameters&) override;
	virtual h256 blockHash(u256 _number) override;
	void setTransaction(Address _caller, u256 _value, u256 _gasPrice, bytes const& _data);
	void setContract(Address _myAddress, u256 _myBalance, u256 _myNonce, std::map<u256, u256> const& _storage, bytes const& _code);
	void set(Address _a, u256 _myBalance, u256 _myNonce, std::map<u256, u256> const& _storage, bytes const& _code);
	void reset(u256 _myBalance, u256 _myNonce, std::map<u256, u256> const& _storage);
	u256 doPosts();

	eth::OnOpFunc simpleTrace() const;

	std::map<Address, std::tuple<u256, u256, std::map<u256, u256>, bytes>> addresses;
	bytes thisTxData;
	bytes thisTxCode;
	u256 gas;
	u256 execGas;
};

} } // Namespace Close
