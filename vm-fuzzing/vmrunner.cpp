#include "vmrunner.h"
#include <test/tools/libtestutils/TestLastBlockHashes.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libevm/VMFactory.h>

typedef std::vector<uint8_t> stack_item_t;
typedef std::vector<stack_item_t> stack_t;
typedef std::pair<uint64_t, uint64_t> address_opcode_t;
typedef std::vector< address_opcode_t > vm_trace_t;

using namespace std;
using namespace dev;
using namespace dev::eth;
using namespace dev::test;

vm_trace_t g_trace;
stack_t g_stack;
bool g_do_trace;
uint64_t g_execution_num;

FakeExtVM::FakeExtVM(EnvInfo const& _envInfo, unsigned _depth):			/// TODO: XXX: remove the default argument & fix.
	ExtVMFace(_envInfo, Address(), Address(), Address(), 0, 1, bytesConstRef(), bytes(), EmptySHA3, false, _depth)
{}

std::pair<h160, eth::owning_bytes_ref> FakeExtVM::create(u256 _endowment, u256& io_gas, bytesConstRef _init, Instruction , u256, OnOpFunc const&)
{
	Address na = right160(sha3(rlpList(myAddress, get<1>(addresses[myAddress]))));
	Transaction t(_endowment, gasPrice, io_gas, _init.toBytes());
	//callcreates.push_back(t);
	return {na, eth::owning_bytes_ref{}};
}

std::pair<bool, eth::owning_bytes_ref> FakeExtVM::call(CallParameters& _p)
{
	Transaction t(_p.valueTransfer, gasPrice, _p.gas, _p.receiveAddress, _p.data.toVector());
	//callcreates.push_back(t);
	return {true, eth::owning_bytes_ref{}};  // Return empty output.
}

h256 FakeExtVM::blockHash(u256 _number)
{
	//cnote << "Warning: using fake blockhash code!\n";
	if (_number < envInfo().number() && _number >= (std::max<u256>(256, envInfo().number()) - 256))
		return sha3(toString(_number));

	return h256();
}

void FakeExtVM::set(Address _a, u256 _myBalance, u256 _myNonce, map<u256, u256> const& _storage, bytes const& _code)
{
	get<0>(addresses[_a]) = _myBalance;
	get<1>(addresses[_a]) = _myNonce;
	get<2>(addresses[_a]) = _storage;
	get<3>(addresses[_a]) = _code;
}

void FakeExtVM::reset(u256 _myBalance, u256 _myNonce, map<u256, u256> const& _storage)
{
	//callcreates.clear();
	addresses.clear();
	set(myAddress, _myBalance, _myNonce, _storage, get<3>(addresses[myAddress]));
}

vm_trace_t cpp_get_trace(void)
{
    return g_trace;
}

stack_t cpp_get_stack(void)
{
    return g_stack;
}

eth::OnOpFunc FakeExtVM::simpleTrace() const
{

	return [](uint64_t steps, uint64_t pc, eth::Instruction inst, bigint newMemSize, bigint gasCost, bigint gas, dev::eth::VM* voidVM, dev::eth::ExtVMFace const* voidExt)
	{
		FakeExtVM const& ext = *static_cast<FakeExtVM const*>(voidExt);
		eth::VM& vm = *voidVM;

        g_stack.clear();
		for (auto i: vm.stack()) {
            stack_item_t stack_item;

            /* Convert Boost bigint to bytes */
            export_bits(i, std::back_inserter(stack_item), 8);
            /* Pad with zeroes */
            for (int j = stack_item.size(); j < 32; j++) {
                stack_item.push_back(0x00);
            }
            g_stack.push_back(stack_item);
        }

        if ( g_do_trace == true ) {
            printf("[%zu] %zu : %s\n", g_execution_num, pc, instructionInfo((Instruction)inst).name.c_str());
        }

        g_execution_num++;
        g_trace.push_back( address_opcode_t(pc, (uint64_t)inst));
	};
}

int cpp_run_vm(
        const uint8_t* code,
        size_t size,
        bool do_trace,
        uint64_t gas,
        uint64_t blocknumber,
        uint64_t timestamp,
        uint64_t gaslimit,
        uint64_t difficulty,
        uint64_t gasprice,
        uint64_t balance)
{
    g_trace.clear();
    g_do_trace = do_trace;
    g_execution_num = 0;

	BlockHeader blockHeader;
	blockHeader.setGasLimit(gaslimit);
	blockHeader.setDifficulty(difficulty);
	blockHeader.setTimestamp(timestamp);
	blockHeader.setAuthor(Address(0x155));
	blockHeader.setNumber(blocknumber);

    TestLastBlockHashes lastBlockHashes(h256s(256, h256()));
	eth::EnvInfo env(blockHeader, lastBlockHashes, 0);

    FakeExtVM fev(env);

    fev.code = bytes(code, code + size);
    fev.codeHash = sha3(fev.code);
    fev.gas = gas;
    try {
        auto vm = eth::VMFactory::create();
        do_trace = true;
        auto vmtrace = do_trace ? fev.simpleTrace() : OnOpFunc{};
        vm->exec(fev.gas, fev, vmtrace);
    }
    catch (VMException const&)
    {
        return 0;
    }

    return 1;
}
