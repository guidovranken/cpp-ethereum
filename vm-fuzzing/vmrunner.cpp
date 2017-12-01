#include <libdevcore/CommonIO.h>
#include <libdevcore/Log.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethereum/ExtVM.h>
#include <libethereum/State.h>
#include <libethereum/Transaction.h>
#include <libevm/ExtVMFace.h>
#include <libevm/VM.h>
#include <libevm/VMFactory.h>
#include <test/tools/libtesteth/BlockChainHelper.h>
#include <test/tools/libtesteth/TestHelper.h>
#include <test/tools/libtestutils/TestLastBlockHashes.h>

typedef std::vector<uint8_t> stack_item_t;
typedef std::vector<stack_item_t> stack_t;
typedef std::pair<uint64_t, uint64_t> address_opcode_t;
typedef std::vector< address_opcode_t > vm_trace_t;
typedef uint64_t gas_item_t;
typedef std::vector<gas_item_t> gas_t;

using namespace std;
using namespace dev;
using namespace dev::eth;
using namespace dev::test;

/* Various traces, exported to the fuzzer */
gas_t g_gas;
vm_trace_t g_trace;
stack_t prev_stack;
stack_t g_stack;

bool g_do_trace;
uint64_t g_execution_num;
uint64_t g_max_pc;

/* Called by the fuzzer to retrieve instruction trace after execution */
vm_trace_t cpp_get_trace(void)
{
    return g_trace;
}

/* Called by the fuzzer to retrieve stack after execution */
stack_t cpp_get_stack(void)
{
    return g_stack;
}

/* Called by the fuzzer to retrieve gas trace after execution */
gas_t cpp_get_gas(void)
{
    return g_gas;
}

eth::OnOpFunc simpleTrace()
{
    /* Called by the VM for every executed instruction. */
    return [](uint64_t steps, uint64_t pc, eth::Instruction inst, bigint newMemSize, bigint gasCost, bigint gas, dev::eth::VM* voidVM, dev::eth::ExtVMFace const* voidExt)
    {
        /* Disable compiler warnings for unused variables */
        (void)steps;
        (void)newMemSize;
        (void)gasCost;

        ExtVM const& ext = *static_cast<ExtVM const*>(voidExt);
        eth::VM& vm = *voidVM;
        stack_t cur_stack;

        /* If the VM tries to fetch an instruction from a non-existing code address,
         * this is logged as STOP instruction.
         * Intercept this behavior and don't log the artificial STOP.
         */
        if ( pc >= g_max_pc ) {
            if ( (Instruction)inst != Instruction::STOP ) {
                printf("??? OOB instruction is not STOP\n");
                abort();
            }
            return;
        }

        for (auto i: vm.stack()) {
            stack_item_t stack_item;

            /* Convert Boost bigint to bytes */
            export_bits(i, std::back_inserter(stack_item), 8);
            /* Pad with zeroes */
            for (int j = stack_item.size(); j < 32; j++) {
                stack_item.push_back(0x00);
            }
            cur_stack.push_back(stack_item);
        }

        /* Stack logging must be delayed by one execution to be aligned with
         * Parity/Geth logging behavior */
        g_stack = prev_stack;
        prev_stack = cur_stack;

        if ( g_do_trace == true ) {
            /* Print current variables if --trace is specified */
            std::cout << "[" << g_execution_num << "] " << pc << " : " << instructionInfo((Instruction)inst).name << std::endl;

            std::cout << "Stack: [";
            for ( auto S : cur_stack ) {
                std::cout << (h256)S << " ";
            }
            std::cout << "]" << std::endl;

            std::cout << "Gas: " << gas << std::endl;
            std::cout << "Depth: " << ext.depth + 1 << std::endl;
        }

        g_execution_num++;

        g_trace.push_back( address_opcode_t(pc, (uint64_t)inst));
        g_gas.push_back(static_cast<uint64_t>(gas));
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
    g_stack.clear();
    g_gas.clear();
    prev_stack.clear();

    g_do_trace = do_trace;
    g_execution_num = 1;

    /* No logging to stderr */
    g_logVerbosity = 0;

    BlockHeader blockHeader;
    blockHeader.setGasLimit(gaslimit);
    blockHeader.setDifficulty(difficulty);
    blockHeader.setTimestamp(timestamp);
    blockHeader.setAuthor(Address(0));
    blockHeader.setNumber(blocknumber);

    TestLastBlockHashes lastBlockHashes(h256s(256, h256()));
    eth::EnvInfo env(blockHeader, lastBlockHashes, 0);

    Ethash::init();
    ChainParams p = ChainParams(genesisInfo(eth::Network::ByzantiumTest));

    BlockChain blockchain(p, "/tmp/X", WithExisting::Kill);
    OverlayDB stateDB = OverlayDB();
    Address addr(0x155);
    Block block = blockchain.genesisBlock(stateDB);
    block.mutableState().addBalance(addr, u256(100));
    ExtVM fev(block.mutableState(), env, *blockchain.sealEngine(), addr, addr, addr, 0, 0, bytesConstRef(), bytesConstRef(), h256());

    fev.code = bytes(code, code + size);
    g_max_pc = size;
    fev.codeHash = sha3(fev.code);
    fev.origin = Address(0);
    //fev.gas = gas;
    fev.gasPrice = gasprice;
    fev.myAddress = Address(0x155);
    fev.caller = Address(0x155);
    fev.value = balance; 

    /* Run */
    try {
        auto vm = eth::VMFactory::create();
        u256 _gas(gas);
        vm->exec(_gas, fev, simpleTrace());
    }
    catch (VMException const& e)
    {
        /* Catch normal VM exceptions such as out of gas, invalid jump dest, ... */
        if ( do_trace ) {
            std::cout << diagnostic_information(e) << std::endl;
        }

        /* Return failure */
        return 0;
    }

    /* Return success */
    return 1;
}
