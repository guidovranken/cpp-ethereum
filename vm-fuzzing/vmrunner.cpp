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

#include <openssl/md5.h>
MD5_CTX g_md5_trace;
MD5_CTX g_md5_stack;
MD5_CTX g_md5_gas;

uint8_t g_stack_hash[16];
uint8_t g_trace_hash[16];

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

/* Called by the fuzzer to retrieve instruction trace after execution */
vm_trace_t cpp_get_trace(void)
{
    return g_trace;
}

/* Called by the fuzzer to retrieve instruction trace hash after execution */
void cpp_get_trace_hash(uint8_t* hash)
{
    memcpy(hash, g_trace_hash, sizeof(g_trace_hash));
}

/* Called by the fuzzer to retrieve stack after execution */
stack_t cpp_get_stack(void)
{
    return g_stack;
}

/* Called by the fuzzer to retrieve the stack hash after execution */
void cpp_get_stack_hash(uint8_t* hash)
{
    memcpy(hash, g_stack_hash, sizeof(g_stack_hash));
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

        /* Update MD5 over current stack */
        for (auto i: vm.stack()) {
            stack_item_t stack_item;
            stack_item_t stack_item2;
            std::size_t size = i.backend().size();
            boost::multiprecision::limb_type* p = i.backend().limbs();

            if ( size > 4 ) {
                /* This shouldn't happen */
                abort();
            }

            uint64_t S[4];
            for (int j = 0; j < 4; j++) {
                S[j] = (j < (int)size) ? p[j] : 0;
            }

            uint8_t reversed[32];
            for (int j = 0; j < 32; j++) {
                uint8_t* from = (uint8_t*)S;
                reversed[j] = from[31-j];
            }
            if ( MD5_Update(&g_md5_stack, reversed, 32) != 1 ) { abort(); }
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

        /* Update MD5 over current address and opcode */
        struct {
            uint64_t address;
            uint64_t opcode;
        } address_opcode;
        address_opcode.address = pc;
        address_opcode.opcode = (uint8_t)inst;
        if ( MD5_Update(&g_md5_trace, &address_opcode, sizeof(address_opcode)) != 1 ) { abort(); }

        /* Update MD5 over current gas */
        uint64_t gas_uint64 = static_cast<uint64_t>(gas);
        if ( MD5_Update(&g_md5_gas, &gas_uint64, sizeof(gas_uint64)) != 1 ) { abort(); }
    };
}

extern "C" void cpp_get_prestate(size_t* address, size_t* balance, uint8_t** code, size_t* code_size, size_t idx);
static void set_prestate(State* state)
{
    size_t i = 0;

    while ( 1 ) {
        size_t _address;
        size_t balance;
        uint8_t* code;
        size_t code_size;

        /* Retrieve the tuple (address, balance, code) from the fuzzer shim */
        cpp_get_prestate(&_address, &balance, &code, &code_size, i);

        if ( _address == 0 ) {
            /* address set to 0 by cpp_get_prestate() signals the end of the account list */
            break;
        }

        i += 1;

        Address address(_address);

        state->addBalance(address, balance);
        state->setCode(address, bytes(code, code + code_size));
    }
}

int cpp_run_vm(
        const uint8_t* code,
        size_t codesize,
        const uint8_t* input,
        size_t inputsize,
        bool do_trace,
        uint64_t gas,
        uint64_t blocknumber,
        uint64_t timestamp,
        uint64_t gaslimit,
        uint64_t difficulty,
        uint64_t gasprice,
        uint64_t balance)
{
    static bool ethash_initialized = false;
    static ChainParams* p = NULL;
    int ret = 0;

    if ( MD5_Init(&g_md5_trace) != 1 ) { abort(); }
    if ( MD5_Init(&g_md5_stack) != 1 ) { abort(); }
    if ( MD5_Init(&g_md5_gas) != 1 ) { abort(); }

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

    if ( ethash_initialized == false ) {
        Ethash::init();
        ethash_initialized = true;
    }
    if ( p == NULL ) {
        p = new ChainParams(genesisInfo(eth::Network::ByzantiumTest));
    }

    OverlayDB stateDB = OverlayDB();
    Address addr(0x155);
	SealEngineFace* sealEngine = p->createSealEngine();
    State state(State::Null);
    state.noteAccountStartNonce(u256(0));
    state.addBalance(addr, u256(0));

    /* Precompiles */
    state.addBalance(Address(1), u256(1));
    state.addBalance(Address(2), u256(1));
    state.addBalance(Address(3), u256(1));
    state.addBalance(Address(4), u256(1));

    set_prestate(&state);

    ExtVM fev(state, env, *sealEngine, addr, addr, addr, 0, 0, bytesConstRef(), bytesConstRef(), h256());

    fev.code = bytes(code, code + codesize);
    fev.data = bytesConstRef(input, inputsize);
    fev.codeHash = h256(0);
    fev.origin = Address(0);
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

        goto end;
    }


    ret = 1;
end:
    unsigned char hash[MD5_DIGEST_LENGTH];
    if ( MD5_Final(g_trace_hash, &g_md5_trace) != 1 ) { abort(); }
    if ( MD5_Final(g_stack_hash, &g_md5_stack) != 1 ) { abort(); }
    if ( MD5_Final(hash, &g_md5_gas) != 1 ) { abort(); }

    delete sealEngine;

    return ret;
}
