#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <cstdint>
#include <vector>

using namespace nil::crypto3;

using hash_type = hashes::sha2<256>;
using block_type = hash_type::block_type;

constexpr std::size_t PROBLEM_SIZE_LOG2 = 4;
constexpr std::size_t VALIDATORS_COUNT = 800000; // << PROBLEM_SIZE_LOG2;

bool is_same(block_type block0, block_type block1)
{
    return block0[0] == block1[0] && block0[1] == block1[1];
}

[[circuit]] bool balance_tree(
    [[private_input]] size_t actual_validator_count,
    [[private_input]] std::array<block_type, VALIDATORS_COUNT> validators_pubkeys)
{

    for (size_t i = 0; i < actual_validator_count; ++i)
    {
        for (size_t j = i + 1; j < actual_validator_count; ++j)
        {
            bool sameElementsFound = !is_same(validators_pubkeys[i], validators_pubkeys[j]);
            __builtin_assigner_exit_check(sameElementsFound);
        }
    }

    return true;
}
