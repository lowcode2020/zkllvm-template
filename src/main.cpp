#include <cstdint>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

using namespace nil::crypto3;

using field_type = algebra::curves::pallas::base_field_type;

constexpr std::size_t VALIDATORS_COUNT = 1000000;

[[circuit]] field_type::value_type is_unique(
    [[private_input]] size_t actual_validator_count,
    [[private_input]] std::array<field_type::value_type, VALIDATORS_COUNT> validators_pubkeys,
    field_type::value_type poseidon_commitment)
{

    field_type::value_type validator0 = validators_pubkeys[0];
    field_type::value_type validator1 = validators_pubkeys[1];

    field_type::value_type hash_result = hash<hashes::poseidon>(validator0, validator1);

    for (size_t i = 2; i < actual_validator_count; ++i)
    {
        hash_result = hash<hashes::poseidon>(hash_result, validators_pubkeys[i]);
    }

    // __builtin_assigner_exit_check(hash_result == poseidon_commitment);

    return hash_result;
}