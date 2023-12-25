#include <cstdint>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;

using field_type = algebra::curves::pallas::base_field_type;

constexpr std::size_t VALIDATORS_COUNT = 1000000;

[[circuit]] bool is_unique(
    [[private_input]] size_t actual_validator_count,
    [[private_input]] std::array<field_type::value_type, VALIDATORS_COUNT> sorted_validators_pubkeys,
    [[private_input]] std::array<field_type::value_type, VALIDATORS_COUNT> initial_validators_pubkeys,
    [[private_input]] std::array<size_t, VALIDATORS_COUNT> unique_to_initial_mapping)
{

    // we check that sorted_validators_pubkeys are unique
    // and each of shuffled element has same pubkey in initial_validators_pubkeys
    // hence we know that initial_validators_pubkeys is unique

    for (size_t i = 0; i < actual_validator_count - 1; ++i)
    {
        __builtin_assigner_exit_check(sorted_validators_pubkeys[i] < sorted_validators_pubkeys[i + 1]);
        __builtin_assigner_exit_check(initial_validators_pubkeys[unique_to_initial_mapping[i]] == sorted_validators_pubkeys[i]);
    }

    __builtin_assigner_exit_check(initial_validators_pubkeys[unique_to_initial_mapping[actual_validator_count - 1]] == sorted_validators_pubkeys[actual_validator_count - 1]);

    return true;
}