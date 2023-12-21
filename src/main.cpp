#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <cstdint>

using namespace nil::crypto3;

using hash_type = hashes::sha2<256>;
using block_type = hash_type::block_type;
using field_type = algebra::curves::pallas::base_field_type;

const std::array<block_type, 40> precomputed_zero_hashes = {{{0x00000000000000000000000000000000_cppui255, 0x00000000000000000000000000000000_cppui255},
                                                             {0xf5a5fd42d16a20302798ef6ed309979b_cppui255, 0x43003d2320d9f0e8ea9831a92759fb4b_cppui255},
                                                             {0xdb56114e00fdd4c1f85c892bf35ac9a8_cppui255, 0x9289aaecb1ebd0a96cde606a748b5d71_cppui255},
                                                             {0xc78009fdf07fc56a11f122370658a353_cppui255, 0xaaa542ed63e44c4bc15ff4cd105ab33c_cppui255},
                                                             {0x536d98837f2dd165a55d5eeae9148595_cppui255, 0x4472d56f246df256bf3cae19352a123c_cppui255},
                                                             {0x9efde052aa15429fae05bad4d0b1d7c6_cppui255, 0x4da64d03d7a1854a588c2cb8430c0d30_cppui255},
                                                             {0xd88ddfeed400a8755596b21942c1497e_cppui255, 0x114c302e6118290f91e6772976041fa1_cppui255},
                                                             {0x87eb0ddba57e35f6d286673802a4af59_cppui255, 0x75e22506c7cf4c64bb6be5ee11527f2c_cppui255},
                                                             {0x26846476fd5fc54a5d43385167c95144_cppui255, 0xf2643f533cc85bb9d16b782f8d7db193_cppui255},
                                                             {0x506d86582d252405b840018792cad2bf_cppui255, 0x1259f1ef5aa5f887e13cb2f0094f51e1_cppui255},
                                                             {0xffff0ad7e659772f9534c195c815efc4_cppui255, 0x14ef1e1daed4404c06385d11192e92b_cppui255},
                                                             {0x6cf04127db05441cd833107a52be8528_cppui255, 0x68890e4317e6a02ab47683aa75964220_cppui255},
                                                             {0xb7d05f875f140027ef5118a2247bbb84_cppui255, 0xce8f2f0f1123623085daf7960c329f5f_cppui255},
                                                             {0xdf6af5f5bbdb6be9ef8aa618e4bf8073_cppui255, 0x960867171e29676f8b284dea6a08a85e_cppui255},
                                                             {0xb58d900f5e182e3c50ef74969ea16c77_cppui255, 0x26c549757cc23523c369587da7293784_cppui255},
                                                             {0xd49a7502ffcfb0340b1d7885688500ca_cppui255, 0x308161a7f96b62df9d083b71fcc8f2bb_cppui255},
                                                             {0x8fe6b1689256c0d385f42f5bbe2027a2_cppui255, 0x2c1996e110ba97c171d3e5948de92beb_cppui255},
                                                             {0x8d0d63c39ebade8509e0ae3c9c3876fb_cppui255, 0x5fa112be18f905ecacfecb92057603ab_cppui255},
                                                             {0x95eec8b2e541cad4e91de38385f2e046_cppui255, 0x619f54496c2382cb6cacd5b98c26f5a4_cppui255},
                                                             {0xf893e908917775b62bff23294dbbe3a1_cppui255, 0xcd8e6cc1c35b4801887b646a6f81f17f_cppui255},
                                                             {0xcddba7b592e3133393c16194fac7431a_cppui255, 0xbf2f5485ed711db282183c819e08ebaa_cppui255},
                                                             {0x8a8d7fe3af8caa085a7639a832001457_cppui255, 0xdfb9128a8061142ad0335629ff23ff9c_cppui255},
                                                             {0xfeb3c337d7a51a6fbf00b9e34c52e1c9_cppui255, 0x195c969bd4e7a0bfd51d5c5bed9c1167_cppui255},
                                                             {0xe71f0aa83cc32edfbefa9f4d3e0174ca_cppui255, 0x85182eec9f3a09f6a6c0df6377a510d7_cppui255},
                                                             {0x31206fa80a50bb6abe29085058f16212_cppui255, 0x212a60eec8f049fecb92d8c8e0a84bc0_cppui255},
                                                             {0x21352bfecbeddde993839f614c3dac0a_cppui255, 0x3ee37543f9b412b16199dc158e23b544_cppui255},
                                                             {0x619e312724bb6d7c3153ed9de791d764_cppui255, 0xa366b389af13c58bf8a8d90481a46765_cppui255},
                                                             {0x7cdd2986268250628d0c10e385c58c61_cppui255, 0x91e6fbe05191bcc04f133f2cea72c1c4_cppui255},
                                                             {0x848930bd7ba8cac54661072113fb2788_cppui255, 0x69e07bb8587f91392933374d017bcbe1_cppui255},
                                                             {0x8869ff2c22b28cc10510d98532928033_cppui255, 0x28be4fb0e80495e8bb8d271f5b889636_cppui255},
                                                             {0xb5fe28e79f1b850f8658246ce9b6a1e7_cppui255, 0xb49fc06db7143e8fe0b4f2b0c5523a5c_cppui255},
                                                             {0x985e929f70af28d0bdd1a90a808f977f_cppui255, 0x597c7c778c489e98d3bd8910d31ac0f7_cppui255},
                                                             {0xc6f67e02e6e4e1bdefb994c6098953f3_cppui255, 0x4636ba2b6ca20a4721d2b26a886722ff_cppui255},
                                                             {0x1c9a7e5ff1cf48b4ad1582d3f4e4a100_cppui255, 0x4f3b20d8c5a2b71387a4254ad933ebc5_cppui255},
                                                             {0x2f075ae229646b6f6aed19a5e372cf29_cppui255, 0x5081401eb893ff599b3f9acc0c0d3e7d_cppui255},
                                                             {0x328921deb59612076801e8cd61592107_cppui255, 0xb5c67c79b846595cc6320c395b46362c_cppui255},
                                                             {0xbfb909fdb236ad2411b4e4883810a074_cppui255, 0xb840464689986c3f8a8091827e17c327_cppui255},
                                                             {0x55d8fb3687ba3ba49f342c77f5a1f89b_cppui255, 0xec83d811446e1a467139213d640b6a74_cppui255},
                                                             {0xf7210d4f8e7e1039790e7bf4efa20755_cppui255, 0x5a10a6db1dd4b95da313aaa88b88fe76_cppui255},
                                                             {0xad21b516cbc645ffe34ab5de1c8aef8c_cppui255, 0xd4e7f8d2b51e8e1456adc7563cda206f_cppui255}}};

constexpr std::size_t VALIDATORS_MAX_SIZE_LOG2 = 40;

constexpr std::size_t VALIDATORS_TARGET_TREE_HEIGHT = VALIDATORS_MAX_SIZE_LOG2;

constexpr std::size_t PROBLEM_SIZE_LOG2 = 6;
constexpr std::size_t VALIDATORS_COUNT = 1 << PROBLEM_SIZE_LOG2;  // 2 ** PROBLEM_SIZE_LOG2
constexpr std::size_t VALIDATORS_TREE_HEIGHT = PROBLEM_SIZE_LOG2; // 2 ** PROBLEM_SIZE_LOG2

constexpr std::size_t VALIDATOR_FIELDS = 8;
constexpr std::size_t BEACON_STATE_FIELD_INCLUSION_PROOF_LENGTH = 5;
constexpr std::size_t VALIDATORS_FIELD_INDEX = 11;

constexpr std::size_t BEACON_BLOCK_FIELDS_COUNT = 5;

constexpr bool BYTE_ORDER_MSB = true;
constexpr bool BYTE_ORDER_LSB = false;

bool is_same(block_type block0, block_type block1)
{
    return block0[0] == block1[0] && block0[1] == block1[1];
}

template <std::size_t LayerSize>
block_type hash_layer(std::array<block_type, LayerSize> input, size_t layer)
{
    constexpr size_t NextLayerSize = (LayerSize % 2 == 0) ? LayerSize / 2 : (LayerSize / 2 + 1);
    std::array<block_type, NextLayerSize> next_layer;

    for (std::size_t leaf_index = 0; leaf_index < LayerSize / 2; leaf_index++)
    {
        next_layer[leaf_index] = hash<hash_type>(input[2 * leaf_index], input[2 * leaf_index + 1]);
    }
    if (LayerSize % 2 != 0)
    {
        next_layer[NextLayerSize - 1] = hash<hash_type>(LayerSize - 1, precomputed_zero_hashes[layer]);
    }
    if (LayerSize == 2)
        return next_layer[0];
    else
        return hash_layer<NextLayerSize>(next_layer, layer + 1);
}

template <std::size_t LayerSize>
block_type hash_tree(std::array<block_type, LayerSize> input)
{
    return hash_layer(input, 0);
}

block_type lift_uint64(uint64_t value)
{
    std::array<typename field_type::value_type, 128> decomposed_block;
    __builtin_assigner_bit_decomposition(decomposed_block.data(), 64, value, BYTE_ORDER_LSB);
    __builtin_assigner_bit_decomposition(decomposed_block.data() + 64, 64, uint64_t(0), BYTE_ORDER_LSB);
    return {
        __builtin_assigner_bit_composition(decomposed_block.data(), 128, BYTE_ORDER_LSB),
        0};
}

block_type mix_in_size(const block_type root, size_t size)
{
    return hash<hash_type>(root, lift_uint64(size));
}

template <size_t TargetTreeHeight, size_t LeafsCount, size_t LeafsTreeHeight>
block_type merkelize(std::array<block_type, LeafsCount> merkle_leaves)
{
    block_type leaves_tree_root = hash_tree<LeafsCount>(merkle_leaves);

    block_type current_hash = leaves_tree_root;
    for (size_t height = LeafsTreeHeight; height < TargetTreeHeight; ++height)
    {
        current_hash = hash<hash_type>(current_hash, precomputed_zero_hashes[height]);
    }
    return current_hash;
}

block_type compute_validators_ssz_merkleization(
    size_t actual_validator_count,
    std::array<block_type, VALIDATORS_COUNT> validators_pubkeys,
    std::array<block_type, VALIDATORS_COUNT> validators_withdrawal_credentials,
    std::array<uint64_t, VALIDATORS_COUNT> validators_effective_balances,
    std::array<uint64_t, VALIDATORS_COUNT> validators_slashed,
    std::array<uint64_t, VALIDATORS_COUNT> validators_activation_eligibility_epoch,
    std::array<uint64_t, VALIDATORS_COUNT> validators_activation_epoch,
    std::array<uint64_t, VALIDATORS_COUNT> validators_exit_epoch,
    std::array<uint64_t, VALIDATORS_COUNT> validators_withdrawable_epoch)
{
    std::array<block_type, VALIDATORS_COUNT> validator_leaves;

    for (size_t validator_idx; validator_idx < VALIDATORS_COUNT; ++validator_idx)
    {
        validator_leaves[validator_idx] = hash_tree<8>({validators_pubkeys[validator_idx],
                                                        validators_withdrawal_credentials[validator_idx],
                                                        lift_uint64(validators_effective_balances[validator_idx]),
                                                        lift_uint64(validators_slashed[validator_idx]),
                                                        lift_uint64(validators_activation_eligibility_epoch[validator_idx]),
                                                        lift_uint64(validators_activation_epoch[validator_idx]),
                                                        lift_uint64(validators_exit_epoch[validator_idx]),
                                                        lift_uint64(validators_withdrawable_epoch[validator_idx])});
    }

    return mix_in_size(
        merkelize<VALIDATORS_TARGET_TREE_HEIGHT, VALIDATORS_COUNT, VALIDATORS_TREE_HEIGHT>(validator_leaves),
        actual_validator_count);
}

template <size_t ProofSize>
bool verify_inclusion_proof(size_t field_index, block_type field_hash, block_type merkle_root, std::array<block_type, ProofSize> inclusion_proof)
{
    size_t cur_index = field_index;
    block_type current_hash = field_hash;
    block_type return_block = field_hash;

    current_hash = hash<hash_type>(current_hash, inclusion_proof[0]);
    current_hash = hash<hash_type>(inclusion_proof[1], current_hash);
    current_hash = hash<hash_type>(current_hash, inclusion_proof[2]);
    current_hash = hash<hash_type>(inclusion_proof[3], current_hash);
    current_hash = hash<hash_type>(current_hash, inclusion_proof[4]);

    return is_same(current_hash, merkle_root);
}

[[circuit]] block_type circuit(
    [[private_input]] size_t actual_validator_count, // this is the number of real, non-empty validators and balances in use
    [[private_input]] std::array<block_type, VALIDATORS_COUNT> validators_pubkeys,
    [[private_input]] std::array<block_type, VALIDATORS_COUNT> validators_withdrawal_credentials,
    [[private_input]] std::array<uint64_t, VALIDATORS_COUNT> validators_effective_balances,
    [[private_input]] std::array<uint64_t, VALIDATORS_COUNT> validators_slashed,
    [[private_input]] std::array<uint64_t, VALIDATORS_COUNT> validators_activation_eligibility_epoch,
    [[private_input]] std::array<uint64_t, VALIDATORS_COUNT> validators_activation_epoch,
    [[private_input]] std::array<uint64_t, VALIDATORS_COUNT> validators_exit_epoch,
    [[private_input]] std::array<uint64_t, VALIDATORS_COUNT> validators_withdrawable_epoch,
    uint64_t slot,
    uint64_t epoch,
    [[private_input]] block_type expected_validators_hash,
    block_type beacon_state_hash,
    block_type beacon_block_hash,
    [[private_input]] std::array<block_type, BEACON_STATE_FIELD_INCLUSION_PROOF_LENGTH> validators_hash_inclusion_proof,
    [[private_input]] std::array<block_type, BEACON_BLOCK_FIELDS_COUNT> beacon_block_fields)
{
    // Sanity-checking input
    // bool inputSanityCheck = ((actual_validator_count <= VALIDATORS_COUNT) &&
    //                          (slot >= epoch * 32) &&
    //                          (slot < (epoch + 1) * 32));
    // __builtin_assigner_exit_check(inputSanityCheck);

    block_type validators_hash = compute_validators_ssz_merkleization(
        actual_validator_count,
        validators_pubkeys,
        validators_withdrawal_credentials,
        validators_effective_balances,
        validators_slashed,
        validators_activation_eligibility_epoch,
        validators_activation_epoch,
        validators_exit_epoch,
        validators_withdrawable_epoch);

    bool merkleHashesMatch =
        is_same(expected_validators_hash, validators_hash);
    // __builtin_assigner_exit_check(merkleHashesMatch);

    bool beaconStateInclusionCheck = true;
    verify_inclusion_proof(VALIDATORS_FIELD_INDEX, validators_hash, beacon_state_hash, validators_hash_inclusion_proof);
    // __builtin_assigner_exit_check(beaconStateInclusionCheck);

    bool beaconBlockInclusionCheck = (is_same(lift_uint64(slot), beacon_block_fields[0]) &&
                                      is_same(beacon_state_hash, beacon_block_fields[3]) &&
                                      is_same(hash_tree(beacon_block_fields), beacon_block_hash));
    // __builtin_assigner_exit_check(beaconBlockInclusionCheck);

    return validators_hash;
}