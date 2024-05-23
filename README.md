# Concordium Liquid Staking SmartContract

### Explanation:

1. **Contract Initialization**:

   - The contract name is updated to `concordium_staking`.
   - The `contract_init` function initializes the contract state with the token address and default values.

2. **Stake Function**:

   - The `stake` function allows users to stake tokens. It transfers tokens to the contract, updates the user's stake, mints liquid tokens, and logs the event.

3. **Unstake Function**:

   - The `unstake` function allows users to unstake tokens. It ensures the user has enough staked tokens, calculates rewards, updates the state, transfers tokens back to the user, and logs the event.

4. **Claim Rewards Function**:

   - The `claim_rewards` function allows users to claim their rewards. It calculates rewards, transfers them to the user, and logs the event.

5. **Get Earned Rewards Function**:

   - The `get_earned_rewards` function calculates and returns the earned rewards for a user without transferring them.

6. **Update APR Function**:

   - The `update_apr` function allows the contract owner to update the APR. It updates the state and logs the event.

7. **Helper Functions**:
   - `calculate_reward` calculates the rewards based on the staked amount, duration
