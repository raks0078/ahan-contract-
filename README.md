## Concordium Liquid Staking Smart Contract Explaination

### Overview

This document provides a step-by-step guide for deploying and configuring the Concordium Liquid Staking smart contract along with associated modules and contracts. The Liquid Staking contract allows users to stake EUROe stablecoin tokens and earn rewards.

### Contracts Details

1. **EUROe Stablecoin Contract:**
   - **Contract Address:** [Link](https://testnet.ccdscan.io/tokens?dcount=1&dentity=contract&dcontractAddressIndex=7260&dcontractAddressSubIndex=0)
  
2. **Liquid EUROe Contract:**
   - **Contract Address:** [Link](https://testnet.ccdscan.io/tokens?dcount=1&dentity=contract&dcontractAddressIndex=9248&dcontractAddressSubIndex=0)

3. **Staking Contract:**
   - **Contract Address:** [Link](https://testnet.ccdscan.io/tokens?dcount=2&dentity=contract&dcontractAddressIndex=9273&dcontractAddressSubIndex=0)
   - **Module:** [Link](https://testnet.ccdscan.io/tokens?dcount=1&dentity=module&dmoduleReference=733850daa2e41aae05bb6b200b902e9a1ef66d3eaf6f18392755656b666191f5)

### Staking Contract Methods

1. **Contract Initialization:**
   - Initializes the contract state with the token address and default values.

2. **onReceivingCIS2 Function:**
   - For receiving CIS2 Token including EUROe stablecoin into the smart contract.

3. **Stake Function:**
   - Allows users to stake tokens, updates user's stake, mints Liquid tokens, and logs the event.

4. **Unstake Function:**
   - Allows users to unstake tokens, calculates rewards, updates the state, transfers tokens back to the user, and logs the event.

5. **Claim Rewards Function:**
   - Allows users to claim their rewards, calculates rewards, transfers them to the user, and logs the event.

6. **withdrawEuroe Function:**
   - Allows the owner to rescue EUROe tokens from the smart contract. Accessible only by the contract owner.

7. **setPaused Function:**
   - Function to pause or unpause the concordium liquid staking contract. Accessible only by the contract owner.

8. **Update APR Function:**
   - Allows the contract owner to update the Annual Percentage Rate (APR). Updates the state and logs the event.

9. **Upgrade Function:**
   - Upgrades the smart contract instance to a new module and optionally calls a migration function after the upgrade.

10. **View Function:**
    - Retrieves contract state.

11. **GetStakeInfo Function:**
    - Retrieves specific user stake.

12. **Get Earned Rewards Function:**
    - Calculates and returns the earned rewards for a user without transferring them.

### Helper Functions

1. **onlyAccount Function:**
   - Validation function to check only account.

2. **get_current_timestamp Function:**
   - Derives the current block timestamp.

3. **calculate_reward Function:**
   - Calculates rewards based on the staked amount and duration.

4. **transfer_euroe_token Function:**
   - Transfers EUROe stablecoin from the smart contract to the user.

5. **mint Function:**
   - Mints the same amount of Liquid EUROe tokens when someone stakes EUROe tokens. Requires 'mintrole' to be provided to this smart contract address on contract configuration.

6. **Burn Function:**
   - Burns Liquid EUROe tokens. Requires 'burnrole' to be provided to this smart contract address on contract configuration.

### Deployment Steps

1. **Upload Concordium Liquid Staking Contract:**
   - Generate `concordium-liquid-staking.wasm.v1` file by running `cargo concordium build --schema-embed --out dist/concordium-staking.wasm.v1 --schema-out dist/concordium-staking-schema.bin` on the project folder.
   
2. **Initialize Contract:**
   - Use the `Initialize Smart Contract` button and provide the necessary parameters including admin account address, Liquid EUROe contract index, and EUROe stablecoin contract index.
   ```json
   {
  "admin": <ADMIN_ACCOUNT_ADDRESS>,
  "liquid_euroe": {
    "index": <LIQUID_EUROE_CONTRAT_INDEX>,
    "subindex": 0
  },
  "token_address": {
    "index": <EUROE_STABLECOIN_CONTRACT_INDEX>,
    "subindex": 0
  }
 }
   ```
3. **Grant Roles to Staking Contract:**
   - Grant 'mintrole' and 'burnrole' to the Staking Contract address on the Liquid EUROe token contract instance.
```json
   {
  "adminrole": {    
    "Account": [
      "3ipmAeMSPvfZdxyoNq8UqETXWxwFCVUwdTXggeNAKdTpo62Sjf"
    ]
  },
  "blockrole": {
    "Account": [
      "3ipmAeMSPvfZdxyoNq8UqETXWxwFCVUwdTXggeNAKdTpo62Sjf"
    ]
  },
  "burnrole": {
        "Contract": [
          {
            "index": 9273,
            "subindex": 0
          }
        ]
  },
  "mintrole": {
     "Contract": [
          {
            "index": 9273,
            "subindex": 0
          }
        ]
  },
  "pauserole": {
    "Account": [
      "3ipmAeMSPvfZdxyoNq8UqETXWxwFCVUwdTXggeNAKdTpo62Sjf"
    ]
  }
 }
```
### UI

- **UI Module:** [GitHub Link](https://github.com/raks0078/DAAPCCD)
- **UI Deployment:** [Vercel App Link](https://daapccd.vercel.app/)

### Wallet and Explorer

- **Concordium Browser Wallet:** [Chrome Web Store](https://chromewebstore.google.com/detail/mnnkpffndmickbiakofclnpoiajlegmg)
- **Explorer Link:** [Testnet Explorer](https://testnet.ccdscan.io/)

### Conclusion

This comprehensive guide provides all the necessary information and steps required for deploying and configuring the Concordium Liquid Staking smart contract along with relevant modules and contracts. For further assistance or inquiries, please refer to the provided links or contact the respective developers.
