//! SPDX-License-Identifier: MIT

use concordium_std::*; // Import Concordium standard library.
use concordium_cis2::*; // Import Concordium CIS-2 library.

/// The initial value of APR
const INITIAL_APR: u64 = 139;

/// The default denominator of APR
const APR_DENOMINATOR: u128 = 1_000_000_00;

/// The ID of the EUROe token
const TOKEN_ID_EUROE: ContractTokenId = TokenIdUnit();

/// Upgrade parameters
#[derive(Serialize, SchemaType)]
pub struct UpgradeParams {
    /// The new module reference.
    pub module: ModuleReference,

    /// Optional entrypoint to call in the new module after upgrade.
    pub migrate: Option<(OwnedEntrypointName, OwnedParameter)>,
}

/// InitContract parameters
#[derive(Serialize, SchemaType)]
pub struct InitContractParams {
    /// The admin role of concordium liquid staking smart contract.
    pub admin: AccountAddress,

    /// Address of liquid EUROe token contract.
    pub liquid_euroe: ContractAddress,

    /// Address of the CIS-2 EUROe token contract.
    pub token_address: ContractAddress,
}

/// Withdraw parameters
#[derive(Serialize, SchemaType)]
pub struct WithdrawEuroEParams {
    /// The address of withdrawable
    withdraw_address: AccountAddress,

    /// The amount to withdraw
    amount: TokenAmountU64,
}

/// Set paused parameters
#[derive(Serialize, SchemaType, Clone)]
#[repr(transparent)]
pub struct SetPausedParams {
    /// Paused state for stopping relevant contract operations.
    pub paused: bool,
}

/// UpdateApr parameters
#[derive(Serialize, SchemaType, Clone)]
pub struct UpdateAprParams {
    /// The new apr value.
    new_apr: u64,
}

/// The parameter for the contract function `mint`
/// which mints an amount of liquid EUROe to a given address.
#[derive(Serialize, SchemaType)]
pub struct MintParams {
    /// The address of owner.
    pub owner: Address,

    /// The amount to mint.
    pub amount: TokenAmountU64,
}

/// The parameter for the contract function `burn`
/// which burns an amount of liquid EUROe to a given address.
#[derive(Serialize, SchemaType)]
pub struct BurnParams {
    /// The amount to burn liquid EUROe.
    pub amount: TokenAmountU64,

    /// The address of user.
    pub burnaddress: Address,
}

/// View results
#[derive(Serialize, SchemaType)]
pub struct ViewResult {
    /// Paused state for stopping relevant contract operations.
    paused: bool,

    /// The admin role of concordium liquid staking smart contract.
    admin: AccountAddress,

    /// Total amount of staked tokens.
    total_staked: TokenAmountU64,

    /// The Apr.
    apr: u64,

    /// Address of liquid EUROe token contract
    liquid_euroe: ContractAddress,

    /// Address of the EUROe token contract.
    token_address: ContractAddress,

    /// The total number of participants
    total_participants: u64,
}

/// Information about a stake.
#[derive(Debug, Serialize, SchemaType, Clone, PartialEq, Eq)]
pub struct StakeInfo {
    /// The staked amount of user.
    pub amount: TokenAmountU64,

    /// Timestamp when the stake was made.
    pub timestamp: u64,
}

/// State of the contract.
#[derive(Serial, DeserialWithState)]
#[concordium(state_parameter = "S")]
struct State<S = StateApi> {
    /// Paused state for stopping relevant contract operations.
    paused: bool,

    /// The admin role of concordium liquid staking smart contract.
    admin: AccountAddress,

    /// The total amount of staked tokens.
    total_staked: TokenAmountU64,

    /// The annual percentage rate.
    apr: u64,

    /// Mapping of staker addresses to their stake info.
    stakes: StateMap<AccountAddress, StakeInfo, S>,

    /// Address of liquid EUROe token contract
    liquid_euroe: ContractAddress,

    /// Address of the EUROe token contract.
    token_address: ContractAddress,

    /// The total number of participants
    total_participants: u64,
}

/// Implementation of state
impl State {
    pub fn get_user_stake(
        &self,
        user: &AccountAddress
    ) -> (TokenAmountU64, u64) {
        self.stakes.get(user).map_or_else(
            || (TokenAmountU64(0), 0),
            |s| (s.amount, s.timestamp)
        )
    }
}

/// The concordium liquid staking smart contract errors.
#[derive(Debug, PartialEq, Eq, Clone, Reject, Serialize, SchemaType)]
pub enum Error {
    /// Failed Parsing The Parameter.
    #[from(ParseError)]
    ParseParams, // -1

    /// Prevent Unauthorized Access
    UnAuthorized, // -2

    /// Invalid Stake Amount
    InvalidStakeAmount, // -3

    /// No Stake Found
    NoStakeFound, // -4

    /// OnlyAccount
    OnlyAccount, // -5

    /// Only Admin Access
    OnlyAdmin, // -6

    /// Raised when the invocation of the cis2 token contract fails.
    InvokeContractError, //-7

    /// Raised when the parsing of the result from the cis2 token contract
    /// fails.
    ParseResult, //-8

    /// Raised when the response of the cis2 token contract is invalid.
    InvalidResponse, //-9

    /// Failed logging: Log is full.
    LogFull, // -10

    /// Failed logging: Log is malformed.
    LogMalformed, // -11

    /// Upgrade failed because the new module does not exist.
    FailedUpgradeMissingModule, // -12

    /// Upgrade failed because the new module does not contain a contract with a
    /// matching name.
    FailedUpgradeMissingContract, // -13

    /// Upgrade failed because the smart contract version of the module is not
    /// supported.
    FailedUpgradeUnsupportedModuleVersion, // -14

    // Contract is paused.
    ContractPaused, // -15

    /// Insufficient funds
    InsufficientFunds, // -16

    /// Raised when someone else than the cis2 token contract invokes the `stake`
    /// entry point.
    NotTokenContract, //-17
}

/// Mapping the logging errors to Error.
impl From<LogError> for Error {
    fn from(le: LogError) -> Self {
        match le {
            LogError::Full => Self::LogFull,
            LogError::Malformed => Self::LogMalformed,
        }
    }
}

/// Mapping Cis2ClientError<Error> to Error.
impl From<Cis2ClientError<Error>> for Error {
    fn from(e: Cis2ClientError<Error>) -> Self {
        match e {
            Cis2ClientError::InvokeContractError(_) =>
                Self::InvokeContractError,
            Cis2ClientError::ParseResult => Self::ParseResult,
            Cis2ClientError::InvalidResponse => Self::InvalidResponse,
        }
    }
}

/// Mapping UpgradeError to Error
impl From<UpgradeError> for Error {
    #[inline(always)]
    fn from(ue: UpgradeError) -> Self {
        match ue {
            UpgradeError::MissingModule => Self::FailedUpgradeMissingModule,
            UpgradeError::MissingContract => Self::FailedUpgradeMissingContract,
            UpgradeError::UnsupportedModuleVersion =>
                Self::FailedUpgradeUnsupportedModuleVersion,
        }
    }
}

/// Mapping of errors related to contract invocations to Error.
impl<T> From<CallContractError<T>> for Error {
    fn from(_cce: CallContractError<T>) -> Self {
        Self::InvokeContractError
    }
}

/// Enum for different event types in the contract.
#[derive(Debug, Serial, Deserial, PartialEq, Eq, SchemaType)]
#[concordium(repr(u8))]
pub enum Event {
    /// Event for when tokens are staked.
    Staked(StakeEvent),

    /// Event for when tokens are unstaked.
    Unstaked(UnstakeEvent),

    /// Event for when rewards are claimed.
    Claimed(ClaimEvent),

    /// Event for when APR is updated.
    AprUpdated(UpdateAprEvent),
}

/// Event structure for staking.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct StakeEvent {
    /// Address of the user who staked.
    user: AccountAddress,

    /// Amount of tokens staked.
    stake_amount: TokenAmountU64,

    /// Timestamp when the stake was made.
    staked_timestamp: u64,
}

/// Event structure for unstaking.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct UnstakeEvent {
    /// Address of the user who unstaked.
    user: AccountAddress,

    /// Amount of tokens unstaked.
    unstaked_amount: TokenAmountU64,

    /// Timestamp when the unstake was made.
    unix_timestamp: u64,

    /// Rewards earned by the user.
    rewards_earned: TokenAmountU64,
}

/// Event structure for claiming rewards.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct ClaimEvent {
    /// Address of the user who claimed rewards.
    user: AccountAddress,

    /// Amount of rewards claimed.
    rewards_claimed: TokenAmountU64,

    /// Timestamp when the claim was made.
    claim_timestamp: u64,
}

/// Event structure for updating APR.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct UpdateAprEvent {
    /// New APR value.
    new_apr: u64,

    /// Timestamp when the APR was updated.
    update_timestamp: u64,
}

/// Contract token ID type. It has to be the `ContractTokenId` from the cis2
/// token contract.
pub type ContractTokenId = TokenIdUnit;

/// ContractResult type.
pub type ContractResult<A> = Result<A, Error>;

/// Initialization function for the contract.
#[init(contract = "concordium_staking", parameter = "InitContractParams")]
fn contract_init(
    ctx: &InitContext,
    state_builder: &mut StateBuilder
) -> InitResult<State> {
    let params: InitContractParams = ctx.parameter_cursor().get()?; // Get token address from parameters.
    let state = State {
        paused: false,
        admin: params.admin,
        total_staked: TokenAmountU64(0), // Initialize total staked to 0.
        total_participants: 0,
        apr: INITIAL_APR, // Set initial APR to 12%.
        stakes: state_builder.new_map(), // Initialize empty stakes map.
        liquid_euroe: params.liquid_euroe,
        token_address: params.token_address, // Set the token address.
    };

    Ok(state) // Return success.
}

/// Receive cis-2 token
#[receive(
    contract = "concordium_staking",
    name = "onReceivingCIS2",
    error = "Error"
)]
fn contract_on_cis2_received<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    _host: &impl HasHost<State, StateApiType = S>
) -> ContractResult<()> {
    Ok(())
}

/// Function to stake tokens.
#[receive(
    contract = "concordium_staking",
    name = "stake",
    parameter = "OnReceivingCis2DataParams<ContractTokenId, TokenAmountU64,AdditionalData>",
    error = "Error",
    mutable,
    enable_logger
)]
fn contract_stake(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    let state = host.state_mut(); // Get the contract state.
    if !ctx.sender().matches_contract(&state.token_address) {
        bail!(Error::NotTokenContract);
    } // Ensure the sender is the cis2 token contract.

    let params: OnReceivingCis2DataParams<
        ContractTokenId,
        TokenAmountU64,
        AdditionalData
    > = ctx.parameter_cursor().get()?; // Get request parameters.

    let sender_address = only_account(&params.from)?; // Ensure that only accounts can stake.
    let unix_timestamp = get_current_timestamp(ctx); // Get the current timestamp.
    let amount = params.amount; // Get the amount to stake.

    ensure!(!state.paused, Error::ContractPaused);
    ensure!(amount.gt(&TokenAmountU64(0)), Error::InvalidStakeAmount);

    let mut sender_stake = state.stakes
        .entry(sender_address)
        .or_insert_with(|| StakeInfo {
            amount: TokenAmountU64(0),
            timestamp: unix_timestamp,
        }); // Update the sender's stake.

    state.total_staked += amount; // Update the total staked amount.
    if sender_stake.amount.eq(&TokenAmountU64(0)) {
        state.total_participants += 1;
    }

    let user_stake_info = sender_stake.clone();
    sender_stake.amount += amount;
    sender_stake.timestamp = unix_timestamp;

    let apr = state.apr;
    drop(sender_stake);

    mint(host, Address::Account(sender_address), amount)?; // Mint same amount of liquid EUROe tokens

    // If previously staked
    if user_stake_info.amount.gt(&TokenAmountU64(0)) {
        let earned_rewards = TokenAmountU64(
            calculate_reward(
                user_stake_info.amount.0,
                user_stake_info.timestamp,
                unix_timestamp,
                apr
            ).into()
        );

        // transfer EUROe tokens
        transfer_euroe_token(
            host,
            Address::Contract(ctx.self_address()),
            Receiver::Account(sender_address),
            earned_rewards,
            true
        )?;
    }

    logger.log(
        &Event::Staked(StakeEvent {
            user: sender_address,
            stake_amount: amount,
            staked_timestamp: unix_timestamp,
        })
    )?; // Log stake event.

    Ok(()) // Return success.
}

/// Function to unstake tokens.
#[receive(
    contract = "concordium_staking",
    name = "unstake",
    error = "Error",
    mutable,
    enable_logger
)]
fn contract_unstake(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    let sender_address = only_account(&ctx.sender())?; // Ensure that only accounts can unstake
    let unix_timestamp = get_current_timestamp(ctx); // Get the current timestamp.

    let state = host.state_mut(); // Get the contract state.
    ensure!(!state.paused, Error::ContractPaused);

    let sender_stake = state.stakes
        .entry(sender_address)
        .occupied_or(Error::NoStakeFound)?; // Ensure the sender has enough staked tokens.
    let unstake_amount = sender_stake.amount;

    let earned_rewards = TokenAmountU64(
        calculate_reward(
            unstake_amount.0,
            sender_stake.timestamp,
            unix_timestamp,
            state.apr
        ).into()
    ); // Calculate rewards.

    drop(sender_stake);
    state.stakes.remove(&sender_address);
    state.total_staked -= unstake_amount; // Update the total staked amount.
    state.total_participants -= 1;

    burn(host, Address::Account(sender_address), unstake_amount)?; // Burn liquid EUROe tokens.

    transfer_euroe_token(
        host,
        Address::Contract(ctx.self_address()),
        Receiver::Account(sender_address),
        unstake_amount + earned_rewards,
        true
    )?; // Transfer EUROe tokens back to the sender along with rewards.

    logger.log(
        &Event::Unstaked(UnstakeEvent {
            user: sender_address,
            unstaked_amount: unstake_amount,
            unix_timestamp,
            rewards_earned: earned_rewards.into(),
        })
    )?; // Log unstake event.

    Ok(()) // Return success.
}

/// Function to claim rewards.
#[receive(
    contract = "concordium_staking",
    name = "claimRewards",
    error = "Error",
    mutable,
    enable_logger
)]
fn contract_claim_rewards(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    let sender_address = only_account(&ctx.sender())?; // Ensure that only accounts can claim rewards
    let unix_timestamp = get_current_timestamp(ctx); // Get the current timestamp.

    let state = host.state_mut();
    ensure!(!state.paused, Error::ContractPaused);

    let mut sender_stake = state.stakes
        .entry(sender_address)
        .occupied_or(Error::NoStakeFound)?;

    let earned_rewards = TokenAmountU64(
        calculate_reward(
            sender_stake.amount.0,
            sender_stake.timestamp,
            unix_timestamp,
            state.apr
        ).into()
    ); // Calculate rewards.

    sender_stake.timestamp = unix_timestamp;
    drop(sender_stake);

    transfer_euroe_token(
        host,
        Address::Contract(ctx.self_address()),
        Receiver::Account(sender_address),
        earned_rewards,
        true
    )?; // Transfer EUROe rewards to the sender

    logger.log(
        &Event::Claimed(ClaimEvent {
            user: sender_address,
            rewards_claimed: earned_rewards,
            claim_timestamp: unix_timestamp,
        })
    )?; // Log claim event.

    Ok(()) // Return success.
}

/// Function to withdraw EUROe stablecoin
/// Access by contract owner only.
#[receive(
    contract = "concordium_staking",
    name = "withdrawEuroe",
    parameter = "WithdrawEuroEParams",
    error = "Error",
    mutable
)]
fn contract_withdraw_euroe(
    ctx: &ReceiveContext,
    host: &mut Host<State>
) -> ContractResult<()> {
    let params: WithdrawEuroEParams = ctx.parameter_cursor().get()?;
    let sender = ctx.sender();
    ensure!(sender.matches_account(&ctx.owner()), Error::UnAuthorized); // Access by contract owner only.

    transfer_euroe_token(
        host,
        Address::Contract(ctx.self_address()),
        Receiver::Account(params.withdraw_address),
        params.amount,
        true
    )?; // transfer EUROe token

    Ok(()) // Return success
}

/// Function to pause or unpause the concordium liquid staking contract
/// Access by contract owner only.
#[receive(
    contract = "concordium_staking",
    name = "setPaused",
    parameter = "SetPausedParams",
    error = "Error",
    mutable
)]
fn contract_set_paused(
    ctx: &ReceiveContext,
    host: &mut Host<State>
) -> ContractResult<()> {
    let params: SetPausedParams = ctx.parameter_cursor().get()?;
    let sender = ctx.sender();
    ensure!(sender.matches_account(&ctx.owner()), Error::UnAuthorized);

    let state = host.state_mut();
    state.paused = params.paused;
    Ok(()) // Return success
}

/// Function to update the APR.
/// Access by contract owner only.
#[receive(
    contract = "concordium_staking",
    name = "updateApr",
    parameter = "UpdateAprParams",
    error = "Error",
    mutable,
    enable_logger
)]
fn update_apr(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    let params: UpdateAprParams = ctx.parameter_cursor().get()?; // Get request parameters.
    let sender = ctx.sender(); // Get the sender's address.

    let update_timestamp = get_current_timestamp(ctx); // Get the current timestamp.
    ensure!(sender.matches_account(&ctx.owner()), Error::UnAuthorized); // Ensure only the contract owner can update the APR
    let state = host.state_mut(); // Get the contract state.

    state.apr = params.new_apr; // Update the APR.
    logger.log(
        &Event::AprUpdated(UpdateAprEvent {
            new_apr: params.new_apr,
            update_timestamp,
        })
    )?; // Log APR update event.

    Ok(()) // Return success
}

/// Upgrade this smart contract instance to a new module and call optionally a
/// migration function after the upgrade.
///
/// It rejects if:
/// - Sender is not the admin of the contract instance.
/// - It fails to parse the parameter.
/// - If the ugrade fails.
/// - If the migration invoke fails.
///
/// This function is marked as `low_level`. This is **necessary** since the
/// high-level mutable functions store the state of the contract at the end of
/// execution. This conflicts with migration since the shape of the state
/// **might** be changed by the migration function. If the state is then written
/// by this function it would overwrite the state stored by the migration
/// function.
#[receive(
    contract = "concordium_staking",
    name = "upgrade",
    parameter = "UpgradeParams",
    error = "Error",
    low_level
)]
fn contract_upgrade(
    ctx: &ReceiveContext,
    host: &mut LowLevelHost
) -> ContractResult<()> {
    let state: State = host.state().read_root()?; // Read the top-level contract state.
    ensure!(ctx.sender().matches_account(&state.admin), Error::OnlyAdmin); // Check that only the admin is authorized to upgrade the smart contract.
    let params: UpgradeParams = ctx.parameter_cursor().get()?; // Parse the parameter.

    host.upgrade(params.module)?; // Trigger the upgrade.
    if let Some((func, parameters)) = params.migrate {
        host.invoke_contract_raw(
            &ctx.self_address(),
            parameters.as_parameter(),
            func.as_entrypoint_name(),
            Amount::zero()
        )?;
    } // Call the migration function if provided.

    Ok(()) // Return success
}

/// Function to retrieve contract state
#[receive(
    contract = "concordium_staking",
    name = "view",
    return_value = "ViewResult"
)]
fn contract_view(
    _ctx: &ReceiveContext,
    host: &Host<State>
) -> ContractResult<ViewResult> {
    let state = host.state();
    Ok(ViewResult {
        paused: state.paused,
        admin: state.admin,
        total_staked: state.total_staked,
        apr: state.apr,
        liquid_euroe: state.liquid_euroe,
        token_address: state.token_address,
        total_participants: state.total_participants,
    }) // Return success
}

/// Function to retrieve specific user stake
#[receive(
    contract = "concordium_staking",
    name = "getStakeInfo",
    parameter = "AccountAddress",
    return_value = "StakeInfo"
)]
fn contract_get_stake_info(
    ctx: &ReceiveContext,
    host: &Host<State>
) -> ContractResult<StakeInfo> {
    let user: AccountAddress = ctx.parameter_cursor().get()?;
    let state = host.state();
    let (amount, timestamp) = state.get_user_stake(&user);

    Ok(StakeInfo {
        amount,
        timestamp,
    }) // Return success
}

/// Function to get earned rewards.
#[receive(
    contract = "concordium_staking",
    name = "getEarnedRewards",
    parameter = "AccountAddress",
    return_value = "u64"
)]
fn get_earned_rewards(
    ctx: &ReceiveContext,
    host: &Host<State>
) -> ContractResult<u64> {
    let user: AccountAddress = ctx.parameter_cursor().get()?;
    let unix_timestamp = get_current_timestamp(ctx); // Get the current timestamp.
    let state = host.state(); // Get the contract state.

    let (amount, timestamp) = state.get_user_stake(&user);
    let earned_rewards = calculate_reward(
        amount.0,
        timestamp,
        unix_timestamp,
        state.apr
    ); // Calculate rewards.

    Ok(earned_rewards) // Return the calculated rewards.
}

/// Validation function to check only account
fn only_account(sender: &Address) -> ContractResult<AccountAddress> {
    match sender {
        Address::Contract(_) => bail!(Error::OnlyAccount),
        Address::Account(account_address) => Ok(*account_address),
    }
}

/// Function to derive current block timestamp
fn get_current_timestamp(ctx: &ReceiveContext) -> u64 {
    ctx.metadata().block_time().millis / 1000
}

/// Function to calculate rewards.
fn calculate_reward(amount: u64, start: u64, end: u64, apr: u64) -> u64 {
    let seconds_passed = end - start;
    (((amount * apr * seconds_passed) as u128) / APR_DENOMINATOR) as u64
}

/// Function to transfer EUROe stablecoin.
fn transfer_euroe_token(
    host: &mut Host<State>,
    from: Address,
    to: Receiver,
    amount: TokenAmountU64,
    before_transfer_check: bool
) -> ContractResult<()> {
    let state = host.state();
    let client = Cis2Client::new(state.token_address);

    if before_transfer_check {
        let contract_balance = client.balance_of::<
            State,
            ContractTokenId,
            TokenAmountU64,
            Error
        >(host, TOKEN_ID_EUROE, from)?;
        ensure!(contract_balance.gt(&amount), Error::InsufficientFunds);
    }

    client.transfer::<State, ContractTokenId, TokenAmountU64, Error>(
        host,
        Transfer {
            amount,
            from,
            to,
            token_id: TOKEN_ID_EUROE,
            data: AdditionalData::empty(),
        }
    )?;

    Ok(())
}

/// Function to mint liquid EUROe.
fn mint(
    host: &mut Host<State>,
    to: Address,
    amount: TokenAmountU64
) -> ContractResult<()> {
    let liquid_euroe = host.state().liquid_euroe;
    let parameter = MintParams {
        owner: to,
        amount,
    };

    host.invoke_contract(
        &liquid_euroe,
        &parameter,
        EntrypointName::new_unchecked("mint"),
        Amount::zero()
    )?;

    Ok(()) // Return success
}

/// Function to burn liquid EUROe.
fn burn(
    host: &mut Host<State>,
    burnaddress: Address,
    amount: TokenAmountU64
) -> ContractResult<()> {
    let liquid_euroe = host.state().liquid_euroe;
    let parameter = BurnParams {
        amount,
        burnaddress,
    };
    host.invoke_contract(
        &liquid_euroe,
        &parameter,
        EntrypointName::new_unchecked("burn"),
        Amount::zero()
    )?;

    Ok(()) // Return success
}
