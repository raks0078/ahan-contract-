use concordium_std::*; // Import Concordium standard library.
use concordium_cis2::*; // Import Concordium CIS-2 library.

/// Initial APR
pub const INITIAL_APR: u64 = 139;

/// Denominator of APR
pub const APR_DENOMINATOR: u64 = 1_000_000_00;

/// Upgrade params
#[derive(Serialize, SchemaType)]
pub struct UpgradeParams {
    /// The new module reference.
    pub module: ModuleReference,
    /// Optional entrypoint to call in the new module after upgrade.
    pub migrate: Option<(OwnedEntrypointName, OwnedParameter)>,
}

/// Request structure for contract initialization
#[derive(Serialize, SchemaType, Clone)]
pub struct InitContractParams {
    /// The admin role of concordium liquid staking smart contract.
    admin: AccountAddress,

    /// Address of the CIS-2 EuroE token contract.
    token_address: ContractAddress,

    /// The token Id
    token_id: ContractTokenId,
}

/// Request structure for staking tokens.
#[derive(Serialize, SchemaType, Clone)]
pub struct StakeRequest {
    /// Amount of tokens to stake.
    amount: u64,
}

/// Request structure for updating APR.
#[derive(Serialize, SchemaType, Clone)]
pub struct UpdateAprRequest {
    /// The new apr value.
    new_apr: u64,
}

/// Information about a stake.
#[derive(Debug, Serialize, SchemaType, Clone, PartialEq, Eq)]
pub struct StakeInfo {
    /// The staked amount of user.
    amount: TokenAmountU64,

    /// Timestamp when the stake was made.
    timestamp: u64,
}

/// State of the contract.
#[derive(Serial, DeserialWithState)]
#[concordium(state_parameter = "S")]
struct State<S = StateApi> {
    /// The admin role of concordium liquid staking smart contract.
    admin: AccountAddress,

    /// Total amount of staked tokens.
    total_staked: TokenAmountU64,

    /// The annual percentage rate.
    apr: u64,

    /// Mapping of staker addresses to their stake info.
    stakes: StateMap<AccountAddress, StakeInfo, S>,

    /// Address of the CIS-2 EuroE token contract.
    token_address: ContractAddress,

    /// The token Id
    token_id: TokenIdU8,
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

    /// Already Staked
    AlreadyStaked, // -5,

    /// CIS Transfer Failed
    Cis2TransferFailed, // -6

    /// OnlyAccount
    OnlyAccount, // -7

    /// Only Admin Access
    OnlyAdmin, // -8

    /// Raised when the invocation of the cis2 token contract fails.
    InvokeContractError, //-9

    /// Raised when the parsing of the result from the cis2 token contract
    /// fails.
    ParseResult, //-10

    /// Raised when the response of the cis2 token contract is invalid.
    InvalidResponse, //-11

    /// Failed logging: Log is full.
    LogFull, // -12

    /// Failed logging: Log is malformed.
    LogMalformed, // -13
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
            Cis2ClientError::InvokeContractError(_) => Self::InvokeContractError,
            Cis2ClientError::ParseResult => Self::ParseResult,
            Cis2ClientError::InvalidResponse => Self::InvalidResponse,
        }
    }
}

/// Enum for different event types in the contract.
#[derive(Debug, Serial, Deserial, PartialEq, Eq, SchemaType)]
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
pub type ContractTokenId = TokenIdU8;

/// ContractResult type
pub type ContractResult<A> = Result<A, Error>;

/// Initialization function for the contract.
#[init(contract = "concordium_staking", parameter = "InitContractParams")]
fn contract_init(ctx: &InitContext, state_builder: &mut StateBuilder) -> InitResult<State> {
    let params: InitContractParams = ctx.parameter_cursor().get()?; // Get token address from parameters.
    let state = State {
        admin: params.admin,
        total_staked: TokenAmountU64(0), // Initialize total staked to 0.
        apr: INITIAL_APR, // Set initial APR to 12%.
        stakes: state_builder.new_map(), // Initialize empty stakes map.
        token_address: params.token_address, // Set the token address.
        token_id: params.token_id,
    };
    Ok(state) // Return success.
}

/// Function to stake tokens.
#[receive(
    contract = "concordium_staking",
    name = "stake",
    parameter = "StakeRequest",
    mutable,
    enable_logger
)]
fn stake(ctx: &ReceiveContext, host: &mut Host<State>, logger: &mut Logger) -> ContractResult<()> {
    let params: StakeRequest = ctx.parameter_cursor().get()?; // Get request parameters.

    // Ensure that only accounts can stake.
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(Error::OnlyAccount.into()),
        Address::Account(account_address) => account_address,
    };

    let unix_timestamp = ctx.metadata().block_time().millis / 1000; // Get the current timestamp.

    let state = host.state_mut(); // Get the contract state.
    let amount = params.amount; // Get the amount to stake.

    ensure!(amount > 0, Error::InvalidStakeAmount);

    // Update the total staked amount.
    state.total_staked += TokenAmountU64(amount.into());

    // Update the sender's stake.
    let mut sender_stake = state.stakes
        .entry(sender_address)
        .or_insert_with(|| StakeInfo { amount: TokenAmountU64(0), timestamp: unix_timestamp });

    ensure_eq!(sender_stake.amount, TokenAmountU64(0), Error::AlreadyStaked);

    sender_stake.amount = TokenAmountU64(amount.into());
    sender_stake.timestamp = unix_timestamp;
    drop(sender_stake);

    // Transfer EuroE tokens to the staking contract.
    cis2_transfer(
        host,
        Address::Account(sender_address),
        Receiver::Contract(
            ctx.self_address(),
            OwnedEntrypointName::new_unchecked("transfer".to_string())
        ),
        TokenAmountU64(amount.into())
    )?;

    // Mint liquid EuroE tokens (represented here as a simple balance update).
    /* let minted_tokens = amount; // 1:1 ratio for simplicity.
    let sender_liquid_balance = host.invoke_contract(sender);
    host.update_balance(sender, sender_liquid_balance + minted_tokens)?; */

    // Log stake event.
    logger.log(
        &Event::Staked(StakeEvent {
            user: sender_address,
            stake_amount: amount.into(),
            staked_timestamp: unix_timestamp,
        })
    )?;

    Ok(()) // Return success.
}

/// Function to unstake tokens.
#[receive(contract = "concordium_staking", name = "unstake", mutable, enable_logger)]
fn unstake(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    // Ensure that only accounts can unstake
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(Error::OnlyAccount.into()),
        Address::Account(account_address) => account_address,
    };

    let unix_timestamp = ctx.metadata().block_time().millis / 1000; // Get the current timestamp.

    let state = host.state_mut(); // Get the contract state.
    // Ensure the sender has enough staked tokens.

    let sender_stake = state.stakes.entry(sender_address).occupied_or(Error::NoStakeFound)?;
    let unstake_amount = sender_stake.amount;

    // Calculate rewards.
    let earned_rewards = TokenAmountU64(
        calculate_reward(unstake_amount.0, sender_stake.timestamp, unix_timestamp, state.apr).into()
    );

    drop(sender_stake);
    state.stakes.remove(&sender_address);

    // Update the total staked amount.
    state.total_staked -= unstake_amount;

    // Burn liquid EuroE tokens.
    /* let sender_liquid_balance = host.balance(sender);
    host.update_balance(sender, sender_liquid_balance - amount)?; */

    // Transfer EuroE tokens back to the sender along with rewards.
    cis2_transfer(
        host,
        Address::Contract(ctx.self_address()),
        Receiver::Account(sender_address),
        unstake_amount + earned_rewards
    )?;

    // Log unstake event.
    logger.log(
        &Event::Unstaked(UnstakeEvent {
            user: sender_address,
            unstaked_amount: unstake_amount,
            unix_timestamp,
            rewards_earned: earned_rewards.into(),
        })
    )?;

    Ok(()) // Return success.
}

/// Function to claim rewards.
#[receive(contract = "concordium_staking", name = "claimRewards", mutable, enable_logger)]
fn claim_rewards(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    // Ensure that only accounts can claim rewards
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(Error::OnlyAccount.into()),
        Address::Account(account_address) => account_address,
    };

    // Get the current timestamp.
    let unix_timestamp = ctx.metadata().block_time().millis / 1000;

    let state = host.state_mut();
    let mut sender_stake = state.stakes.entry(sender_address).occupied_or(Error::NoStakeFound)?;

    // Calculate rewards.
    let earned_rewards = TokenAmountU64(
        calculate_reward(
            sender_stake.amount.0,
            sender_stake.timestamp,
            unix_timestamp,
            state.apr
        ).into()
    );

    sender_stake.timestamp = unix_timestamp;
    drop(sender_stake);

    // Transfer rewards to the sender
    cis2_transfer(
        host,
        Address::Contract(ctx.self_address()),
        Receiver::Account(sender_address),
        earned_rewards
    )?;

    // Log claim event.
    logger.log(
        &Event::Claimed(ClaimEvent {
            user: sender_address,
            rewards_claimed: earned_rewards,
            claim_timestamp: unix_timestamp,
        })
    )?;

    Ok(()) // Return success.
}

/// Function to get earned rewards.
#[receive(contract = "concordium_staking", name = "getEarnedRewards", return_value = "u64")]
fn get_earned_rewards(ctx: &ReceiveContext, host: &Host<State>) -> ReceiveResult<u64> {
    let sender_address: AccountAddress = match ctx.sender() {
        Address::Contract(_) => bail!(Error::OnlyAccount.into()),
        Address::Account(account_address) => account_address,
    };
    let unix_timestamp = ctx.metadata().block_time().millis / 1000; // Get the current timestamp.

    let state = host.state(); // Get the contract state.
    let sender_stake = state.stakes.get(&sender_address).unwrap();

    // Calculate rewards.
    let earned_rewards = calculate_reward(
        sender_stake.amount.0,
        sender_stake.timestamp,
        unix_timestamp,
        state.apr
    );

    Ok(earned_rewards) // Return the calculated rewards.
}

/// Function to update the APR.
#[receive(
    contract = "concordium_staking",
    name = "updateApr",
    parameter = "UpdateAprRequest",
    mutable,
    enable_logger
)]
fn update_apr(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ReceiveResult<()> {
    let params: UpdateAprRequest = ctx.parameter_cursor().get()?; // Get request parameters.
    let sender = ctx.sender(); // Get the sender's address.
    let now = ctx.metadata().block_time(); // Get the current timestamp.

    // Ensure only the contract owner can update the APR
    ensure!(sender.matches_account(&ctx.owner()), Error::UnAuthorized.into());

    let state = host.state_mut(); // Get the contract state.
    state.apr = params.new_apr; // Update the APR.

    // Log APR update event.
    logger.log(
        &Event::AprUpdated(UpdateAprEvent {
            new_apr: params.new_apr,
            update_timestamp: now.millis,
        })
    )?;

    Ok(()) // Return success.
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
    contract = "smart_contract_upgrade",
    name = "upgrade",
    parameter = "UpgradeParams",
    error = "CustomContractError",
    low_level
)]
fn contract_upgrade(ctx: &ReceiveContext, host: &mut LowLevelHost) -> ContractResult<()> {
    // Read the top-level contract state.
    let state: State = host.state().read_root()?;

    // Check that only the admin is authorized to upgrade the smart contract.
    ensure!(ctx.sender().matches_account(&state.admin), Error::OnlyAdmin);

    // Parse the parameter.
    let params: UpgradeParams = ctx.parameter_cursor().get()?;

    // Trigger the upgrade.
    host.upgrade(params.module).unwrap();

    // Call the migration function if provided.
    if let Some((func, parameters)) = params.migrate {
        host.invoke_contract_raw(
            &ctx.self_address(),
            parameters.as_parameter(),
            func.as_entrypoint_name(),
            Amount::zero()
        ).unwrap();
    }
    Ok(())
}

/// Function to calculate rewards.
fn calculate_reward(amount: u64, start: u64, end: u64, apr: u64) -> u64 {
    let seconds_passed = end - start;
    (amount * apr * seconds_passed) / APR_DENOMINATOR
}

/// Function to transfer CIS-2 tokens.
fn cis2_transfer(
    host: &mut Host<State>,
    from: Address,
    to: Receiver,
    amount: TokenAmountU64
) -> ContractResult<()> {
    let client = Cis2Client::new(host.state.token_address);

    client.transfer::<State, TokenIdU8, TokenAmountU64, Error>(host, Transfer {
        amount,
        from,
        to,
        token_id: host.state.token_id,
        data: AdditionalData::empty(),
    })?;

    Ok(())
}
