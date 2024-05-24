//! SPDX-License-Identifier: MIT

use concordium_std::*; // Import Concordium standard library.
use concordium_cis2::*; // Import Concordium CIS-2 library.

/// Initial APR
const INITIAL_APR: u64 = 139;

/// Denominator of APR
const APR_DENOMINATOR: u64 = 1_000_000_00;

/// List of supported entrypoints by the `permit` function (CIS3 standard).
const _SUPPORTS_PERMIT_ENTRYPOINTS: [EntrypointName; 4] = [
    EntrypointName::new_unchecked("stake"),
    EntrypointName::new_unchecked("unstake"),
    EntrypointName::new_unchecked("claim_rewards"),
    EntrypointName::new_unchecked("updateOperator"),
];

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

    /// Address of liquid Euroe token contract
    liquid_euroe: ContractAddress,

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

/// Part of the parameter type for the contract function `permit`.
/// Specifies the message that is signed.
#[derive(SchemaType, Serialize)]
pub struct PermitMessage {
    /// The contract_address that the signature is intended for.
    pub contract_address: ContractAddress,
    /// A nonce to prevent replay attacks.
    pub nonce: u64,
    /// A timestamp to make signatures expire.
    pub timestamp: Timestamp,
    /// The entry_point that the signature is intended for.
    pub entry_point: OwnedEntrypointName,
    /// The serialized payload that should be forwarded to either the `transfer`
    /// or the `updateOperator` function.
    #[concordium(size_length = 2)]
    pub payload: Vec<u8>,
}
/// The parameter type for the contract function `permit`.
/// Takes a signature, the signer, and the message that was signed.
#[derive(Serialize, SchemaType)]
pub struct PermitParam {
    /// Signature/s. The CIS3 standard supports multi-sig accounts.
    pub signature: AccountSignatures,
    /// Account that created the above signature.
    pub signer: AccountAddress,
    /// Message that was signed.
    pub message: PermitMessage,
}

#[derive(Serialize)]
pub struct PermitParamPartial {
    /// Signature/s. The CIS3 standard supports multi-sig accounts.
    signature: AccountSignatures,
    /// Account that created the above signature.
    signer: AccountAddress,
}

/// The parameter for the contract function `mint` which mints an amount of EUROe to a given address.
#[derive(Serial, Deserial, SchemaType)]
pub struct MintParams {
    pub owner: Address,
    pub amount: TokenAmountU64,
}

#[derive(Serial, Deserial, SchemaType)]
pub struct BurnParams {
    pub amount: TokenAmountU64,
    pub burnaddress: Address,
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
    /// Paused state for stopping relevant contract operations.
    paused: bool,

    /// The admin role of concordium liquid staking smart contract.
    admin: AccountAddress,

    /// Total amount of staked tokens.
    total_staked: TokenAmountU64,

    /// The annual percentage rate.
    apr: u64,

    /// Mapping of staker addresses to their stake info.
    stakes: StateMap<AccountAddress, StakeInfo, S>,

    /// Address of liquid Euroe token contract
    liquid_euroe: ContractAddress,

    /// Address of the CIS-2 EuroE token contract.
    token_address: ContractAddress,

    /// The token Id
    token_id: TokenIdU8,

    /// A registry to link an account to its next nonce. The nonce is used to
    /// prevent replay attacks of the signed message. The nonce is increased
    /// sequentially every time a signed message (corresponding to the
    /// account) is successfully executed in the `permit` function. This
    /// mapping keeps track of the next nonce that needs to be used by the
    /// account to generate a signature.
    nonces_registry: StateMap<AccountAddress, u64, S>,
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

    /// Upgrade failed because the new module does not exist.
    FailedUpgradeMissingModule, // -14

    /// Upgrade failed because the new module does not contain a contract with a
    /// matching name.
    FailedUpgradeMissingContract, // -15

    /// Upgrade failed because the smart contract version of the module is not
    /// supported.
    FailedUpgradeUnsupportedModuleVersion, // -16

    // Contract is paused.
    ContractPaused, // -17

    /// Failed to verify signature because signer account does not exist on
    /// chain.
    MissingAccount, // -18

    /// Failed to verify signature because data was malformed.
    MalformedData, // -19

    /// Failed signature verification: Invalid signature.
    WrongSignature, // -20

    /// Failed signature verification: A different nonce is expected.
    NonceMismatch, // -21

    /// Failed signature verification: Signature was intended for a different
    /// contract.
    WrongContract, // -22

    /// Failed signature verification: Signature was intended for a different
    /// entry_point.
    WrongEntryPoint, // -23

    /// Failed signature verification: Signature is expired.
    Expired, // -24
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

/// Mapping UpgradeError to Error
impl From<UpgradeError> for Error {
    #[inline(always)]
    fn from(ue: UpgradeError) -> Self {
        match ue {
            UpgradeError::MissingModule => Self::FailedUpgradeMissingModule,
            UpgradeError::MissingContract => Self::FailedUpgradeMissingContract,
            UpgradeError::UnsupportedModuleVersion => Self::FailedUpgradeUnsupportedModuleVersion,
        }
    }
}

/// Mapping of errors related to contract invocations to CustomContractError.
impl<T> From<CallContractError<T>> for Error {
    fn from(_cce: CallContractError<T>) -> Self {
        Self::InvokeContractError
    }
}

/// Mapping account signature error to CustomContractError
impl From<CheckAccountSignatureError> for Error {
    fn from(e: CheckAccountSignatureError) -> Self {
        match e {
            CheckAccountSignatureError::MissingAccount => Self::MissingAccount,
            CheckAccountSignatureError::MalformedData => Self::MalformedData,
        }
    }
}

/// Enum for different event types in the contract.
#[derive(Debug, Serial, Deserial, PartialEq, Eq)]
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

    /// The event tracks the nonce used by the signer of the `PermitMessage`
    /// whenever the `permit` function is invoked.
    #[concordium(tag = 250)]
    Nonce(NonceEvent),
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

/// The NonceEvent is logged when the `permit` function is invoked. The event
/// tracks the nonce used by the signer of the `PermitMessage`.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct NonceEvent {
    /// Account that signed the `PermitMessage`.
    pub account: AccountAddress,
    /// The nonce that was used in the `PermitMessage`.
    pub nonce: u64,
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
        paused: false,
        admin: params.admin,
        total_staked: TokenAmountU64(0), // Initialize total staked to 0.
        apr: INITIAL_APR, // Set initial APR to 12%.
        stakes: state_builder.new_map(), // Initialize empty stakes map.
        liquid_euroe: params.liquid_euroe,
        token_address: params.token_address, // Set the token address.
        token_id: params.token_id,
        nonces_registry: state_builder.new_map(),
    };

    Ok(state) // Return success.
}

/// Helper function to calculate the `message_hash`.
#[receive(
    contract = "concordium_staking",
    name = "viewMessageHash",
    parameter = "PermitParam",
    return_value = "[u8;32]",
    error = "Error",
    crypto_primitives,
    mutable
)]
fn contract_view_message_hash(
    ctx: &ReceiveContext,
    _host: &mut Host<State>,
    crypto_primitives: &impl HasCryptoPrimitives
) -> ContractResult<[u8; 32]> {
    // Parse the parameter.
    let mut cursor = ctx.parameter_cursor();
    // The input parameter is `PermitParam` but we only read the initial part of it
    // with `PermitParamPartial`. I.e. we read the `signature` and the
    // `signer`, but not the `message` here.
    let param: PermitParamPartial = cursor.get()?;

    // The input parameter is `PermitParam` but we have only read the initial part
    // of it with `PermitParamPartial` so far. We read in the `message` now.
    // `(cursor.size() - cursor.cursor_position()` is the length of the message in
    // bytes.
    let mut message_bytes = vec![0; (cursor.size() - cursor.cursor_position()) as usize];

    cursor.read_exact(&mut message_bytes)?;

    // The message signed in the Concordium browser wallet is prepended with the
    // `account` address and 8 zero bytes. Accounts in the Concordium browser wallet
    // can either sign a regular transaction (in that case the prepend is
    // `account` address and the nonce of the account which is by design >= 1)
    // or sign a message (in that case the prepend is `account` address and 8 zero
    // bytes). Hence, the 8 zero bytes ensure that the user does not accidentally
    // sign a transaction. The account nonce is of type u64 (8 bytes).
    let mut msg_prepend = [0; 32 + 8];
    // Prepend the `account` address of the signer.
    msg_prepend[0..32].copy_from_slice(param.signer.as_ref());

    // Prepend 8 zero bytes.
    msg_prepend[32..40].copy_from_slice(&[0u8; 8]);

    // Calculate the message hash.
    let message_hash = crypto_primitives.hash_sha2_256(
        &[&msg_prepend[0..40], &message_bytes].concat()
    ).0;

    Ok(message_hash)
}

/// Verify an ed25519 signature and allow user to stake, unstake & claim rewards
/// Euroe stablecoin
/// In case of a `stake` action:
/// Logs a `StakeEvent` event
///
/// In case of a `unstake` action:
/// Logs an `UnstakeEvent` event.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - The contract is paused.
/// - The sender is blocked.
/// - A different nonce is expected.
/// - The signature was intended for a different contract.
/// - The signature was intended for a different `entry_point`.
/// - The signature is expired.
/// - The signature can not be validated.
/// - Fails to log event.
#[receive(
    contract = "concordium_staking",
    name = "permit",
    parameter = "PermitParam",
    crypto_primitives,
    mutable,
    enable_logger
)]
fn contract_permit(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut impl HasLogger,
    crypto_primitives: &impl HasCryptoPrimitives
) -> ContractResult<()> {
    // Check if the contract is paused.
    ensure!(!host.state().paused, Error::ContractPaused);

    // Parse the parameter.
    let param: PermitParam = ctx.parameter_cursor().get()?;

    let mut entry = host
        .state_mut()
        .nonces_registry.entry(param.signer)
        .or_insert_with(|| 0);

    // Get the current nonce.
    let nonce = *entry;

    // Bump nonce.
    *entry += 1;
    drop(entry);

    let message = param.message;

    // Check the nonce to prevent replay attacks.
    ensure_eq!(message.nonce, nonce, Error::NonceMismatch);

    // Check that the signature was intended for this contract.
    ensure_eq!(message.contract_address, ctx.self_address(), Error::WrongContract);

    // Check signature is not expired.
    ensure!(message.timestamp > ctx.metadata().slot_time(), Error::Expired);

    let message_hash = contract_view_message_hash(ctx, host, crypto_primitives)?;

    // Check signature.
    let valid_signature = host.check_account_signature(
        param.signer,
        &param.signature,
        &message_hash
    )?;

    ensure!(valid_signature, Error::WrongSignature);

    /* if message.entry_point.as_entrypoint_name() == EntrypointName::new_unchecked("stake") {
        Ok(());
    } else if message.entry_point.as_entrypoint_name() == EntrypointName::new_unchecked("unstake") {
        Ok(());
    } else {
        bail!(Error::WrongEntryPoint);
    } */

    // Log the nonce event.
    logger.log(
        &Event::Nonce(NonceEvent {
            account: param.signer,
            nonce,
        })
    )?;

    Ok(())
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

    // Mint liquid EuroE tokens
    mint(host, Address::Account(sender_address), TokenAmountU64(amount.into()))?;

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
    burn(host, Address::Account(sender_address), unstake_amount)?;

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
    contract = "concordium_staking",
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
    host.upgrade(params.module)?;

    // Call the migration function if provided.
    if let Some((func, parameters)) = params.migrate {
        host.invoke_contract_raw(
            &ctx.self_address(),
            parameters.as_parameter(),
            func.as_entrypoint_name(),
            Amount::zero()
        )?;
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

/// Function to mint liquid-Euroe
fn mint(host: &mut Host<State>, to: Address, amount: TokenAmountU64) -> ContractResult<()> {
    let le = host.state().liquid_euroe;
    let parameter = to_bytes(
        &(MintParams {
            owner: to,
            amount,
        })
    );
    host.invoke_contract(&le, &parameter, EntrypointName::new_unchecked("mint"), Amount::zero())?;

    Ok(())
}

/// Function to burn liquid-Euroe
fn burn(
    host: &mut Host<State>,
    burnaddress: Address,
    amount: TokenAmountU64
) -> ContractResult<()> {
    let le = host.state().liquid_euroe;
    let parameter = to_bytes(
        &(BurnParams {
            amount,
            burnaddress,
        })
    );
    host.invoke_contract(&le, &parameter, EntrypointName::new_unchecked("burn"), Amount::zero())?;

    Ok(())
}
