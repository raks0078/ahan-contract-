//! SPDX-License-Identifier: MIT

use concordium_std::*; // Import Concordium standard library.
use concordium_cis2::*; // Import Concordium CIS-2 library.

/// The initial value of APR
const INITIAL_APR: u64 = 139;

/// The default denominator of APR
const APR_DENOMINATOR: u128 = 1_000_000_00;

/// The ID of the EUROe token
const TOKEN_ID_EUROE: ContractTokenId = TokenIdUnit();

/// List of entrypoints supported by the `permit` function (CIS3)
const SUPPORTS_PERMIT_ENTRYPOINTS: [EntrypointName; 2] = [
    EntrypointName::new_unchecked("unstake"),
    EntrypointName::new_unchecked("claimRewards"),
];

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

/// Unstake parameters
#[derive(Serialize, SchemaType)]
pub struct UnstakeParams {
    /// The EUROe token amount to unstake
    pub amount: TokenAmountU64,
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

    /// The serialized payload.
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
    pub signature: AccountSignatures,

    /// Account that created the above signature.
    pub signer: AccountAddress,
}

/// The parameter type for the contract function `supportsPermit`.
#[derive(Debug, Serialize, SchemaType)]
pub struct SupportsPermitQueryParams {
    /// The list of supportPermit queries.
    #[concordium(size_length = 2)]
    pub queries: Vec<OwnedEntrypointName>,
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

    /// A registry to link an account to its next nonce. The nonce is used to
    /// prevent replay attacks of the signed message. The nonce is increased
    /// sequentially every time a signed message (corresponding to the
    /// account) is successfully executed in the `permit` function. This
    /// mapping keeps track of the next nonce that needs to be used by the
    /// account to generate a signature.
    nonces_registry: StateMap<AccountAddress, u64, S>,
}

/// Implementation of state
impl State {
    /// Get user stake info
    pub fn get_user_stake(
        &self,
        user: &AccountAddress
    ) -> (TokenAmountU64, u64) {
        self.stakes.get(user).map_or_else(
            || (TokenAmountU64(0), 0),
            |s| (s.amount, s.timestamp)
        )
    }

    /// Get currrent nonce of a user
    pub fn get_user_nonce(&self, user: &AccountAddress) -> u64 {
        self.nonces_registry.get(user).map_or_else(
            || 0,
            |n| n.clone()
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

    /// Invalid unstake amount
    InvalidUnstakeAmount,
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
    /// Cis3 event.
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
    /// The nonce that was used in the `PermitMessage`.
    pub nonce: u64,
    /// Account that signed the `PermitMessage`.
    pub account: AccountAddress,
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
        nonces_registry: state_builder.new_map(),
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

/// Verify an ed25519 signature and allow the unstake, claimRewards.
#[receive(
    contract = "concordium_staking",
    name = "permit",
    parameter = "PermitParam",
    error = "Error",
    crypto_primitives,
    mutable,
    enable_logger
)]
fn contract_permit(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger,
    crypto_primitives: &impl HasCryptoPrimitives
) -> ContractResult<()> {
    // Check if the contract is paused.
    ensure!(!host.state().paused, Error::ContractPaused);

    // Parse the parameter.
    let param: PermitParam = ctx.parameter_cursor().get()?;

    // Update the nonce.
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

    ensure_eq!(message.nonce, nonce, Error::NonceMismatch); // Check the nonce to prevent replay attacks.

    ensure_eq!(
        message.contract_address,
        ctx.self_address(),
        Error::WrongContract
    ); // Check that the signature was intended for this contract.

    ensure!(message.timestamp > ctx.metadata().slot_time(), Error::Expired); // Check signature is not expired.

    let message_hash = contract_view_message_hash(
        ctx,
        host,
        crypto_primitives
    )?;

    let valid_signature = host.check_account_signature(
        param.signer,
        &param.signature,
        &message_hash
    )?; // Check signature.

    ensure!(valid_signature, Error::WrongSignature);

    if
        message.entry_point.as_entrypoint_name() ==
        EntrypointName::new_unchecked("unstake")
    {
        let payload: UnstakeParams = from_bytes(&message.payload)?;
        unstake_helper(ctx, host, logger, param.signer, payload.amount)?;
    } else if
        // claim
        message.entry_point.as_entrypoint_name() ==
        EntrypointName::new_unchecked("claimRewards")
    {
        claim_rewards_helper(ctx, host, logger, param.signer)?;
    } else {
        // no entrypoint
        bail!(Error::WrongEntryPoint);
    }

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
    parameter = "UnstakeParams",
    error = "Error",
    mutable,
    enable_logger
)]
fn contract_unstake(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger
) -> ContractResult<()> {
    let param: UnstakeParams = ctx.parameter_cursor().get()?;
    let sender_address = only_account(&ctx.sender())?;
    unstake_helper(ctx, host, logger, sender_address, param.amount)
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
    let sender_address = only_account(&ctx.sender())?;
    claim_rewards_helper(ctx, host, logger, sender_address)
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

/// Get current nonce of a user
#[receive(
    contract = "concordium_staking",
    name = "getUserNonce",
    parameter = "AccountAddress",
    error = "Error",
    return_value = "u64"
)]
fn contract_get_user_nonce(
    ctx: &ReceiveContext,
    host: &Host<State>
) -> ContractResult<u64> {
    let user: AccountAddress = ctx.parameter_cursor().get()?;
    let state = host.state();
    Ok(state.get_user_nonce(&user))
}

/// Helper function that can be invoked at the front-end to serialize the
/// `PermitMessage` before signing it in the wallet.
#[receive(
    contract = "concordium_staking",
    name = "serializationHelper",
    parameter = "PermitMessage"
)]
fn contract_serialization_helper(
    _ctx: &ReceiveContext,
    _host: &Host<State>
) -> ContractResult<()> {
    Ok(())
}

/// Calculates the message hash
/// The contract can only be called by any account
/// Returns message hash
///
/// It rejects if:
/// - It fails to parse the parameter
#[receive(
    contract = "concordium_staking",
    name = "viewMessageHash",
    parameter = "PermitParam",
    return_value = "[u8;32]",
    crypto_primitives
)]
fn contract_view_message_hash<S: HasStateApi>(
    ctx: &ReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>,
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
    let mut message_bytes =
        vec![0; (cursor.size() - cursor.cursor_position()) as usize];

    cursor.read_exact(&mut message_bytes)?;

    // The message signed in the Concordium browser wallet is prepended with the
    // `account` address and 8 zero bytes. Accounts in the Concordium browser wallet
    // can either sign a regular transaction (in that case the prepend is
    // `account` address and the nonce of the account which is by design >= 1)
    // or sign a message (in that case the prepend is `account` address and 8 zero
    // bytes). Hence, the 8 zero bytes ensure that the user does not accidentally
    // sign a transaction. The account nonce is of type u64 (8 bytes).
    let mut msg_prepend = vec![0; 32 + 8];

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

/// Get the entrypoints supported by the `permit` function given a
/// list of entrypoints.
///
/// It rejects if:
/// - It fails to parse the parameter.
#[receive(
    contract = "concordium_staking",
    name = "supportsPermit",
    parameter = "SupportsPermitQueryParams",
    return_value = "SupportsQueryResponse",
    error = "Error"
)]
fn contract_supports_permit<S: HasStateApi>(
    ctx: &ReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>
) -> ContractResult<SupportsQueryResponse> {
    // Parse the parameter.
    let params: SupportsPermitQueryParams = ctx.parameter_cursor().get()?;

    // Build the response.
    let mut response = Vec::with_capacity(params.queries.len());
    for entrypoint in params.queries {
        if
            SUPPORTS_PERMIT_ENTRYPOINTS.contains(
                &entrypoint.as_entrypoint_name()
            )
        {
            response.push(SupportResult::Support);
        } else {
            response.push(SupportResult::NoSupport);
        }
    }
    let result = SupportsQueryResponse::from(response);
    Ok(result)
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
    return_value = "StakeInfo",
    error = "Error"
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
    return_value = "u64",
    error = "Error"
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

//  ## HELPER FUNCTIONS ##

fn unstake_helper(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger,
    sender_address: AccountAddress,
    amount: TokenAmountU64
) -> ContractResult<()> {
    let unix_timestamp = get_current_timestamp(ctx); // Get the current timestamp.

    let state = host.state_mut(); // Get the contract state.
    ensure!(!state.paused, Error::ContractPaused);

    let mut sender_stake = state.stakes
        .entry(sender_address)
        .occupied_or(Error::NoStakeFound)?; // Ensure the sender has enough staked tokens.

    let staked_amount = sender_stake.amount;
    ensure!(staked_amount.0 >= amount.0, Error::InvalidUnstakeAmount); // ensure the unstake amount

    let earned_rewards = TokenAmountU64(
        calculate_reward(
            amount.0,
            sender_stake.timestamp,
            unix_timestamp,
            state.apr
        ).into()
    ); // Calculate rewards.

    sender_stake.amount -= amount;
    drop(sender_stake);

    if amount.eq(&staked_amount) {
        state.stakes.remove(&sender_address);
        state.total_participants -= 1;
    }

    state.total_staked -= amount; // Update the total staked amount.

    burn(host, Address::Account(sender_address), amount)?; // Burn liquid EUROe tokens.

    transfer_euroe_token(
        host,
        Address::Contract(ctx.self_address()),
        Receiver::Account(sender_address),
        amount + earned_rewards,
        true
    )?; // Transfer EUROe tokens back to the sender along with rewards.

    logger.log(
        &Event::Unstaked(UnstakeEvent {
            user: sender_address,
            unstaked_amount: amount,
            unix_timestamp,
            rewards_earned: earned_rewards.into(),
        })
    )?; // Log unstake event.

    Ok(()) // Return success.
}

fn claim_rewards_helper(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut Logger,
    sender_address: AccountAddress
) -> ContractResult<()> {
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
