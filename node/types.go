package node

import (
	"fmt"
	"math/big"
	"net/http"
)

type BigInt struct {
	*big.Int
}

func NewBigInt(val int64) *BigInt {
	return &BigInt{big.NewInt(val)}
}

func (b *BigInt) UnmarshalJSON(data []byte) error {
	if b.Int == nil {
		b.Int = new(big.Int)
	}

	str := string(data)

	if str == "null" {
		return nil
	}

	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}

	if _, ok := b.SetString(str, 10); !ok {
		return fmt.Errorf("cannot parse %q as big integer", str)
	}

	return nil
}

func (b *BigInt) MarshalJSON() ([]byte, error) {
	if b.Int == nil {
		return []byte("null"), nil
	}
	return []byte(b.Int.String()), nil
}

func (b *BigInt) String() string {
	if b.Int == nil {
		return "0"
	}
	return b.Int.String()
}

// Config holds the configuration for the NodeProvider.
type Config struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NodeProvider is the client for interacting with the Ergo Node API.
type NodeProvider struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

type (
	TransactionBoxID   string
	TransactionID      string
	ModifierID         string
	Digest32           string
	HexString          string
	ErgoTree           string
	ErgoAddress        string
	ADDigest           string
	SerializedAdProof  string
	SpendingProofBytes string
	SValue             string
	Votes              string
	DlogSecret         string
	Version            int8
	Timestamp          int64
)

type WalletInteraction string

const (
	WalletInteractionOff    WalletInteraction = "off"
	WalletInteractionShared WalletInteraction = "shared"
	WalletInteractionForced WalletInteraction = "forced"
)

// ErgoTransactionInput represents a transaction input.
type ErgoTransactionInput struct {
	BoxID         TransactionBoxID `json:"boxId"`
	SpendingProof SpendingProof    `json:"spendingProof"`
}

// ErgoTransactionDataInput represents a transaction data input.
type ErgoTransactionDataInput struct {
	BoxID TransactionBoxID `json:"boxId"`
}

// ErgoTransactionUnsignedInput represents an unsigned transaction input.
type ErgoTransactionUnsignedInput struct {
	BoxID     TransactionBoxID  `json:"boxId"`
	Extension map[string]SValue `json:"extension,omitempty"`
}

// SpendingProof contains the proof bytes and context extension.
type SpendingProof struct {
	ProofBytes SpendingProofBytes `json:"proofBytes"`
	Extension  map[string]SValue  `json:"extension"`
}

// ErgoTransactionOutput represents a transaction output.
type ErgoTransactionOutput struct {
	BoxID               *TransactionBoxID `json:"boxId,omitempty"`
	Value               int64             `json:"value"`
	ErgoTree            ErgoTree          `json:"ergoTree"`
	CreationHeight      int32             `json:"creationHeight"`
	Assets              []Asset           `json:"assets,omitempty"`
	AdditionalRegisters Registers         `json:"additionalRegisters"`
	TransactionID       *TransactionID    `json:"transactionId,omitempty"`
	Index               *int32            `json:"index,omitempty"`
}

// Asset represents a token in a transaction.
type Asset struct {
	TokenID TokenID `json:"tokenId"`
	Amount  int64   `json:"amount"`
}

// TokenID is an alias for Digest32, used for token identifiers.
type TokenID = Digest32

// Registers holds the additional registers for a box.
type Registers map[string]SValue

// ErgoTransaction represents a signed Ergo transaction.
type ErgoTransaction struct {
	ID         *TransactionID             `json:"id,omitempty"`
	Inputs     []ErgoTransactionInput     `json:"inputs"`
	DataInputs []ErgoTransactionDataInput `json:"dataInputs"`
	Outputs    []ErgoTransactionOutput    `json:"outputs"`
	Size       *int32                     `json:"size,omitempty"`
}

// UnsignedErgoTransaction represents an unsigned Ergo transaction.
type UnsignedErgoTransaction struct {
	ID         *TransactionID                 `json:"id,omitempty"`
	Inputs     []ErgoTransactionUnsignedInput `json:"inputs"`
	DataInputs []ErgoTransactionDataInput     `json:"dataInputs"`
	Outputs    []ErgoTransactionOutput        `json:"outputs"`
}

// NodeInfo contains information about the node's state and configuration.
type NodeInfo struct {
	Name                  string      `json:"name"`
	AppVersion            string      `json:"appVersion"`
	FullHeight            *int32      `json:"fullHeight"`
	HeadersHeight         *int32      `json:"headersHeight"`
	MaxPeerHeight         *int32      `json:"maxPeerHeight"`
	BestFullHeaderID      *ModifierID `json:"bestFullHeaderId"`
	PreviousFullHeaderID  *ModifierID `json:"previousFullHeaderId"`
	BestHeaderID          *ModifierID `json:"bestHeaderId"`
	StateRoot             *ADDigest   `json:"stateRoot"`
	StateType             string      `json:"stateType"`
	StateVersion          *ModifierID `json:"stateVersion"`
	IsMining              bool        `json:"isMining"`
	PeersCount            int32       `json:"peersCount"`
	UnconfirmedCount      int32       `json:"unconfirmedCount"`
	Difficulty            *int64      `json:"difficulty"` // Using int64 as it can be a BigInt
	CurrentTime           Timestamp   `json:"currentTime"`
	LaunchTime            Timestamp   `json:"launchTime"`
	HeadersScore          *BigInt     `json:"headersScore"`    // Using BigInt for very large numbers
	FullBlocksScore       *BigInt     `json:"fullBlocksScore"` // Using BigInt for very large numbers
	GenesisBlockID        *ModifierID `json:"genesisBlockId"`
	Parameters            Parameters  `json:"parameters"`
	Eip27Supported        *bool       `json:"eip27Supported,omitempty"`
	Eip37Supported        *bool       `json:"eip37Supported,omitempty"`
	RestApiUrl            *string     `json:"restApiUrl,omitempty"`
	Network               *string     `json:"network,omitempty"`
	IsExplorer            *bool       `json:"isExplorer,omitempty"`
	LastMemPoolUpdateTime *Timestamp  `json:"lastMemPoolUpdateTime,omitempty"`
	LastSeenMessageTime   *Timestamp  `json:"lastSeenMessageTime,omitempty"`
}

// Parameters defines system parameters.
type Parameters struct {
	Height           int32   `json:"height"`
	BlockVersion     Version `json:"blockVersion"`
	StorageFeeFactor int32   `json:"storageFeeFactor"`
	MinValuePerByte  int32   `json:"minValuePerByte"`
	MaxBlockSize     int32   `json:"maxBlockSize"`
	MaxBlockCost     int32   `json:"maxBlockCost"`
	TokenAccessCost  int32   `json:"tokenAccessCost"`
	InputCost        int32   `json:"inputCost"`
	DataInputCost    int32   `json:"dataInputCost"`
	OutputCost       int32   `json:"outputCost"`
}

// ApiError represents a standard error response from the API.
type ApiError struct {
	Error  int     `json:"error"`
	Reason string  `json:"reason"`
	Detail *string `json:"detail"`
}

// FullBlock represents a block with header and transactions.
type FullBlock struct {
	Header            BlockHeader       `json:"header"`
	BlockTransactions BlockTransactions `json:"blockTransactions"`
	AdProofs          *BlockADProofs    `json:"adProofs"` // Nullable in some contexts
	Extension         Extension         `json:"extension"`
	Size              int32             `json:"size"`
}

// BlockHeader represents the header of a block.
type BlockHeader struct {
	ID               ModifierID   `json:"id"`
	Timestamp        Timestamp    `json:"timestamp"`
	Version          Version      `json:"version"`
	AdProofsRoot     Digest32     `json:"adProofsRoot"`
	StateRoot        ADDigest     `json:"stateRoot"`
	TransactionsRoot Digest32     `json:"transactionsRoot"`
	NBits            int64        `json:"nBits"`
	ExtensionHash    Digest32     `json:"extensionHash"`
	PowSolutions     PowSolutions `json:"powSolutions"`
	Height           int32        `json:"height"`
	Difficulty       string       `json:"difficulty"` // Can be a large number
	ParentID         ModifierID   `json:"parentId"`
	Votes            Votes        `json:"votes"`
	Size             *int32       `json:"size,omitempty"`
	ExtensionID      *ModifierID  `json:"extensionId,omitempty"`
	TransactionsID   *ModifierID  `json:"transactionsId,omitempty"`
	AdProofsID       *ModifierID  `json:"adProofsId,omitempty"`
}

// PowSolutions contains the proof-of-work solution.
type PowSolutions struct {
	PK string  `json:"pk"`
	W  string  `json:"w"`
	N  string  `json:"n"`
	D  *BigInt `json:"d"` // Using BigInt for very large numbers
}

// BlockTransactions contains the transactions of a block.
type BlockTransactions struct {
	HeaderID     ModifierID        `json:"headerId"`
	Transactions []ErgoTransaction `json:"transactions"`
	Size         int32             `json:"size"`
}

// BlockADProofs contains the AD proofs of a block.
type BlockADProofs struct {
	HeaderID   ModifierID        `json:"headerId"`
	ProofBytes SerializedAdProof `json:"proofBytes"`
	Digest     Digest32          `json:"digest"`
	Size       int32             `json:"size"`
}

// Extension contains the extension data of a block.
type Extension struct {
	HeaderID ModifierID     `json:"headerId"`
	Digest   Digest32       `json:"digest"`
	Fields   []KeyValueItem `json:"fields"`
}

// KeyValueItem is a key-value pair.
type KeyValueItem [2]HexString

// MerkleProof for a transaction.
type MerkleProof struct {
	Leaf   string          `json:"leaf"`
	Levels [][]interface{} `json:"levels"` // Array of [hash, side]
}

// PopowHeader is a header with interlinks for NiPoPoW proofs.
type PopowHeader struct {
	Header     BlockHeader  `json:"header"`
	Interlinks []ModifierID `json:"interlinks"`
}

// NipopowProof is a non-interactive proof of proof-of-work.
type NipopowProof struct {
	M          float64       `json:"m"`
	K          float64       `json:"k"`
	Prefix     []PopowHeader `json:"prefix"`
	SuffixHead PopowHeader   `json:"suffixHead"`
	SuffixTail []BlockHeader `json:"suffixTail"`
}

// Transactions is a list of Ergo transactions.
type Transactions []ErgoTransaction

// FeeHistogramBin represents one bin in a fee histogram.
type FeeHistogramBin struct {
	NTxns    int32 `json:"nTxns,omitempty"`
	TotalFee int64 `json:"totalFee,omitempty"`
}

// FeeHistogram is a list of histogram bins.
type FeeHistogram []FeeHistogramBin

// Peer represents a network peer.
type Peer struct {
	Address        string  `json:"address"`
	RestApiUrl     *string `json:"restApiUrl,omitempty"`
	Name           *string `json:"name,omitempty"`
	LastSeen       *int64  `json:"lastSeen,omitempty"`
	ConnectionType *string `json:"connectionType,omitempty"` // "Incoming" or "Outgoing"
}

// BlacklistedPeers contains a list of blacklisted peer addresses.
type BlacklistedPeers struct {
	Addresses []string `json:"addresses"`
}

// PeersStatus contains network time information.
type PeersStatus struct {
	LastIncomingMessage int64 `json:"lastIncomingMessage"`
	CurrentNetworkTime  int64 `json:"currentNetworkTime"`
}

// SyncInfo provides synchronization information about peers.
type SyncInfo struct {
	Address string   `json:"address"`
	Mode    PeerMode `json:"mode"`
	Version string   `json:"version"`
	Status  string   `json:"status"`
	Height  *int     `json:"height"`
}

// PeerMode describes the operating mode of a peer.
type PeerMode struct {
	State                 string `json:"state"`
	VerifyingTransactions bool   `json:"verifyingTransactions"`
	FullBlocksSuffix      int    `json:"fullBlocksSuffix"`
}

// TrackInfo provides information on tracked modifiers.
type TrackInfo struct {
	InvalidModifierApproxSize int                                  `json:"invalidModifierApproxSize"`
	Requested                 map[string]RequestedInfoByModifierID `json:"requested"`
	Received                  map[string]ConnectedPeerByModifierId `json:"received"`
}

// RequestedInfoByModifierId is a map of modifier IDs to requested info.
type RequestedInfoByModifierID map[string]RequestedInfo

// RequestedInfo describes a request for a modifier.
type RequestedInfo struct {
	Address *string `json:"address,omitempty"`
	Version *string `json:"version,omitempty"`
	Checks  int     `json:"checks"`
}

// ConnectedPeerByModifierId is a map of modifier IDs to connected peers.
type ConnectedPeerByModifierId map[string]ConnectedPeer

// ConnectedPeer describes a connected peer for a modifier.
type ConnectedPeer struct {
	Address     string    `json:"address"`
	Version     *string   `json:"version,omitempty"`
	LastMessage Timestamp `json:"lastMessage"`
}

// AddressValidity indicates if an Ergo address is valid.
type AddressValidity struct {
	Address ErgoAddress `json:"address"`
	IsValid bool        `json:"isValid"`
	Error   *string     `json:"error,omitempty"`
}

// ScriptBytes represents script bytes.
type ScriptBytes struct {
	Bytes HexString `json:"bytes"`
}

// ErgoTreeObject contains a serialized ErgoTree.
type ErgoTreeObject struct {
	Tree ErgoTree `json:"tree"`
}

// InitWallet is the request body for initializing a wallet.
type InitWallet struct {
	Pass         string  `json:"pass"`
	MnemonicPass *string `json:"mnemonicPass,omitempty"`
}

// InitWalletResult is the result of initializing a wallet.
type InitWalletResult struct {
	Mnemonic string `json:"mnemonic"`
}

// RestoreWallet is the request body for restoring a wallet.
type RestoreWallet struct {
	Pass                    string  `json:"pass"`
	Mnemonic                string  `json:"mnemonic"`
	MnemonicPass            *string `json:"mnemonicPass,omitempty"`
	UsePre1627KeyDerivation bool    `json:"usePre1627KeyDerivation"`
}

// CheckWallet is the request body for checking a wallet mnemonic.
type CheckWallet struct {
	Mnemonic     string  `json:"mnemonic"`
	MnemonicPass *string `json:"mnemonicPass,omitempty"`
}

// PassphraseMatch is the result of checking a wallet mnemonic.
type PassphraseMatch struct {
	Matched bool `json:"matched"`
}

// UnlockWallet is the request body for unlocking a wallet.
type UnlockWallet struct {
	Pass string `json:"pass"`
}

// WalletRescanRequest is the request body for rescan wallet endpoint.
type WalletRescanRequest struct {
	FromHeight int32 `json:"fromHeight"`
}

// WalletStatus represents the status of the node's wallet.
type WalletStatus struct {
	IsInitialized bool   `json:"isInitialized"`
	IsUnlocked    bool   `json:"isUnlocked"`
	ChangeAddress string `json:"changeAddress"`
	WalletHeight  int    `json:"walletHeight"`
	Error         string `json:"error"`
}

// DeriveKey is the request body for deriving a new key.
type DeriveKey struct {
	DerivationPath string `json:"derivationPath"`
}

// DeriveKeyResult is the result of deriving a key.
type DeriveKeyResult struct {
	Address ErgoAddress `json:"address"`
}

// DeriveNextKeyResult is the result of deriving the next key.
type DeriveNextKeyResult struct {
	DerivationPath string      `json:"derivationPath"`
	Address        ErgoAddress `json:"address"`
}

// BalancesSnapshot represents the balance of ERG and other assets.
type BalancesSnapshot struct {
	Height  int32   `json:"height"`
	Balance int64   `json:"balance"`
	Assets  []Asset `json:"assets,omitempty"`
}

// WalletTransaction is a transaction augmented with wallet-specific information.
type WalletTransaction struct {
	ID               *TransactionID             `json:"id,omitempty"`
	Inputs           []ErgoTransactionInput     `json:"inputs"`
	DataInputs       []ErgoTransactionDataInput `json:"dataInputs"`
	Outputs          []ErgoTransactionOutput    `json:"outputs"`
	InclusionHeight  int32                      `json:"inclusionHeight"`
	NumConfirmations int32                      `json:"numConfirmations"`
	Scans            []int                      `json:"scans"`
	Size             *int32                     `json:"size,omitempty"`
}

// WalletBox is a box augmented with wallet-specific information.
type WalletBox struct {
	Box                 ErgoTransactionOutput `json:"box"`
	ConfirmationsNum    *int32                `json:"confirmationsNum"`
	Address             ErgoAddress           `json:"address"`
	CreationTransaction ModifierID            `json:"creationTransaction"`
	SpendingTransaction *ModifierID           `json:"spendingTransaction"`
	SpendingHeight      *int32                `json:"spendingHeight"`
	InclusionHeight     int32                 `json:"inclusionHeight"`
	Onchain             bool                  `json:"onchain"`
	Spent               bool                  `json:"spent"`
	CreationOutIndex    int32                 `json:"creationOutIndex"`
	Scans               []int                 `json:"scans"`
}

// BoxesRequestHolder is the request body for collecting wallet boxes.
type BoxesRequestHolder struct {
	TargetAssets  [][2]interface{} `json:"targetAssets"` // Array of [TokenID, Amount]
	TargetBalance int64            `json:"targetBalance"`
}

// RequestsHolder is the request body for generating a transaction from multiple requests.
type RequestsHolder struct {
	Requests      []interface{} `json:"requests"` // Can be PaymentRequest, AssetIssueRequest, etc.
	Fee           *int64        `json:"fee,omitempty"`
	InputsRaw     []string      `json:"inputsRaw,omitempty"`
	DataInputsRaw []string      `json:"dataInputsRaw,omitempty"`
}

// PaymentRequest is a request to make a payment.
type PaymentRequest struct {
	Address   ErgoAddress `json:"address"`
	Value     int64       `json:"value"`
	Assets    []Asset     `json:"assets,omitempty"`
	Registers *Registers  `json:"registers,omitempty"`
}

// AssetIssueRequest is a request to issue a new asset.
type AssetIssueRequest struct {
	Address     *ErgoAddress `json:"address,omitempty"`
	ErgValue    *int64       `json:"ergValue,omitempty"`
	Amount      int64        `json:"amount"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Decimals    int32        `json:"decimals"`
	Registers   *Registers   `json:"registers,omitempty"`
}

// BurnTokensRequest is a request to burn tokens.
type BurnTokensRequest struct {
	AssetsToBurn []Asset `json:"assetsToBurn"`
}

// TransactionSigningRequest is the request body for signing a transaction.
type TransactionSigningRequest struct {
	Tx            UnsignedErgoTransaction `json:"tx"`
	InputsRaw     []string                `json:"inputsRaw,omitempty"`
	DataInputsRaw []string                `json:"dataInputsRaw,omitempty"`
	Hints         *TransactionHintsBag    `json:"hints,omitempty"`
	Secrets       struct {
		Dlog []DlogSecret `json:"dlog,omitempty"`
		Dht  []DhtSecret  `json:"dht,omitempty"`
	} `json:"secrets"`
}

// DhtSecret is a Diffie-Hellman tuple secret.
type DhtSecret struct {
	Secret string `json:"secret"`
	G      string `json:"g"`
	H      string `json:"h"`
	U      string `json:"u"`
	V      string `json:"v"`
}

// TransactionHintsBag contains hints for signing a transaction.
type TransactionHintsBag struct {
	SecretHints []InputHints `json:"secretHints,omitempty"`
	PublicHints []InputHints `json:"publicHints,omitempty"`
}

// InputHints is a map of input indices to hints.
type InputHints map[string][]interface{}

// PrivateKeyRequest is a request to get a private key for an address.
type PrivateKeyRequest struct {
	Address ErgoAddress `json:"address"`
}

// WorkMessage is a block candidate for an external miner.
type WorkMessage struct {
	Msg   string                       `json:"msg"`
	B     int64                        `json:"b"` // BigInt
	PK    string                       `json:"pk"`
	Proof *ProofOfUpcomingTransactions `json:"proof,omitempty"`
}

// ProofOfUpcomingTransactions proves that a block contains certain transactions.
type ProofOfUpcomingTransactions struct {
	MsgPreimage string        `json:"msgPreimage"`
	TxProofs    []MerkleProof `json:"txProofs"`
}

// RewardAddress holds the miner's reward address.
type RewardAddress struct {
	RewardAddress ErgoAddress `json:"rewardAddress"`
}

// RewardPubKey holds the miner's reward public key.
type RewardPubKey struct {
	RewardPubkey string `json:"rewardPubkey"`
}

// SerializedBox is a box represented as hex-encoded bytes.
type SerializedBox struct {
	BoxID TransactionBoxID `json:"boxId"`
	Bytes HexString        `json:"bytes"`
}

// SnapshotsInfo contains information about UTXO snapshots.
type SnapshotsInfo struct {
	AvailableManifests []map[string]interface{} `json:"availableManifests"`
}

// SourceHolder holds Sigma source code.
type SourceHolder struct {
	Source string `json:"source"`
}

// AddressHolder holds an Ergo address.
type AddressHolder struct {
	Address ErgoAddress `json:"address"`
}

// ExecuteScript is the request body for executing a script.
type ExecuteScript struct {
	Script         string                 `json:"script"`
	NamedConstants map[string]interface{} `json:"namedConstants,omitempty"`
	Context        *ErgoLikeContext       `json:"context,omitempty"`
}

// ErgoLikeContext is the context for script execution.
type ErgoLikeContext struct {
	LastBlockUtxoRoot   AvlTreeData             `json:"lastBlockUtxoRoot"`
	Headers             []SigmaHeader           `json:"headers"`
	PreHeader           PreHeader               `json:"preHeader"`
	DataBoxes           []ErgoTransactionOutput `json:"dataBoxes"`
	BoxesToSpend        []ErgoTransactionOutput `json:"boxesToSpend"`
	SpendingTransaction ErgoLikeTransaction     `json:"spendingTransaction"`
	SelfIndex           int64                   `json:"selfIndex"`
	Extension           map[string]interface{}  `json:"extension"`
	ValidationSettings  string                  `json:"validationSettings"`
	CostLimit           int64                   `json:"costLimit"`
	InitCost            int64                   `json:"initCost"`
}

// AvlTreeData represents data for an AVL+ tree.
type AvlTreeData struct {
	Digest      Digest32 `json:"digest"`
	TreeFlags   *int32   `json:"treeFlags,omitempty"`
	KeyLength   *int32   `json:"keyLength,omitempty"`
	ValueLength *int32   `json:"valueLength,omitempty"`
}

// SigmaHeader is a block header for the ErgoLikeContext.
type SigmaHeader struct {
	ID               *ModifierID   `json:"id,omitempty"`
	Timestamp        Timestamp     `json:"timestamp"`
	Version          Version       `json:"version"`
	AdProofsRoot     Digest32      `json:"adProofsRoot"`
	AdProofsID       *ModifierID   `json:"adProofsId,omitempty"`
	StateRoot        AvlTreeData   `json:"stateRoot"`
	TransactionsRoot Digest32      `json:"transactionsRoot"`
	TransactionsID   *ModifierID   `json:"transactionsId,omitempty"`
	NBits            int64         `json:"nBits"`
	ExtensionHash    Digest32      `json:"extensionHash"`
	ExtensionRoot    *Digest32     `json:"extensionRoot,omitempty"`
	ExtensionID      *ModifierID   `json:"extensionId,omitempty"`
	Height           int32         `json:"height"`
	Size             *int32        `json:"size,omitempty"`
	ParentID         ModifierID    `json:"parentId"`
	PowSolutions     *PowSolutions `json:"powSolutions,omitempty"`
	Votes            Votes         `json:"votes"`
	MinerPk          *string       `json:"minerPk,omitempty"`
	PowOnetimePk     *string       `json:"powOnetimePk,omitempty"`
	PowNonce         *Digest32     `json:"powNonce,omitempty"`
	PowDistance      *float64      `json:"powDistance,omitempty"`
}

// PreHeader contains fields of a block header that can be predicted.
type PreHeader struct {
	Timestamp Timestamp  `json:"timestamp"`
	Version   Version    `json:"version"`
	NBits     int64      `json:"nBits"`
	Height    int32      `json:"height"`
	ParentID  ModifierID `json:"parentId"`
	Votes     Votes      `json:"votes"`
	MinerPk   *string    `json:"minerPk,omitempty"`
}

// ErgoLikeTransaction is a transaction structure for the ErgoLikeContext.
type ErgoLikeTransaction struct {
	ID         ModifierID                 `json:"id"`
	Inputs     []ErgoTransactionInput     `json:"inputs"`
	DataInputs []ErgoTransactionDataInput `json:"dataInputs"`
	Outputs    []ErgoTransactionOutput    `json:"outputs"`
}

// CryptoResult is the result of a script execution.
type CryptoResult struct {
	Value SigmaBoolean `json:"value"`
	Cost  int64        `json:"cost"`
}

// SigmaBoolean represents a sigma proposition expression.
type SigmaBoolean struct {
	Op        *int8          `json:"op,omitempty"`
	H         *HexString     `json:"h,omitempty"`
	G         *HexString     `json:"g,omitempty"`
	U         *HexString     `json:"u,omitempty"`
	V         *HexString     `json:"v,omitempty"`
	Condition *bool          `json:"condition,omitempty"`
	Args      []SigmaBoolean `json:"args,omitempty"`
}

// ScanRequest is the request body for registering a scan.
type ScanRequest struct {
	ScanName          string             `json:"scanName,omitempty"`
	RemoveOffchain    *bool              `json:"removeOffchain,omitempty"`
	WalletInteraction *WalletInteraction `json:"walletInteraction,omitempty"`
	TrackingRule      interface{}        `json:"trackingRule,omitempty"` // Can be one of many predicate types
}

// Scan represents a registered scan.
type Scan struct {
	ScanName          string             `json:"scanName"`
	ScanID            int                `json:"scanId"`
	WalletInteraction *WalletInteraction `json:"walletInteraction,omitempty"`
	RemoveOffchain    *bool              `json:"removeOffchain,omitempty"`
	TrackingRule      interface{}        `json:"trackingRule,omitempty"`
}

// ScanID holds the ID of a scan.
type ScanID struct {
	ScanID int `json:"scanId"`
}

// ScanIDBoxID is used to stop tracking a box for a scan.
type ScanIDBoxID struct {
	ScanID int              `json:"scanId"`
	BoxID  TransactionBoxID `json:"boxId"`
}

// ScanIdsBox is a box with associated scan IDs.
type ScanIdsBox struct {
	ScanIds []int                 `json:"scanIds"`
	Box     ErgoTransactionOutput `json:"box"`
}

// GenerateCommitmentsRequest is the request body for generating transaction commitments.
type GenerateCommitmentsRequest struct {
	Tx      UnsignedErgoTransaction `json:"tx"`
	Secrets *struct {
		Dlog []DlogSecret `json:"dlog,omitempty"`
		Dht  []DhtSecret  `json:"dht,omitempty"`
	} `json:"secrets,omitempty"`
	InputsRaw     []string `json:"inputsRaw,omitempty"`
	DataInputsRaw []string `json:"dataInputsRaw,omitempty"`
}

// HintExtractionRequest is the request body for extracting prover hints.
type HintExtractionRequest struct {
	Tx            ErgoTransaction `json:"tx"`
	Real          []SigmaBoolean  `json:"real"`
	Simulated     []SigmaBoolean  `json:"simulated"`
	InputsRaw     []string        `json:"inputsRaw,omitempty"`
	DataInputsRaw []string        `json:"dataInputsRaw,omitempty"`
}

// EmissionInfo contains emission data for a given height.
type EmissionInfo struct {
	MinerReward      int64 `json:"minerReward"`
	TotalCoinsIssued int64 `json:"totalCoinsIssued"`
	TotalRemainCoins int64 `json:"totalRemainCoins"`
	Reemitted        int64 `json:"reemitted"`
}

// EmissionScripts contains emission-related scripts.
type EmissionScripts struct {
	Emission       string `json:"emission"`
	Reemission     string `json:"reemission"`
	Pay2Reemission string `json:"pay2Reemission"`
}

// IndexedHeightResponse contains the indexed height and full height.
type IndexedHeightResponse struct {
	IndexedHeight int `json:"indexedHeight"`
	FullHeight    int `json:"fullHeight"`
}

// IndexedErgoTransaction is a transaction with extra indexing information.
type IndexedErgoTransaction struct {
	ID               TransactionID              `json:"id"`
	Inputs           []IndexedErgoBox           `json:"inputs"`
	DataInputs       []ErgoTransactionDataInput `json:"dataInputs"`
	Outputs          []IndexedErgoBox           `json:"outputs"`
	InclusionHeight  int32                      `json:"inclusionHeight"`
	NumConfirmations int32                      `json:"numConfirmations"`
	BlockID          ModifierID                 `json:"blockId"`
	Timestamp        Timestamp                  `json:"timestamp"`
	Index            int32                      `json:"index"`
	GlobalIndex      int64                      `json:"globalIndex"`
	Size             int32                      `json:"size"`
}

// IndexedErgoBox is a box with extra indexing information.
type IndexedErgoBox struct {
	ErgoTransactionOutput
	Address            ErgoAddress `json:"address"`
	SpentTransactionID *ModifierID `json:"spentTransactionId"`
	SpendingHeight     *int32      `json:"spendingHeight"`
	InclusionHeight    int32       `json:"inclusionHeight"`
	GlobalIndex        int64       `json:"globalIndex"`
}

// TransactionsByAddressResponse is the response for getting transactions by address.
type TransactionsByAddressResponse struct {
	Items []IndexedErgoTransaction `json:"items"`
	Total int                      `json:"total"`
}

// BoxesByAddressResponse is the response for getting boxes by address.
type BoxesByAddressResponse struct {
	Items []IndexedErgoBox `json:"items"`
	Total int              `json:"total"`
}

// BoxesByTokenIdResponse is the response for getting boxes by token ID.
type BoxesByTokenIdResponse struct {
	Items []IndexedErgoBox `json:"items"`
	Total int              `json:"total"`
}

// IndexedToken is a token with extra indexing information.
type IndexedToken struct {
	ID             ModifierID `json:"id"`
	BoxID          ModifierID `json:"boxId"`
	EmissionAmount int64      `json:"emissionAmount"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Decimals       int32      `json:"decimals"`
}

// AddressBalanceResponse contains confirmed and unconfirmed balances for an address.
type AddressBalanceResponse struct {
	Confirmed   BalanceInfo `json:"confirmed"`
	Unconfirmed BalanceInfo `json:"unconfirmed"`
}

// BalanceInfo contains nanoERG and token balances.
type BalanceInfo struct {
	NanoErgs int64       `json:"nanoErgs"`
	Tokens   []TokenInfo `json:"tokens"`
}

// TokenInfo contains detailed information about a token in a balance.
type TokenInfo struct {
	TokenID  *ModifierID `json:"tokenId,omitempty"`
	Amount   int64       `json:"amount"`
	Decimals *int        `json:"decimals,omitempty"`
	Name     *string     `json:"name,omitempty"`
}
