package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// New creates a new NodeProvider instance.
func New(config Config) (*NodeProvider, error) {
	if config.BaseURL == "" {
		return nil, errors.New("BaseURL is required")
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &NodeProvider{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(config.BaseURL, "/"),
		apiKey:     config.APIKey,
	}, nil
}

// doRequest is a helper function to make HTTP requests to the Ergo node API.
func (p *NodeProvider) doRequest(
	ctx context.Context,
	method, path string,
	reqBody, target interface{},
) error {
	var bodyReader io.Reader
	if reqBody != nil {
		// Handle raw string body for endpoints like /utils/address
		if str, ok := reqBody.(string); ok {
			bodyReader = strings.NewReader(str)
		} else {
			reqBytes, err := json.Marshal(reqBody)
			if err != nil {
				return fmt.Errorf("failed to marshal request body: %w", err)
			}
			bodyReader = bytes.NewReader(reqBytes)
		}
	}

	fullURL := p.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if p.apiKey != "" {
		req.Header.Set("api_key", p.apiKey)
	}
	req.Header.Set("Accept", "application/json")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr ApiError
		if json.Unmarshal(respBodyBytes, &apiErr) == nil &&
			apiErr.Reason != "" {
			detail := ""
			if apiErr.Detail != nil {
				detail = *apiErr.Detail
			}
			return fmt.Errorf(
				"API error (%d - %s): %s",
				resp.StatusCode,
				apiErr.Reason,
				detail,
			)
		}
		return fmt.Errorf(
			"API error: status %d, body: %s",
			resp.StatusCode,
			string(respBodyBytes),
		)
	}

	if target != nil {
		if str, ok := target.(*string); ok {
			*str = strings.Trim(string(respBodyBytes), `"`)
			return nil
		}
		if raw, ok := target.(*json.RawMessage); ok {
			*raw = respBodyBytes
			return nil
		}
		if err := json.Unmarshal(respBodyBytes, target); err != nil {
			return fmt.Errorf(
				"failed to decode JSON response: %w. Body: %s",
				err,
				string(respBodyBytes),
			)
		}
	}

	return nil
}

// Info Endpoints

func (p *NodeProvider) GetNodeInfo(ctx context.Context) (*NodeInfo, error) {
	var info NodeInfo
	err := p.doRequest(ctx, http.MethodGet, "/info", nil, &info)
	return &info, err
}

// Blocks Endpoints

func (p *NodeProvider) GetHeaderIDs(
	ctx context.Context,
	limit, offset *int32,
) ([]ModifierID, error) {
	params := url.Values{}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}

	path := "/blocks"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var headerIDs []ModifierID
	err := p.doRequest(ctx, http.MethodGet, path, nil, &headerIDs)
	return headerIDs, err
}

func (p *NodeProvider) SendMinedBlock(
	ctx context.Context,
	block FullBlock,
) error {
	return p.doRequest(ctx, http.MethodPost, "/blocks", block, nil)
}

func (p *NodeProvider) GetFullBlockAt(
	ctx context.Context,
	blockHeight int32,
) ([]ModifierID, error) {
	path := fmt.Sprintf("/blocks/at/%d", blockHeight)
	var headerIDs []ModifierID
	err := p.doRequest(ctx, http.MethodGet, path, nil, &headerIDs)
	return headerIDs, err
}

func (p *NodeProvider) GetChainSlice(
	ctx context.Context,
	fromHeight, toHeight *int32,
) ([]BlockHeader, error) {
	params := url.Values{}
	if fromHeight != nil {
		params.Add("fromHeight", strconv.Itoa(int(*fromHeight)))
	}
	if toHeight != nil {
		params.Add("toHeight", strconv.Itoa(int(*toHeight)))
	}

	path := "/blocks/chainSlice"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var headers []BlockHeader
	err := p.doRequest(ctx, http.MethodGet, path, nil, &headers)
	return headers, err
}

func (p *NodeProvider) GetFullBlockByID(
	ctx context.Context,
	headerID ModifierID,
) (*FullBlock, error) {
	path := fmt.Sprintf("/blocks/%s", headerID)
	var block FullBlock
	err := p.doRequest(ctx, http.MethodGet, path, nil, &block)
	return &block, err
}

func (p *NodeProvider) GetFullBlockByIds(
	ctx context.Context,
	headerIDs []ModifierID,
) ([]FullBlock, error) {
	var blocks []FullBlock
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/blocks/headerIds",
		headerIDs,
		&blocks,
	)
	return blocks, err
}

func (p *NodeProvider) GetBlockHeaderByID(
	ctx context.Context,
	headerID ModifierID,
) (*BlockHeader, error) {
	path := fmt.Sprintf("/blocks/%s/header", headerID)
	var header BlockHeader
	err := p.doRequest(ctx, http.MethodGet, path, nil, &header)
	return &header, err
}

func (p *NodeProvider) GetBlockTransactionsByID(
	ctx context.Context,
	headerID ModifierID,
) (*BlockTransactions, error) {
	path := fmt.Sprintf("/blocks/%s/transactions", headerID)
	var txs BlockTransactions
	err := p.doRequest(ctx, http.MethodGet, path, nil, &txs)
	return &txs, err
}

func (p *NodeProvider) GetProofForTx(
	ctx context.Context,
	headerID ModifierID,
	txID TransactionID,
) (*MerkleProof, error) {
	path := fmt.Sprintf("/blocks/%s/proofFor/%s", headerID, txID)
	var proof MerkleProof
	err := p.doRequest(ctx, http.MethodGet, path, nil, &proof)
	return &proof, err
}

func (p *NodeProvider) GetLastHeaders(
	ctx context.Context,
	count int,
) ([]BlockHeader, error) {
	path := fmt.Sprintf("/blocks/lastHeaders/%d", count)
	var headers []BlockHeader
	err := p.doRequest(ctx, http.MethodGet, path, nil, &headers)
	return headers, err
}

func (p *NodeProvider) GetModifierById(
	ctx context.Context,
	modifierID ModifierID,
) (json.RawMessage, error) {
	path := fmt.Sprintf("/blocks/modifier/%s", modifierID)
	var modifier json.RawMessage
	err := p.doRequest(ctx, http.MethodGet, path, nil, &modifier)
	return modifier, err
}

// Nipopow Endpoints

func (p *NodeProvider) GetPopowHeaderByID(
	ctx context.Context,
	headerID ModifierID,
) (*PopowHeader, error) {
	path := fmt.Sprintf("/nipopow/popowHeaderById/%s", headerID)
	var popowHeader PopowHeader
	err := p.doRequest(ctx, http.MethodGet, path, nil, &popowHeader)
	return &popowHeader, err
}

func (p *NodeProvider) GetPopowHeaderByHeight(
	ctx context.Context,
	height int32,
) (*PopowHeader, error) {
	path := fmt.Sprintf("/nipopow/popowHeaderByHeight/%d", height)
	var popowHeader PopowHeader
	err := p.doRequest(ctx, http.MethodGet, path, nil, &popowHeader)
	return &popowHeader, err
}

func (p *NodeProvider) GetPopowProof(
	ctx context.Context,
	minChainLength, suffixLength float64,
) (*NipopowProof, error) {
	path := fmt.Sprintf(
		"/nipopow/proof/%.0f/%.0f",
		minChainLength,
		suffixLength,
	)
	var proof NipopowProof
	err := p.doRequest(ctx, http.MethodGet, path, nil, &proof)
	return &proof, err
}

func (p *NodeProvider) GetPopowProofByHeaderID(
	ctx context.Context,
	minChainLength, suffixLength float64,
	headerID ModifierID,
) (*NipopowProof, error) {
	path := fmt.Sprintf(
		"/nipopow/proof/%.0f/%.0f/%s",
		minChainLength,
		suffixLength,
		headerID,
	)
	var proof NipopowProof
	err := p.doRequest(ctx, http.MethodGet, path, nil, &proof)
	return &proof, err
}

// Transactions Endpoints

func (p *NodeProvider) SendTransaction(
	ctx context.Context,
	tx ErgoTransaction,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(ctx, http.MethodPost, "/transactions", tx, &txIDStr)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

func (p *NodeProvider) SendTransactionAsBytes(
	ctx context.Context,
	txBytesHex string,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/transactions/bytes",
		`"`+txBytesHex+`"`,
		&txIDStr,
	)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

func (p *NodeProvider) CheckTransaction(
	ctx context.Context,
	tx ErgoTransaction,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/transactions/check",
		tx,
		&txIDStr,
	)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

func (p *NodeProvider) CheckTransactionAsBytes(
	ctx context.Context,
	txBytesHex string,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/transactions/checkBytes",
		`"`+txBytesHex+`"`,
		&txIDStr,
	)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

func (p *NodeProvider) GetUnconfirmedTransactions(
	ctx context.Context,
	limit, offset *int32,
) (*Transactions, error) {
	params := url.Values{}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}

	path := "/transactions/unconfirmed"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var txs Transactions
	err := p.doRequest(ctx, http.MethodGet, path, nil, &txs)
	return &txs, err
}

func (p *NodeProvider) CheckUnconfirmedTransaction(
	ctx context.Context,
	txID TransactionID,
) (bool, error) {
	path := fmt.Sprintf("/transactions/unconfirmed/%s", txID)
	fullURL := p.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, fullURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HEAD request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("HEAD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func (p *NodeProvider) GetUnconfirmedTransactionByID(
	ctx context.Context,
	txID TransactionID,
) (*ErgoTransaction, error) {
	path := fmt.Sprintf("/transactions/unconfirmed/byTransactionId/%s", txID)
	var tx ErgoTransaction
	err := p.doRequest(ctx, http.MethodGet, path, nil, &tx)
	return &tx, err
}

func (p *NodeProvider) GetUnconfirmedTxIds(
	ctx context.Context,
) ([]TransactionID, error) {
	var txIds []TransactionID
	err := p.doRequest(
		ctx,
		http.MethodGet,
		"/transactions/unconfirmed/transactionIds",
		nil,
		&txIds,
	)
	return txIds, err
}

func (p *NodeProvider) GetUnconfirmedTxsByIds(
	ctx context.Context,
	txIDs []TransactionID,
) ([]ErgoTransaction, error) {
	var txs []ErgoTransaction
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/transactions/unconfirmed/byTransactionIds",
		txIDs,
		&txs,
	)
	return txs, err
}

func (p *NodeProvider) GetUnconfirmedTransactionsByErgoTree(
	ctx context.Context,
	ergoTreeHex string,
	limit, offset *int32,
) (*Transactions, error) {
	params := url.Values{}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	path := "/transactions/unconfirmed/byErgoTree"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var txs Transactions
	err := p.doRequest(ctx, http.MethodPost, path, `"`+ergoTreeHex+`"`, &txs)
	return &txs, err
}

func (p *NodeProvider) GetUnconfirmedTransactionInputBoxById(
	ctx context.Context,
	boxID TransactionBoxID,
) (*ErgoTransactionOutput, error) {
	path := fmt.Sprintf("/transactions/unconfirmed/inputs/byBoxId/%s", boxID)
	var box ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetUnconfirmedTransactionOutputBoxById(
	ctx context.Context,
	boxID TransactionBoxID,
) (*ErgoTransactionOutput, error) {
	path := fmt.Sprintf("/transactions/unconfirmed/outputs/byBoxId/%s", boxID)
	var box ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetUnconfirmedTransactionOutputBoxesByErgoTree(
	ctx context.Context,
	ergoTreeHex string,
	limit, offset *int32,
) ([]ErgoTransactionOutput, error) {
	params := url.Values{}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	path := "/transactions/unconfirmed/outputs/byErgoTree"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodPost, path, `"`+ergoTreeHex+`"`, &boxes)
	return boxes, err
}

func (p *NodeProvider) GetUnconfirmedTransactionOutputBoxesByTokenId(
	ctx context.Context,
	tokenID TokenID,
) ([]ErgoTransactionOutput, error) {
	path := fmt.Sprintf(
		"/transactions/unconfirmed/outputs/byTokenId/%s",
		tokenID,
	)
	var boxes []ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodGet, path, nil, &boxes)
	return boxes, err
}

func (p *NodeProvider) GetUnconfirmedTransactionOutputBoxesByRegisters(
	ctx context.Context,
	registers Registers,
	limit, offset *int32,
) ([]ErgoTransactionOutput, error) {
	params := url.Values{}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	path := "/transactions/unconfirmed/outputs/byRegisters"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodPost, path, registers, &boxes)
	return boxes, err
}

func (p *NodeProvider) GetFeeHistogram(
	ctx context.Context,
	bins *int32,
	maxtime *int64,
) (*FeeHistogram, error) {
	params := url.Values{}
	if bins != nil {
		params.Add("bins", strconv.Itoa(int(*bins)))
	}
	if maxtime != nil {
		params.Add("maxtime", strconv.FormatInt(*maxtime, 10))
	}
	path := "/transactions/poolHistogram"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var histogram FeeHistogram
	err := p.doRequest(ctx, http.MethodGet, path, nil, &histogram)
	return &histogram, err
}

func (p *NodeProvider) GetRecommendedFee(
	ctx context.Context,
	waitTime int32,
	txSize int32,
) (*int, error) {
	params := url.Values{}
	params.Add("waitTime", strconv.Itoa(int(waitTime)))
	params.Add("txSize", strconv.Itoa(int(txSize)))
	path := "/transactions/getFee?" + params.Encode()
	var fee int
	err := p.doRequest(ctx, http.MethodGet, path, nil, &fee)
	return &fee, err
}

func (p *NodeProvider) GetExpectedWaitTime(
	ctx context.Context,
	fee int32,
	txSize int32,
) (*int, error) {
	params := url.Values{}
	params.Add("fee", strconv.Itoa(int(fee)))
	params.Add("txSize", strconv.Itoa(int(txSize)))
	path := "/transactions/waitTime?" + params.Encode()
	var waitTime int
	err := p.doRequest(ctx, http.MethodGet, path, nil, &waitTime)
	return &waitTime, err
}

func (p *NodeProvider) GetSpendingProofByBoxId(
	ctx context.Context,
	boxID string,
	height int32,
) (*SpendingProof, error) {
	path := fmt.Sprintf("/transactions/spendingProof/%s", boxID)
	path += "?height=" + strconv.Itoa(int(height))

	var proof SpendingProof
	err := p.doRequest(ctx, http.MethodGet, path, nil, &proof)
	return &proof, err
}

func (p *NodeProvider) GetSpendingProofByUnconfirmedBoxId(
	ctx context.Context,
	boxID string,
) (*SpendingProof, error) {
	path := fmt.Sprintf("/transactions/unconfirmed/spendingProof/%s", boxID)

	var proof SpendingProof
	err := p.doRequest(ctx, http.MethodGet, path, nil, &proof)
	return &proof, err
}

// Peers Endpoints

func (p *NodeProvider) GetAllPeers(ctx context.Context) ([]Peer, error) {
	var peers []Peer
	err := p.doRequest(ctx, http.MethodGet, "/peers/all", nil, &peers)
	return peers, err
}

func (p *NodeProvider) GetConnectedPeers(ctx context.Context) ([]Peer, error) {
	var peers []Peer
	err := p.doRequest(ctx, http.MethodGet, "/peers/connected", nil, &peers)
	return peers, err
}

func (p *NodeProvider) ConnectToPeer(
	ctx context.Context,
	peerAddress string,
) error {
	return p.doRequest(
		ctx,
		http.MethodPost,
		"/peers/connect",
		`"`+peerAddress+`"`,
		nil,
	)
}

func (p *NodeProvider) GetBlacklistedPeers(
	ctx context.Context,
) (*BlacklistedPeers, error) {
	var peers BlacklistedPeers
	err := p.doRequest(ctx, http.MethodGet, "/peers/blacklisted", nil, &peers)
	return &peers, err
}

func (p *NodeProvider) GetPeersStatus(
	ctx context.Context,
) ([]PeersStatus, error) {
	var status []PeersStatus
	err := p.doRequest(ctx, http.MethodGet, "/peers/status", nil, &status)
	return status, err
}

func (p *NodeProvider) GetPeersSyncInfo(
	ctx context.Context,
) ([]SyncInfo, error) {
	var info []SyncInfo
	err := p.doRequest(ctx, http.MethodGet, "/peers/syncInfo", nil, &info)
	return info, err
}

func (p *NodeProvider) GetPeersTrackInfo(
	ctx context.Context,
) ([]TrackInfo, error) {
	var info []TrackInfo
	err := p.doRequest(ctx, http.MethodGet, "/peers/trackInfo", nil, &info)
	return info, err
}

// Utils Endpoints

func (p *NodeProvider) GetRandomSeed(ctx context.Context) (*string, error) {
	var seed string
	err := p.doRequest(ctx, http.MethodGet, "/utils/seed", nil, &seed)
	return &seed, err
}

func (p *NodeProvider) CheckAddressValidityWithGet(
	ctx context.Context,
	address ErgoAddress,
) (*AddressValidity, error) {
	path := fmt.Sprintf("/utils/address/%s", address)
	var validity AddressValidity
	err := p.doRequest(ctx, http.MethodGet, path, nil, &validity)
	return &validity, err
}

func (p *NodeProvider) CheckAddressValidity(
	ctx context.Context,
	address ErgoAddress,
) (*AddressValidity, error) {
	var validity AddressValidity
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/utils/address",
		`"`+string(address)+`"`,
		&validity,
	)
	return &validity, err
}

func (p *NodeProvider) AddressToRaw(
	ctx context.Context,
	address ErgoAddress,
) (*string, error) {
	path := fmt.Sprintf("/utils/addressToRaw/%s", address)
	var raw string
	err := p.doRequest(ctx, http.MethodGet, path, nil, &raw)
	return &raw, err
}

func (p *NodeProvider) RawToAddress(
	ctx context.Context,
	pubkeyHex string,
) (*ErgoAddress, error) {
	path := "/utils/rawToAddress/" + pubkeyHex
	var address ErgoAddress
	err := p.doRequest(ctx, http.MethodGet, path, nil, &address)
	return &address, err
}

func (p *NodeProvider) ErgoTreeToAddressWithGet(
	ctx context.Context,
	ergoTreeHex string,
) (*ErgoAddress, error) {
	path := "/utils/ergoTreeToAddress/" + ergoTreeHex
	var address ErgoAddress
	err := p.doRequest(ctx, http.MethodGet, path, nil, &address)
	return &address, err
}

func (p *NodeProvider) ErgoTreeToAddress(
	ctx context.Context,
	ergoTreeHex string,
) (*ErgoAddress, error) {
	var address ErgoAddress
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/utils/ergoTreeToAddress",
		`"`+ergoTreeHex+`"`,
		&address,
	)
	return &address, err
}

func (p *NodeProvider) GetRandomSeedWithLength(
	ctx context.Context,
	length int,
) (*string, error) {
	path := fmt.Sprintf("/utils/seed/%d", length)
	var seed string
	err := p.doRequest(ctx, http.MethodGet, path, nil, &seed)
	return &seed, err
}

func (p *NodeProvider) HashBlake2b(
	ctx context.Context,
	message string,
) (*string, error) {
	var hash string
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/utils/hash/blake2b",
		`"`+message+`"`,
		&hash,
	)
	return &hash, err
}

// Wallet Endpoints

func (p *NodeProvider) WalletInit(
	ctx context.Context,
	req InitWallet,
) (*InitWalletResult, error) {
	var res InitWalletResult
	err := p.doRequest(ctx, http.MethodPost, "/wallet/init", req, &res)
	return &res, err
}

func (p *NodeProvider) WalletRestore(
	ctx context.Context,
	req RestoreWallet,
) error {
	return p.doRequest(ctx, http.MethodPost, "/wallet/restore", req, nil)
}

func (p *NodeProvider) CheckSeed(
	ctx context.Context,
	req CheckWallet,
) (*PassphraseMatch, error) {
	var res PassphraseMatch
	err := p.doRequest(ctx, http.MethodPost, "/wallet/check", req, &res)
	return &res, err
}

func (p *NodeProvider) WalletUnlock(
	ctx context.Context,
	req UnlockWallet,
) error {
	return p.doRequest(ctx, http.MethodPost, "/wallet/unlock", req, nil)
}

func (p *NodeProvider) WalletLock(ctx context.Context) error {
	return p.doRequest(ctx, http.MethodGet, "/wallet/lock", nil, nil)
}

func (p *NodeProvider) WalletRescan(
	ctx context.Context,
	fromHeight *int32,
) error {
	var reqBody *WalletRescanRequest
	if fromHeight != nil {
		reqBody = &WalletRescanRequest{FromHeight: *fromHeight}
	}
	return p.doRequest(ctx, http.MethodPost, "/wallet/rescan", reqBody, nil)
}

func (p *NodeProvider) GetWalletStatus(
	ctx context.Context,
) (*WalletStatus, error) {
	var status WalletStatus
	err := p.doRequest(ctx, http.MethodGet, "/wallet/status", nil, &status)
	return &status, err
}

func (p *NodeProvider) WalletUpdateChangeAddress(
	ctx context.Context,
	address ErgoAddress,
) error {
	return p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/updateChangeAddress",
		`"`+string(address)+`"`,
		nil,
	)
}

func (p *NodeProvider) WalletDeriveKey(
	ctx context.Context,
	req DeriveKey,
) (*DeriveKeyResult, error) {
	var res DeriveKeyResult
	err := p.doRequest(ctx, http.MethodPost, "/wallet/deriveKey", req, &res)
	return &res, err
}

func (p *NodeProvider) WalletDeriveNextKey(
	ctx context.Context,
) (*DeriveNextKeyResult, error) {
	var res DeriveNextKeyResult
	err := p.doRequest(ctx, http.MethodGet, "/wallet/deriveNextKey", nil, &res)
	return &res, err
}

func (p *NodeProvider) WalletBalances(
	ctx context.Context,
) (*BalancesSnapshot, error) {
	var balances BalancesSnapshot
	err := p.doRequest(ctx, http.MethodGet, "/wallet/balances", nil, &balances)
	return &balances, err
}

func (p *NodeProvider) WalletTransactions(
	ctx context.Context,
	minConf, maxConf, minHeight, maxHeight *int32,
) ([]WalletTransaction, error) {
	params := url.Values{}
	if minConf != nil {
		params.Add("minConfirmations", strconv.Itoa(int(*minConf)))
	}
	if maxConf != nil {
		params.Add("maxConfirmations", strconv.Itoa(int(*maxConf)))
	}
	if minHeight != nil {
		params.Add("minInclusionHeight", strconv.Itoa(int(*minHeight)))
	}
	if maxHeight != nil {
		params.Add("maxInclusionHeight", strconv.Itoa(int(*maxHeight)))
	}

	path := "/wallet/transactions"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	var txs []WalletTransaction
	err := p.doRequest(ctx, http.MethodGet, path, nil, &txs)
	return txs, err
}

func (p *NodeProvider) WalletGetTransaction(
	ctx context.Context,
	txID TransactionID,
) ([]WalletTransaction, error) {
	path := fmt.Sprintf("/wallet/transactionById?id=%s", txID)
	var txs []WalletTransaction
	err := p.doRequest(ctx, http.MethodGet, path, nil, &txs)
	return txs, err
}

func (p *NodeProvider) WalletTransactionsByScanId(
	ctx context.Context,
	scanId int32,
	minInclHeight, maxInclHeight, minConf, maxConf *int32,
	includeUnconfirmed *bool,
) ([]WalletTransaction, error) {
	params := url.Values{}
	if minInclHeight != nil {
		params.Add("minInclusionHeight", strconv.Itoa(int(*minInclHeight)))
	}
	if maxInclHeight != nil {
		params.Add("maxInclusionHeight", strconv.Itoa(int(*maxInclHeight)))
	}
	if minConf != nil {
		params.Add("minConfirmations", strconv.Itoa(int(*minConf)))
	}
	if maxConf != nil {
		params.Add("maxConfirmations", strconv.Itoa(int(*maxConf)))
	}
	if includeUnconfirmed != nil {
		params.Add(
			"includeUnconfirmed",
			strconv.FormatBool(*includeUnconfirmed),
		)
	}

	path := fmt.Sprintf("/wallet/transactionsByScanId/%d", scanId)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var txs []WalletTransaction
	err := p.doRequest(ctx, http.MethodGet, path, nil, &txs)
	return txs, err
}

func (p *NodeProvider) WalletBoxes(
	ctx context.Context,
	minConf, maxConf, minHeight, maxHeight, limit, offset *int32,
) ([]WalletBox, error) {
	params := url.Values{}
	if minConf != nil {
		params.Add("minConfirmations", strconv.Itoa(int(*minConf)))
	}
	if maxConf != nil {
		params.Add("maxConfirmations", strconv.Itoa(int(*maxConf)))
	}
	if minHeight != nil {
		params.Add("minInclusionHeight", strconv.Itoa(int(*minHeight)))
	}
	if maxHeight != nil {
		params.Add("maxInclusionHeight", strconv.Itoa(int(*maxHeight)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}

	path := "/wallet/boxes"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []WalletBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &boxes)
	return boxes, err
}

func (p *NodeProvider) WalletBoxesCollect(
	ctx context.Context,
	req BoxesRequestHolder,
) ([]WalletBox, error) {
	var boxes []WalletBox
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/boxes/collect",
		req,
		&boxes,
	)
	return boxes, err
}

func (p *NodeProvider) WalletUnspentBoxes(
	ctx context.Context,
	minConf, maxConf, minHeight, maxHeight, limit, offset *int32,
) ([]WalletBox, error) {
	params := url.Values{}
	if minConf != nil {
		params.Add("minConfirmations", strconv.Itoa(int(*minConf)))
	}
	if maxConf != nil {
		params.Add("maxConfirmations", strconv.Itoa(int(*maxConf)))
	}
	if minHeight != nil {
		params.Add("minInclusionHeight", strconv.Itoa(int(*minHeight)))
	}
	if maxHeight != nil {
		params.Add("maxInclusionHeight", strconv.Itoa(int(*maxHeight)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}

	path := "/wallet/boxes/unspent"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []WalletBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &boxes)
	return boxes, err
}

func (p *NodeProvider) WalletBalancesUnconfirmed(
	ctx context.Context,
) (*BalancesSnapshot, error) {
	var balances BalancesSnapshot
	err := p.doRequest(
		ctx,
		http.MethodGet,
		"/wallet/balances/withUnconfirmed",
		nil,
		&balances,
	)
	return &balances, err
}

func (p *NodeProvider) WalletAddresses(
	ctx context.Context,
) ([]ErgoAddress, error) {
	var addresses []ErgoAddress
	err := p.doRequest(
		ctx,
		http.MethodGet,
		"/wallet/addresses",
		nil,
		&addresses,
	)
	return addresses, err
}

func (p *NodeProvider) WalletTransactionGenerate(
	ctx context.Context,
	req RequestsHolder,
) (*ErgoTransaction, error) {
	var tx ErgoTransaction
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/transaction/generate",
		req,
		&tx,
	)
	return &tx, err
}

func (p *NodeProvider) WalletUnsignedTransactionGenerate(
	ctx context.Context,
	req RequestsHolder,
) (*UnsignedErgoTransaction, error) {
	var tx UnsignedErgoTransaction
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/transaction/generateUnsigned",
		req,
		&tx,
	)
	return &tx, err
}

func (p *NodeProvider) WalletTransactionSign(
	ctx context.Context,
	req TransactionSigningRequest,
) (*ErgoTransaction, error) {
	var tx ErgoTransaction
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/transaction/sign",
		req,
		&tx,
	)
	return &tx, err
}

func (p *NodeProvider) WalletTransactionGenerateAndSend(
	ctx context.Context,
	req RequestsHolder,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/transaction/send",
		req,
		&txIDStr,
	)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

func (p *NodeProvider) WalletPaymentTransactionGenerateAndSend(
	ctx context.Context,
	req []PaymentRequest,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/payment/send",
		req,
		&txIDStr,
	)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

func (p *NodeProvider) WalletGetPrivateKey(
	ctx context.Context,
	req PrivateKeyRequest,
) (*DlogSecret, error) {
	var secret DlogSecret
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/getPrivateKey",
		req,
		&secret,
	)
	return &secret, err
}

func (p *NodeProvider) GenerateCommitments(
	ctx context.Context,
	req GenerateCommitmentsRequest,
) (*TransactionHintsBag, error) {
	var hints TransactionHintsBag
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/generateCommitments",
		req,
		&hints,
	)
	return &hints, err
}

func (p *NodeProvider) ExtractHints(
	ctx context.Context,
	req HintExtractionRequest,
) (*TransactionHintsBag, error) {
	var hints TransactionHintsBag
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/wallet/extractHints",
		req,
		&hints,
	)
	return &hints, err
}

// Mining Endpoints

func (p *NodeProvider) MiningRequestBlockCandidate(
	ctx context.Context,
) (*WorkMessage, error) {
	var msg WorkMessage
	err := p.doRequest(ctx, http.MethodGet, "/mining/candidate", nil, &msg)
	return &msg, err
}

func (p *NodeProvider) MiningRequestBlockCandidateWithMandatoryTransactions(
	ctx context.Context,
	txs Transactions,
) (*WorkMessage, error) {
	var msg WorkMessage
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/mining/candidateWithTxs",
		txs,
		&msg,
	)
	return &msg, err
}

func (p *NodeProvider) MiningReadMinerRewardAddress(
	ctx context.Context,
) (*RewardAddress, error) {
	var addr RewardAddress
	err := p.doRequest(ctx, http.MethodGet, "/mining/rewardAddress", nil, &addr)
	return &addr, err
}

func (p *NodeProvider) MiningReadMinerRewardPubkey(
	ctx context.Context,
) (*RewardPubKey, error) {
	var pubkey RewardPubKey
	err := p.doRequest(
		ctx,
		http.MethodGet,
		"/mining/rewardPublicKey",
		nil,
		&pubkey,
	)
	return &pubkey, err
}

func (p *NodeProvider) MiningSubmitSolution(
	ctx context.Context,
	sol PowSolutions,
) error {
	return p.doRequest(ctx, http.MethodPost, "/mining/solution", sol, nil)
}

// UTXO Endpoints

func (p *NodeProvider) GetBoxesBinaryProof(
	ctx context.Context,
	boxIDs []TransactionBoxID,
) (*SerializedAdProof, error) {
	var proof SerializedAdProof
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/utxo/getBoxesBinaryProof",
		boxIDs,
		&proof,
	)
	return &proof, err
}

func (p *NodeProvider) GetBoxByID(
	ctx context.Context,
	boxID TransactionBoxID,
) (*ErgoTransactionOutput, error) {
	path := fmt.Sprintf("/utxo/byId/%s", boxID)
	var box ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetBoxByIdBinary(
	ctx context.Context,
	boxID TransactionBoxID,
) (*SerializedBox, error) {
	path := fmt.Sprintf("/utxo/byIdBinary/%s", boxID)
	var box SerializedBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetBoxWithPoolById(
	ctx context.Context,
	boxID TransactionBoxID,
) (*ErgoTransactionOutput, error) {
	path := fmt.Sprintf("/utxo/withPool/byId/%s", boxID)
	var box ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetBoxWithPoolByIds(
	ctx context.Context,
	boxIDs []TransactionBoxID,
) ([]ErgoTransactionOutput, error) {
	var boxes []ErgoTransactionOutput
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/utxo/withPool/byIds",
		boxIDs,
		&boxes,
	)
	return boxes, err
}

func (p *NodeProvider) GetBoxWithPoolByIdBinary(
	ctx context.Context,
	boxID TransactionBoxID,
) (*SerializedBox, error) {
	path := fmt.Sprintf("/utxo/withPool/byIdBinary/%s", boxID)
	var box SerializedBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetSnapshotsInfo(
	ctx context.Context,
) (*SnapshotsInfo, error) {
	var info SnapshotsInfo
	err := p.doRequest(
		ctx,
		http.MethodGet,
		"/utxo/getSnapshotsInfo",
		nil,
		&info,
	)
	return &info, err
}

func (p *NodeProvider) GenesisBoxes(
	ctx context.Context,
) ([]ErgoTransactionOutput, error) {
	var boxes []ErgoTransactionOutput
	err := p.doRequest(ctx, http.MethodGet, "/utxo/genesis", nil, &boxes)
	return boxes, err
}

// Script Endpoints

func (p *NodeProvider) ScriptP2SAddress(
	ctx context.Context,
	source string,
) (*AddressHolder, error) {
	req := SourceHolder{Source: source}
	var res AddressHolder
	err := p.doRequest(ctx, http.MethodPost, "/script/p2sAddress", req, &res)
	return &res, err
}

func (p *NodeProvider) ScriptP2SHAddress(
	ctx context.Context,
	source string,
) (*AddressHolder, error) {
	req := SourceHolder{Source: source}
	var res AddressHolder
	err := p.doRequest(ctx, http.MethodPost, "/script/p2shAddress", req, &res)
	return &res, err
}

func (p *NodeProvider) AddressToTree(
	ctx context.Context,
	address ErgoAddress,
) (*ErgoTreeObject, error) {
	path := fmt.Sprintf("/script/addressToTree/%s", address)
	var tree ErgoTreeObject
	err := p.doRequest(ctx, http.MethodGet, path, nil, &tree)
	return &tree, err
}

func (p *NodeProvider) AddressToBytes(
	ctx context.Context,
	address ErgoAddress,
) (*ScriptBytes, error) {
	path := fmt.Sprintf("/script/addressToBytes/%s", address)
	var scriptBytes ScriptBytes
	err := p.doRequest(ctx, http.MethodGet, path, nil, &scriptBytes)
	return &scriptBytes, err
}

func (p *NodeProvider) ExecuteWithContext(
	ctx context.Context,
	req ExecuteScript,
) (*CryptoResult, error) {
	var res CryptoResult
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/script/executeWithContext",
		req,
		&res,
	)
	return &res, err
}

// can Endpoints

func (p *NodeProvider) RegisterScan(
	ctx context.Context,
	req ScanRequest,
) (*ScanID, error) {
	var res ScanID
	err := p.doRequest(ctx, http.MethodPost, "/scan/register", req, &res)
	return &res, err
}

func (p *NodeProvider) DeregisterScan(
	ctx context.Context,
	req ScanID,
) (*ScanID, error) {
	var res ScanID
	err := p.doRequest(ctx, http.MethodPost, "/scan/deregister", req, &res)
	return &res, err
}

func (p *NodeProvider) ListAllScans(ctx context.Context) ([]Scan, error) {
	var scans []Scan
	err := p.doRequest(ctx, http.MethodGet, "/scan/listAll", nil, &scans)
	return scans, err
}

func (p *NodeProvider) ListUnspentScans(
	ctx context.Context,
	scanID int32,
	minConf, maxConf, minHeight, maxHeight, limit, offset *int32,
) ([]WalletBox, error) {
	params := url.Values{}
	if minConf != nil {
		params.Add("minConfirmations", strconv.Itoa(int(*minConf)))
	}
	if maxConf != nil {
		params.Add("maxConfirmations", strconv.Itoa(int(*maxConf)))
	}
	if minHeight != nil {
		params.Add("minInclusionHeight", strconv.Itoa(int(*minHeight)))
	}
	if maxHeight != nil {
		params.Add("maxInclusionHeight", strconv.Itoa(int(*maxHeight)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	path := fmt.Sprintf("/scan/unspentBoxes/%d", scanID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []WalletBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &boxes)
	return boxes, err
}

func (p *NodeProvider) ListSpentScans(
	ctx context.Context,
	scanID int32,
	minConf, maxConf, minHeight, maxHeight, limit, offset *int32,
) ([]WalletBox, error) {
	params := url.Values{}
	if minConf != nil {
		params.Add("minConfirmations", strconv.Itoa(int(*minConf)))
	}
	if maxConf != nil {
		params.Add("maxConfirmations", strconv.Itoa(int(*maxConf)))
	}
	if minHeight != nil {
		params.Add("minInclusionHeight", strconv.Itoa(int(*minHeight)))
	}
	if maxHeight != nil {
		params.Add("maxInclusionHeight", strconv.Itoa(int(*maxHeight)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	path := fmt.Sprintf("/scan/spentBoxes/%d", scanID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []WalletBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &boxes)
	return boxes, err
}

func (p *NodeProvider) ScanStopTracking(
	ctx context.Context,
	req ScanIDBoxID,
) (*ScanIDBoxID, error) {
	var res ScanIDBoxID
	err := p.doRequest(ctx, http.MethodPost, "/scan/stopTracking", req, &res)
	return &res, err
}

func (p *NodeProvider) ScriptP2SRule(
	ctx context.Context,
	p2sAddress string,
) (*ScanID, error) {
	var res ScanID
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/scan/p2sRule",
		`"`+p2sAddress+`"`,
		&res,
	)
	return &res, err
}

func (p *NodeProvider) AddBox(
	ctx context.Context,
	req ScanIdsBox,
) (*TransactionID, error) {
	var txIDStr string
	err := p.doRequest(ctx, http.MethodPost, "/scan/addBox", req, &txIDStr)
	if err != nil {
		return nil, err
	}
	txID := TransactionID(txIDStr)
	return &txID, nil
}

// Node Control

func (p *NodeProvider) NodeShutdown(ctx context.Context) error {
	return p.doRequest(ctx, http.MethodPost, "/node/shutdown", nil, nil)
}

// Emission Endpoints

func (p *NodeProvider) EmissionAt(
	ctx context.Context,
	blockHeight int32,
) (*EmissionInfo, error) {
	path := fmt.Sprintf("/emission/at/%d", blockHeight)
	var info EmissionInfo
	err := p.doRequest(ctx, http.MethodGet, path, nil, &info)
	return &info, err
}

func (p *NodeProvider) EmissionScripts(
	ctx context.Context,
) (*EmissionScripts, error) {
	var scripts EmissionScripts
	err := p.doRequest(ctx, http.MethodGet, "/emission/scripts", nil, &scripts)
	return &scripts, err
}

// Blockchain Indexed Endpoints

func (p *NodeProvider) GetIndexedHeight(
	ctx context.Context,
) (*IndexedHeightResponse, error) {
	var res IndexedHeightResponse
	err := p.doRequest(
		ctx,
		http.MethodGet,
		"/blockchain/indexedHeight",
		nil,
		&res,
	)
	return &res, err
}

func (p *NodeProvider) GetTxById(
	ctx context.Context,
	txID TransactionID,
) (*IndexedErgoTransaction, error) {
	path := fmt.Sprintf("/blockchain/transaction/byId/%s", txID)
	var tx IndexedErgoTransaction
	err := p.doRequest(ctx, http.MethodGet, path, nil, &tx)
	return &tx, err
}

func (p *NodeProvider) GetTxByIndex(
	ctx context.Context,
	txIndex int64,
) (*IndexedErgoTransaction, error) {
	path := fmt.Sprintf("/blockchain/transaction/byIndex/%d", txIndex)
	var tx IndexedErgoTransaction
	err := p.doRequest(ctx, http.MethodGet, path, nil, &tx)
	return &tx, err
}

func (p *NodeProvider) GetTxsByAddress(
	ctx context.Context,
	address ErgoAddress,
	offset, limit *int32,
) (*TransactionsByAddressResponse, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	path := "/blockchain/transaction/byAddress"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var res TransactionsByAddressResponse
	err := p.doRequest(
		ctx,
		http.MethodPost,
		path,
		`"`+string(address)+`"`,
		&res,
	)
	return &res, err
}

func (p *NodeProvider) GetTxRange(
	ctx context.Context,
	offset, limit *int32,
) ([]ModifierID, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	path := "/blockchain/transaction/range"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	var ids []ModifierID
	err := p.doRequest(ctx, http.MethodGet, path, nil, &ids)
	return ids, err
}

func (p *NodeProvider) GetBlockchainBoxByID(
	ctx context.Context,
	boxID TransactionBoxID,
) (*IndexedErgoBox, error) {
	path := fmt.Sprintf("/blockchain/box/byId/%s", boxID)
	var box IndexedErgoBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetBoxByIndex(
	ctx context.Context,
	boxIndex int64,
) (*IndexedErgoBox, error) {
	path := fmt.Sprintf("/blockchain/box/byIndex/%d", boxIndex)
	var box IndexedErgoBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &box)
	return &box, err
}

func (p *NodeProvider) GetBoxesByTokenId(
	ctx context.Context,
	tokenID TokenID,
	offset, limit *int32,
) (*BoxesByTokenIdResponse, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	path := fmt.Sprintf("/blockchain/box/byTokenId/%s", tokenID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var res BoxesByTokenIdResponse
	err := p.doRequest(ctx, http.MethodGet, path, nil, &res)
	return &res, err
}

func (p *NodeProvider) GetBoxesByTokenIdUnspent(
	ctx context.Context,
	tokenID TokenID,
	offset, limit *int32,
	sortDirection *string,
	includeUnconfirmed *bool,
) ([]IndexedErgoBox, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if sortDirection != nil {
		params.Add("sortDirection", *sortDirection)
	}
	if includeUnconfirmed != nil {
		params.Add(
			"includeUnconfirmed",
			strconv.FormatBool(*includeUnconfirmed),
		)
	}
	path := fmt.Sprintf("/blockchain/box/unspent/byTokenId/%s", tokenID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []IndexedErgoBox
	err := p.doRequest(ctx, http.MethodGet, path, nil, &boxes)
	return boxes, err
}

func (p *NodeProvider) GetBoxesByAddress(
	ctx context.Context,
	address ErgoAddress,
	offset, limit *int32,
) (*BoxesByAddressResponse, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	path := "/blockchain/box/byAddress"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var res BoxesByAddressResponse
	err := p.doRequest(
		ctx,
		http.MethodPost,
		path,
		`"`+string(address)+`"`,
		&res,
	)
	return &res, err
}

func (p *NodeProvider) GetBoxesByAddressUnspent(
	ctx context.Context,
	address ErgoAddress,
	offset, limit *int32,
	sortDirection *string,
	includeUnconfirmed, excludeMempoolSpent *bool,
) ([]IndexedErgoBox, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if sortDirection != nil {
		params.Add("sortDirection", *sortDirection)
	}
	if includeUnconfirmed != nil {
		params.Add(
			"includeUnconfirmed",
			strconv.FormatBool(*includeUnconfirmed),
		)
	}
	if excludeMempoolSpent != nil {
		params.Add(
			"excludeMempoolSpent",
			strconv.FormatBool(*excludeMempoolSpent),
		)
	}
	path := "/blockchain/box/unspent/byAddress"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var boxes []IndexedErgoBox
	err := p.doRequest(
		ctx,
		http.MethodPost,
		path,
		`"`+string(address)+`"`,
		&boxes,
	)
	return boxes, err
}

func (p *NodeProvider) GetBoxRange(
	ctx context.Context,
	offset, limit *int32,
) ([]ModifierID, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	path := "/blockchain/box/range"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	var ids []ModifierID
	err := p.doRequest(ctx, http.MethodGet, path, nil, &ids)
	return ids, err
}

func (p *NodeProvider) GetBoxesByErgoTree(
	ctx context.Context,
	ergoTreeHex string,
	offset, limit *int32,
) (*BoxesByAddressResponse, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	path := "/blockchain/box/byErgoTree"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var res BoxesByAddressResponse
	err := p.doRequest(ctx, http.MethodPost, path, `"`+ergoTreeHex+`"`, &res)
	return &res, err
}

func (p *NodeProvider) GetBoxesByErgoTreeUnspent(
	ctx context.Context,
	ergoTreeHex string,
	offset, limit *int32,
	sortDirection *string,
	includeUnconfirmed *bool,
) (*BoxesByAddressResponse, error) {
	params := url.Values{}
	if offset != nil {
		params.Add("offset", strconv.Itoa(int(*offset)))
	}
	if limit != nil {
		params.Add("limit", strconv.Itoa(int(*limit)))
	}
	if sortDirection != nil {
		params.Add("sortDirection", *sortDirection)
	}
	if includeUnconfirmed != nil {
		params.Add(
			"includeUnconfirmed",
			strconv.FormatBool(*includeUnconfirmed),
		)
	}
	path := "/blockchain/box/unspent/byErgoTree"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var res BoxesByAddressResponse
	err := p.doRequest(ctx, http.MethodPost, path, `"`+ergoTreeHex+`"`, &res)
	return &res, err
}

func (p *NodeProvider) GetTokenByID(
	ctx context.Context,
	tokenID TokenID,
) (*IndexedToken, error) {
	path := fmt.Sprintf("/blockchain/token/byId/%s", tokenID)
	var token IndexedToken
	err := p.doRequest(ctx, http.MethodGet, path, nil, &token)
	return &token, err
}

func (p *NodeProvider) GetTokensByIds(
	ctx context.Context,
	tokenIDs []TokenID,
) ([]IndexedToken, error) {
	var tokens []IndexedToken
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/blockchain/tokens",
		tokenIDs,
		&tokens,
	)
	return tokens, err
}

func (p *NodeProvider) GetAddressBalanceTotal(
	ctx context.Context,
	address ErgoAddress,
) (*AddressBalanceResponse, error) {
	var res AddressBalanceResponse
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/blockchain/balance",
		`"`+string(address)+`"`,
		&res,
	)
	return &res, err
}
