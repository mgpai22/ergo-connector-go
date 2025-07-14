package node

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupNode creates a Node provider for testing.
// It requires ERGO_NODE_URL and optionally ERGO_NODE_API_KEY environment variables.
func setupNode(t *testing.T) *NodeProvider {
	t.Helper()

	nodeURL := os.Getenv("ERGO_NODE_URL")
	if nodeURL == "" {
		t.Skip(
			"ERGO_NODE_URL environment variable not set, skipping integration tests",
		)
	}

	apiKey := os.Getenv("ERGO_NODE_API_KEY")

	config := Config{
		BaseURL: nodeURL,
		APIKey:  apiKey,
	}

	provider, err := New(config)
	require.NoError(t, err, "Failed to create Node provider")

	return provider
}

func TestGetNodeInfo(t *testing.T) {
	node := setupNode(t)
	ctx := context.Background()

	info, err := node.GetNodeInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.NotEmpty(t, info.Name, "Node name should not be empty")
	assert.NotEmpty(t, info.AppVersion, "App version should not be empty")
	assert.NotNil(t, info.FullHeight, "Full height should not be nil")
}

func TestGetLastHeaders(t *testing.T) {
	node := setupNode(t)
	ctx := context.Background()

	headers, err := node.GetLastHeaders(ctx, 5)
	require.NoError(t, err)
	assert.Len(t, headers, 5, "Should return 5 headers")
	assert.NotEmpty(t, headers[0].ID, "Header ID should not be empty")
}

func TestGetBlockHeaderByID(t *testing.T) {
	node := setupNode(t)
	ctx := context.Background()

	info, err := node.GetNodeInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, info.BestHeaderID)

	headerID := *info.BestHeaderID

	header, err := node.GetBlockHeaderByID(ctx, headerID)
	require.NoError(t, err)
	require.NotNil(t, header)

	assert.Equal(
		t,
		headerID,
		header.ID,
		"Queried header ID should match the result",
	)
	assert.NotZero(t, header.Height, "Header height should not be zero")
}

func TestCheckAddressValidity(t *testing.T) {
	node := setupNode(t)
	ctx := context.Background()

	validAddress := "9hphYTmicjazd45pz2ovoHVPz5LTq9EvXoEK9JMGsfWuMtX6eDu"
	invalidAddress := "invalidAddressString"

	// Cannot use the GET version as it's deprecated and might be removed
	// Using POST version instead

	// Test valid address
	// The swagger has a bug, the body is a string, not an object
	// So we'll have to pass it as a string
	validity, err := node.checkAddressValidityPost(ctx, validAddress)
	require.NoError(t, err)
	require.NotNil(t, validity)
	assert.True(t, validity.IsValid)
	assert.Equal(t, ErgoAddress(validAddress), validity.Address)

	// Test invalid address
	validity, err = node.checkAddressValidityPost(ctx, invalidAddress)
	require.NoError(t, err)
	require.NotNil(t, validity)
	assert.False(t, validity.IsValid)
	assert.Equal(t, ErgoAddress(invalidAddress), validity.Address)
}

func (p *NodeProvider) checkAddressValidityPost(
	ctx context.Context,
	address string,
) (*AddressValidity, error) {
	var validity AddressValidity
	err := p.doRequest(
		ctx,
		http.MethodPost,
		"/utils/address",
		`"`+address+`"`,
		&validity,
	)
	return &validity, err
}
