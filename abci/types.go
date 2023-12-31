package abci

import (
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
)

// ProposalHandler defines the handler to be used for
// PrepareProposal, ProcessProposal and PreBlocker
type ProposalHandler struct {
	logger        log.Logger
	valStore      baseapp.ValidatorStore
	cdc           codec.Codec
	govKeeper     govkeeper.Keeper
	stakingKeeper *stakingkeeper.Keeper
}

// VoteExtHandler defines the handler to be used for
// ExtendVote and VerifyExtendVote
type VoteExtHandler struct {
	logger log.Logger
	cdc    codec.Codec
}
