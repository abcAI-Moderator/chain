package abci

import (
	"cosmossdk.io/log"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
)

// SusProposal defines a suspicious (sus) proposal that might be a scam
//type SusProposal struct {
//	HashedTitle string
//	ScamPercent int64
//}

// ScamProposalExtension defines the canonical vote extension structure for scam detection.
type ScamProposalExtension struct {
	Title       string
	HashedTitle string
	ScamPercent int64
	Height      int64
}

func NewVoteExtensionHandler(lg log.Logger, cdc codec.Codec) *VoteExtHandler {
	return &VoteExtHandler{
		logger: lg,
		cdc:    cdc,
	}
}

func (h *VoteExtHandler) ExtendVoteHandler() sdk.ExtendVoteHandler {
	return func(ctx sdk.Context, req *abci.RequestExtendVote) (*abci.ResponseExtendVote, error) {
		h.logger.Info("ExtendVote started")
		h.logger.Info(fmt.Sprintf("Extending votes at block height : %v", req.Height))

		var voteExtension ScamProposalExtension
		var proposalMsg govtypes.MsgSubmitProposal
		for _, tx := range req.Txs {
			if err := h.cdc.Unmarshal(tx, &proposalMsg); err != nil {
				//h.logger.Error(fmt.Sprintf("❌️ :: Transaction is not a gov proposal, %v", err))
				continue
			}
		}

		fmt.Println(proposalMsg)
		if proposalMsg.Title != "" {
			h.logger.Info("MsgSubmit Proposal", proposalMsg.Title, proposalMsg.Summary)
			// Make an API call to OpenAI to compute the score for the proposal title and summary
			//result, err := operator.ComputeScoreProposal(
			//	operatortypes.Proposal{
			//		Title:       proposalMsg.Title,
			//		Description: proposalMsg.Summary,
			//	},
			//)
			//
			//if err != nil {
			//	return nil, err
			//}

			// produce a canonical vote extension ScamProposalExtension
			voteExtension = ScamProposalExtension{
				Title:       proposalMsg.Title,
				HashedTitle: hashStringWithNonce(proposalMsg.Title, req.Height),
				ScamPercent: 91,
				Height:      req.Height,
			}

		}

		bz, err := json.Marshal(voteExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vote extension: %w", err)
		}

		h.logger.Info("ExtendVote ended")

		return &abci.ResponseExtendVote{VoteExtension: bz}, nil
	}
}

// VerifyVoteExtensionHandler handles the verification of the VoteExtensions provided by each validator.
// We are checking if the computed percent is the same for all validators
func (h *VoteExtHandler) VerifyVoteExtensionHandler() sdk.VerifyVoteExtensionHandler {
	return func(ctx sdk.Context, req *abci.RequestVerifyVoteExtension) (*abci.ResponseVerifyVoteExtension, error) {
		var voteExt ScamProposalExtension

		err := json.Unmarshal(req.VoteExtension, &voteExt)
		if err != nil {
			// NOTE: It is safe to return an error as the Cosmos SDK will capture all
			// errors, log them, and reject the proposal.
			return nil, fmt.Errorf("failed to unmarshal vote extension: %w", err)
		}

		if voteExt.Height != req.Height {
			return nil, fmt.Errorf("vote extension height does not match request height; expected: %d, got: %d", req.Height, voteExt.Height)
		}

		// Check if the calculated result is within the range 0 to 100
		if voteExt.ScamPercent > 100 || voteExt.ScamPercent < 0 {
			return nil, fmt.Errorf("vote extension scam percent is outside the range")
		}

		return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_ACCEPT}, nil
	}
}

// hashStringWithNonce hashes a string with a nonce and returns the hash and nonce.
func hashStringWithNonce(data string, height int64) string {
	// Concatenate data with nonce.
	input := fmt.Sprintf("%s%d", data, height)

	// Compute the SHA256 hash.
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hashed := hasher.Sum(nil)

	return hex.EncodeToString(hashed)
}