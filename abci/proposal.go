package abci

import (
	"errors"
	"fmt"
	v1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"

	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types/v1"

	"cosmossdk.io/log"
	"encoding/json"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
)

// ScamProposalTx defines the custom transaction identifying the scam proposal by its ID.
type ScamProposalTx struct {
	Score              int64
	Title              string
	HashedTitle        string
	ExtendedCommitInfo abci.ExtendedCommitInfo
}

// NewProposalHandler creates a new instance of the handler to be used.
func NewProposalHandler(
	lg log.Logger,
	valStore baseapp.ValidatorStore,
	cdc codec.Codec,
	govKeeper govkeeper.Keeper,
	stakingKeeper *stakingkeeper.Keeper,
) *ProposalHandler {
	return &ProposalHandler{
		logger:        lg,
		valStore:      valStore,
		cdc:           cdc,
		govKeeper:     govKeeper,
		stakingKeeper: stakingKeeper,
	}
}

// PrepareProposalHandler is the handler to be used for PrepareProposal.
func (h *ProposalHandler) PrepareProposalHandler() sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
		proposalTxs := req.Txs
		fmt.Println("the requests in a block", len(proposalTxs))
		//if len(proposalTxs) == 0 {
		//	return &abci.ResponsePrepareProposal{Txs: req.Txs}, nil
		//}

		err := baseapp.ValidateVoteExtensions(ctx, h.valStore, req.Height, ctx.ChainID(), req.LocalLastCommit)
		if err != nil {
			return nil, err
		}

		h.logger.Info("PrepareProposal started")

		if req.Height >= ctx.ConsensusParams().Abci.VoteExtensionsEnableHeight {
			scoreWeightedAverage, err := h.computeScamIdentificationResults(ctx, req.LocalLastCommit)
			//TODO: doesn;t exist
			//if err != nil {
			//	return nil, errors.New("failed to compute stake-weighted average score")
			//}

			var scamProposalExt ScamProposalExtension
			voteExtension := req.LocalLastCommit.Votes[0].VoteExtension
			if err := json.Unmarshal(voteExtension, &scamProposalExt); err != nil {
				fmt.Println("the requests in the end of a block", len(req.Txs))
				return &abci.ResponsePrepareProposal{Txs: proposalTxs}, nil
				//return nil, fmt.Errorf("failed to unmrashal vote extension: %w", err)
			}

			fmt.Println("the Scam Proposal", scamProposalExt)
			if scamProposalExt.ScamPercent == 0 {
				return &abci.ResponsePrepareProposal{Txs: req.Txs}, nil
			}

			injectedVoteExtTx := ScamProposalTx{
				Score:              scoreWeightedAverage,
				Title:              scamProposalExt.Title,
				HashedTitle:        scamProposalExt.HashedTitle,
				ExtendedCommitInfo: req.LocalLastCommit,
			}

			fmt.Println("The current height", req.Height)
			//fmt.Println("The injectedVoteExtTx score", injectedVoteExtTx.Score)
			// NOTE: We use stdlib JSON encoding, but an application may choose to use
			// a performant mechanism. This is for demo purposes only.
			bz, err := json.Marshal(injectedVoteExtTx)
			if err != nil {
				h.logger.Error("failed to encode injected vote extension tx", "err", err)
				return nil, errors.New("failed to encode injected vote extension tx")
			}

			// Inject a "fake" tx into the proposal s.t. validators can decode, verify,
			// and store the canonical stake-weighted average prices.
			proposalTxs = append(proposalTxs, bz)
		}
		//fmt.Println("proposalTxs", proposalTxs)

		h.logger.Info("PrepareProposal finished")

		fmt.Println("the requests in the end of a block", len(proposalTxs))
		//fmt.Println("the requests in a block", len(proposalTxs))

		return &abci.ResponsePrepareProposal{Txs: proposalTxs}, nil
	}
}

// ProcessProposalHandler is the handler to be used for ProcessProposal.
func (h *ProposalHandler) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (resp *abci.ResponseProcessProposal, err error) {
		h.logger.Info("ProcessProposal started")

		if len(req.Txs) == 0 {
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
		}

		var injectedVoteExtTx ScamProposalTx
		if err := json.Unmarshal(req.Txs[0], &injectedVoteExtTx); err == nil {
			h.logger.Error("failed to decode injected vote extension tx", "err", err)
			err = baseapp.ValidateVoteExtensions(ctx, h.valStore, req.Height, ctx.ChainID(), injectedVoteExtTx.ExtendedCommitInfo)
			if err != nil {
				return nil, err
			}

			scoreWeightedAverage, err := h.computeScamIdentificationResults(ctx, injectedVoteExtTx.ExtendedCommitInfo)
			if err != nil {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}

			if scoreWeightedAverage != injectedVoteExtTx.Score {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}

			h.logger.Info("ProcessProposal finished")
		}

		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
	}
}

func (h *ProposalHandler) PreBlocker(ctx sdk.Context, req *abci.RequestFinalizeBlock) (*sdk.ResponsePreBlock, error) {
	h.logger.Info("PreBlocker started")
	fmt.Println("PreBlocker Transactions", len(req.Txs))

	res := &sdk.ResponsePreBlock{}
	if len(req.Txs) == 0 {
		h.logger.Info("0 Transactions here")
		return res, nil
	}

	var proposalMsg govtypes.MsgSubmitProposal
	if err := h.cdc.Unmarshal(req.Txs[0], &proposalMsg); err != nil {
	}

	fmt.Println("The SubmitProposalTx", proposalMsg)

	var injectedVoteExtTx ScamProposalTx
	//h.logger.Info("PreBlocker transactions", len(req.Txs))
	if err := json.Unmarshal(req.Txs[len(req.Txs)-1], &injectedVoteExtTx); err != nil {
		h.logger.Error("failed to decode injected vote extension tx", "err", err)
		return res, nil
	}

	fmt.Println("scam Proposal tx", injectedVoteExtTx)

	querier := govkeeper.NewQueryServer(&h.govKeeper)
	resp, err := querier.Proposals(ctx, &v1.QueryProposalsRequest{})
	if err != nil {
		fmt.Println("The querier ☢️")
		return nil, err
	}

	fmt.Println("☢️the proposals here", resp.Proposals)
	for _, proposal := range resp.Proposals {
		if proposal.Title == injectedVoteExtTx.Title {
			// We found the proposal
			// We need to check if the proposal is a scam
			if injectedVoteExtTx.Score > 90 {
				// The proposal is a scam
				// We need to reject it
				proposal.Status = v1.StatusRejected
				proposal.Title = "You got pwned by ABCAI moderator"
				proposal.Summary = "The original proposal was found to be a scam by ABCAI moderator and thus was stripped out of it's contents"
				if err := h.govKeeper.SetProposal(ctx, *proposal); err != nil {
					return nil, err
				}
			}
		}
	}
	h.logger.Info("PreBlocker ended")

	return res, nil
}

// computeScamIdentificationResults aggregates the scam identification results from each validator.
func (h *ProposalHandler) computeScamIdentificationResults(ctx sdk.Context, ci abci.ExtendedCommitInfo) (int64, error) {
	// Get all the votes from the commit info
	var weightedScore int64
	var totalStake int64
	for _, vote := range ci.Votes {
		if vote.BlockIdFlag != cmtproto.BlockIDFlagCommit {
			continue
		}

		var scamPropExt ScamProposalExtension
		if err := json.Unmarshal(vote.VoteExtension, &scamPropExt); err != nil {
			h.logger.Error("failed to decode vote extension", "err", err, "validator", fmt.Sprintf("%x", vote.Validator.Address))
			// We used -1 because is outside our range of interested and will be ignored by the caller
			return -1, err
		}
		fmt.Println("the Scam Proposal", scamPropExt)

		totalStake += vote.Validator.Power
		// Compute stake-weighted sum of the scamScore, i.e.
		// (S1)(W1) + (S2)(W2) + ... + (Sn)(Wn) / (W1 + W2 + ... + Wn)
		weightedScore += scamPropExt.ScamPercent * vote.Validator.Power
	}

	if totalStake == 0 {
		return -1, nil
	}

	// Compute stake-weighted average of the scamScore, i.e.
	// (S1)(W1) + (S2)(W2) + ... + (Sn)(Wn) / (W1 + W2 + ... + Wn)
	return weightedScore / totalStake, nil
}
