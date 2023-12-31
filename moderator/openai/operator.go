package openai

import (
	"context"
	"fmt"
	"github.com/fatal-fruit/cosmapp/moderator/types"
	openai "github.com/sashabaranov/go-openai"
)

const TOKEN_LIMIT = 4096
const AVERAGE_CHARACTERS_PER_TOKEN = 4
const MAX_CHARACTERS = TOKEN_LIMIT * AVERAGE_CHARACTERS_PER_TOKEN
const PROMPT_CHARACTERS_LENGTH = 2000

type scoreWithIndex struct {
	index int
	score int64
}

func ComputeScoreBatchProposals(proposals []types.Proposal) ([]int64, []error) {
	var scores []int64
	var errors []error
	scoreChan := make(chan scoreWithIndex, len(proposals))
	errorChan := make(chan error, len(proposals))

	for i, proposal := range proposals {
		go func(i int, proposal types.Proposal) {
			score, err := ComputeScoreProposal(proposal)
			if err != nil {
				errorChan <- err
			} else {
				scoreChan <- scoreWithIndex{i, score}
			}
		}(i, proposal)
	}

	scoresWithIndex := make([]scoreWithIndex, len(proposals))
	for i := 0; i < len(proposals); i++ {
		select {
		case score := <-scoreChan:
			scoresWithIndex[score.index] = score
		case err := <-errorChan:
			errors = append(errors, err)
		}
	}

	for _, score := range scoresWithIndex {
		scores = append(scores, score.score)
	}

	return scores, errors
}

func ComputeScoreProposal(proposal types.Proposal) (int64, error) {
	truncate_limit_description := MAX_CHARACTERS - PROMPT_CHARACTERS_LENGTH - len(proposal.Title)
	client := openai.NewClient("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")
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model:       openai.GPT3Dot5Turbo,
			Temperature: 0.0,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: "Given a document, you are a blockchain governance proposal scorer. Your task is to read the document and determine whether it represents a legit blockchain governance proposal or a scam proposal. Assign a score between 0 and 1, where 1 represents a legit proposal and 0 represents a scam proposal.",
				},
				{
					Role: openai.ChatMessageRoleUser,
					Content: `Given a document, you are a blockchain governance proposal scorer. Your task is to read the document and determine whether it represents a legit blockchain governance proposal or a scam proposal. Assign a score between 0 and 1, where 1 represents a legit proposal and 0 represents a scam proposal.

					## Document:
					Title: {{proposal_title}}
					Description: {{proposal_description}}
					
					## Scoring Criteria:
					A legit blockchain governance proposal typically includes:
					- Clear and concise title and description
					- Author information with verifiable links
					- Detailed proposal content related to blockchain ecosystem, development, or community improvement
					- References to official discussion forums or documents
					- Links to relevant technical details or supporting documentation
					
					A scam proposal typically includes:
					- Vague or misleading title and description
					- Absence of reliable author information or links
					- Lack of detailed content or relevance to blockchain development or ecosystem
					- References to unofficial or suspicious discussion forums
					- Missing or broken links to relevant technical details or supporting documentation
					
					## Instructions:
					Read the given document and assign a score between 0 and 1 to indicate whether it is a legit blockchain governance proposal or a scam proposal. Use the scoring criteria provided above as guidelines.
					Given a prompt, return a score between 0 and 1 indicating the likelihood that the proposal is a legitimate blockchain governance proposal. A score of 1 indicates a high likelihood of legitimacy, while a score of 0 indicates a high likelihood of being a scam proposal.
					
					## Prompt:
					---
					Title:` + proposal.Title + `
					Description:` + fmt.Sprintf("%.*s", truncate_limit_description, proposal.Description) + `
					---
					
					IMPORTANT! The expected output: A float between 0 and 1 only, do not write any text`,
				},
			},
		},
	)

	fmt.Printf("ChatCompletion response: %v\n", resp)

	if err != nil {
		fmt.Printf("ChatCompletion error: %v\n", err)
		return 0, err
	}

	var scoreFloat float64
	_, err = fmt.Sscanf(resp.Choices[0].Message.Content, "%f", &scoreFloat)

	if err != nil {
		fmt.Printf("Error parsing score: %v\n", err)
		return 0, err
	}

	score := int64(scoreFloat * 100)

	return score, nil
}
