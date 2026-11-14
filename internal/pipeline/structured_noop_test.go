package pipeline

import (
	"context"

	"github.com/craftedsignal/threat-bot/internal/llm"
)

func (n noopLLM) GenerateStructured(ctx context.Context, prompt, system string, _ *llm.Schema, out any) error {
	text, err := n.Generate(ctx, prompt, system)
	if err != nil {
		return err
	}
	if text == "" {
		return nil
	}
	return structuredFromText(text, out)
}
