package permission

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/AgentGuardHQ/agentguard/go/pkg/hook"
)

// agentGuardHandler is lazily initialized on first governance check.
var agentGuardHandler *hook.Handler

// evaluateWithAgentGuard checks if an action is allowed by the AgentGuard
// governance kernel. Uses the Go kernel directly as a library — no subprocess,
// no CLI dependency, in-process policy evaluation.
//
// Activated by SHELLFORGE_GOVERNANCE=true. Every tool call is evaluated against
// agentguard.yaml before Crush's own permission system runs.
//
// If governance is disabled or no policy file is found, returns (true, "")
// to fall through to Crush's normal permissions.
func evaluateWithAgentGuard(opts CreatePermissionRequest) (bool, string) {
	if os.Getenv("SHELLFORGE_GOVERNANCE") != "true" {
		return true, ""
	}

	// Lazy-init the handler on first call
	if agentGuardHandler == nil {
		policyPath := findPolicyFile()
		if policyPath == "" {
			slog.Debug("no agentguard.yaml found, skipping governance")
			return true, ""
		}
		h, err := hook.NewHandler([]string{policyPath})
		if err != nil {
			slog.Warn("agentguard policy load failed", "error", err)
			return true, "" // fail-open
		}
		agentGuardHandler = h
		slog.Info("agentguard governance loaded", "policy", policyPath)
	}

	// Build hook input matching AgentGuard's expected format
	inputFields := map[string]any{
		"command": opts.Action,
	}
	if opts.Path != "" {
		inputFields["file_path"] = opts.Path
	}
	if opts.Params != nil {
		if m, ok := opts.Params.(map[string]any); ok {
			for k, v := range m {
				inputFields[k] = v
			}
		}
	}
	inputJSON, _ := json.Marshal(inputFields)

	input := hook.HookInput{
		Tool:  opts.ToolName,
		Input: json.RawMessage(inputJSON),
		Event: hook.PreToolUse,
	}

	// Evaluate against AgentGuard policies
	resp := agentGuardHandler.Handle(input)

	if resp.Decision != "allow" {
		reason := resp.Reason
		if resp.Suggestion != "" {
			reason = fmt.Sprintf("%s (suggestion: %s)", reason, resp.Suggestion)
		}
		slog.Info("agentguard denied",
			"tool", opts.ToolName,
			"action", opts.Action,
			"reason", reason,
		)
		return false, reason
	}

	slog.Debug("agentguard allowed", "tool", opts.ToolName)
	return true, ""
}

// findPolicyFile looks for agentguard.yaml in standard locations.
func findPolicyFile() string {
	for _, path := range []string{
		"agentguard.yaml",
		"../agentguard.yaml",
		os.Getenv("AGENTGUARD_POLICY"),
	} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
