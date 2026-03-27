package permission

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// evaluateWithAgentGuard checks if an action is allowed by ShellForge's
// governance engine. Calls `shellforge evaluate` as a subprocess.
//
// Activated by SHELLFORGE_GOVERNANCE=true. Every tool call is evaluated
// against agentguard.yaml before Crush's own permission system runs.
//
// If governance is disabled or shellforge isn't installed, returns (true, "")
// to fall through to Crush's normal permissions.
func evaluateWithAgentGuard(opts CreatePermissionRequest) (bool, string) {
	if os.Getenv("SHELLFORGE_GOVERNANCE") != "true" {
		return true, ""
	}

	sfBin, err := exec.LookPath("shellforge")
	if err != nil {
		slog.Debug("shellforge not found, skipping governance")
		return true, ""
	}

	// Check for policy file
	policyFound := false
	for _, path := range []string{"agentguard.yaml", "../agentguard.yaml"} {
		if _, err := os.Stat(path); err == nil {
			policyFound = true
			break
		}
	}
	if !policyFound {
		slog.Debug("no agentguard.yaml found, skipping governance")
		return true, ""
	}

	// Build evaluation payload
	payload := map[string]any{
		"tool":   opts.ToolName,
		"action": opts.Action,
		"path":   opts.Path,
	}
	if opts.Params != nil {
		payload["params"] = opts.Params
	}
	payloadJSON, _ := json.Marshal(payload)

	// Call shellforge evaluate
	cmd := exec.Command(sfBin, "evaluate")
	cmd.Stdin = strings.NewReader(string(payloadJSON))
	out, err := cmd.Output()
	if err != nil {
		// Fail-open on error
		slog.Warn("shellforge evaluate failed", "error", err)
		return true, ""
	}

	var result struct {
		Allowed    bool   `json:"allowed"`
		Reason     string `json:"reason"`
		Suggestion string `json:"suggestion"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		slog.Warn("shellforge response parse failed", "error", err)
		return true, ""
	}

	if !result.Allowed {
		reason := result.Reason
		if result.Suggestion != "" {
			reason = fmt.Sprintf("%s (suggestion: %s)", reason, result.Suggestion)
		}
		slog.Info("agentguard denied", "tool", opts.ToolName, "reason", reason)
		return false, reason
	}

	slog.Debug("agentguard allowed", "tool", opts.ToolName)
	return true, ""
}
