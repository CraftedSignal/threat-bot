package main

import (
	"flag"
	"fmt"
	"github.com/craftedsignal/threat-bot/internal/config"
	"io"
	"os"
	"strings"
)

var version = "dev"
var revision = "unknown"

func runConfigValidation(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("config validate", flag.ContinueOnError)
	flags.SetOutput(output)
	command := flags.String("command", "run", "Validate requirements for run, check-llm, drafts, sources, publish, bundle, or digests")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected config validation arguments")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err = cfg.ValidateFor(*command); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Configuration valid for %s (offline; remote access and model availability not checked)\n", *command)
	return err
}

// validateCommandConfig runs before commands open databases or initialize
// network clients. Read-only draft commands do not require an LLM provider.
func validateCommandConfig(command string, args []string) error {
	for _, arg := range args {
		for _, name := range []string{"-config", "--config", "-log", "--log"} {
			if arg == name || strings.HasPrefix(arg, name+"=") {
				return fmt.Errorf("global flags must precede the command: threat-bot -config PATH %s", command)
			}
		}
	}
	var needsPublisher bool
	var err error
	switch command {
	case "drafts":
		needsPublisher, err = draftsNeedPublisher(args)
	case "digests":
		var opts digestOptions
		opts, err = parseDigestOptions(args)
		needsPublisher = opts.publish
	}
	if err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err = cfg.ValidateFor(command); err != nil {
		return err
	}
	if needsPublisher {
		return cfg.ValidateFor("publish")
	}
	if command == "bundle" && len(args) > 0 && args[0] == "enrich-vendors" {
		return cfg.ValidateFor("check-llm")
	}
	return nil
}

func draftsNeedPublisher(args []string) (bool, error) {
	if len(args) == 0 {
		return false, fmt.Errorf("usage: threat-bot drafts <list|find|show|approve|reject|amend|republish|retire-duplicates>")
	}
	switch args[0] {
	case "approve":
		opts, err := parseDraftApproveOptions(args[1:])
		return opts.publish, err
	case "republish":
		return true, nil
	case "amend":
		opts, err := parseDraftAmendOptions(args[1:])
		return opts.apply, err
	case "retire-duplicates":
		opts, err := parseDraftRetirementOptions(args[1:])
		return opts.apply, err
	case "list", "find", "show", "reject":
		return false, nil
	default:
		return false, fmt.Errorf("unknown drafts command: %s", args[0])
	}
}

func loadConfig() (*config.Config, error) {
	path := flagConfig
	if path == "" {
		path = os.Getenv("THREAT_BOT_CONFIG")
	}
	if path == "" {
		path = "config.yaml"
	}
	return config.Load(path)
}
