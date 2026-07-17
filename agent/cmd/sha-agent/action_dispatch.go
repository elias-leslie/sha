package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

type agentActionHandlers struct {
	run              func(context.Context, bool, time.Duration) error
	status           func(context.Context) error
	rotateCredential func(context.Context) error
	service          func(time.Duration) error
}

func newAgentActionHandlers(agent *Agent, stdout, stderr io.Writer) agentActionHandlers {
	return agentActionHandlers{
		run: func(ctx context.Context, loop bool, interval time.Duration) error {
			return runAgent(
				ctx,
				loop,
				interval,
				func() error { return agent.RunOnceContext(ctx) },
				waitForAgentInterval,
				func(err error) { fmt.Fprintln(stderr, "SHA agent cycle failed; retrying:", err) },
			)
		},
		status: func(ctx context.Context) error {
			hostname, platformVersion := localIdentityFacts()
			var session *deviceSession
			err := agent.runWithContext(ctx, func() error {
				var err error
				session, err = agent.ensureDeviceIdentity(hostname, platformVersion)
				return err
			})
			if err != nil {
				return err
			}
			return printAgentStatusTo(stdout, session.identity)
		},
		rotateCredential: func(ctx context.Context) error {
			hostname, platformVersion := localIdentityFacts()
			var credential *deviceCredentialResponse
			err := agent.runWithContext(ctx, func() error {
				var err error
				credential, err = agent.rotateDeviceCredential(hostname, platformVersion)
				return err
			})
			if err != nil {
				return err
			}
			return json.NewEncoder(stdout).Encode(map[string]string{
				"endpoint_id":       credential.EndpointID,
				"credential_id":     credential.CredentialID,
				"credential_status": credential.Status,
			})
		},
		service: func(interval time.Duration) error {
			return runWindowsService(agent, interval)
		},
	}
}

func dispatchAgentAction(
	ctx context.Context,
	action string,
	loop bool,
	interval time.Duration,
	handlers agentActionHandlers,
) error {
	switch action {
	case "run":
		if interval <= 0 {
			return errors.New("interval must be greater than zero")
		}
		if handlers.run == nil {
			return errors.New("run action is unavailable")
		}
		return handlers.run(ctx, loop, interval)
	case "service":
		if loop {
			return errors.New("service action owns its Windows SCM loop and does not accept -loop")
		}
		if interval <= 0 {
			return errors.New("interval must be greater than zero")
		}
		if handlers.service == nil {
			return errors.New("service action is unavailable")
		}
		return handlers.service(interval)
	case "status":
		if handlers.status == nil {
			return errors.New("status action is unavailable")
		}
		return handlers.status(ctx)
	case "rotate-credential":
		if handlers.rotateCredential == nil {
			return errors.New("rotate-credential action is unavailable")
		}
		return handlers.rotateCredential(ctx)
	default:
		return errors.New("action must be run, service, status, or rotate-credential")
	}
}
