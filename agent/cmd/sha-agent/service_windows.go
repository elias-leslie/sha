//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "SHAAgent"

type windowsServiceHandler struct {
	agent    *Agent
	interval time.Duration
}

func runWindowsService(agent *Agent, interval time.Duration) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect Windows service context: %w", err)
	}
	if !isService {
		return errors.New("service action must be started by the Windows Service Control Manager; use -action run -loop interactively")
	}
	return svc.Run(windowsServiceName, &windowsServiceHandler{agent: agent, interval: interval})
}

func (handler *windowsServiceHandler) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- runAgent(
			ctx,
			true,
			handler.interval,
			func() error { return handler.agent.RunOnceContext(ctx) },
			waitForAgentInterval,
			nil,
		)
	}()

	running := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	changes <- running

	for {
		select {
		case err := <-result:
			changes <- svc.Status{State: svc.StopPending}
			return windowsServiceExitCode(err)
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				return windowsServiceExitCode(<-result)
			}
		}
	}
}

func windowsServiceExitCode(err error) (bool, uint32) {
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	return false, uint32(windows.ERROR_GEN_FAILURE)
}
