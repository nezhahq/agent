package main

import "context"

func (o *ioStreamWriteOwner) CloseSendAfterQuiescence(graceContext context.Context) ioStreamWriteShutdownResult {
	return o.finishWriteSide(graceContext, nil, false)
}

func (o *ioStreamWriteOwner) finishWriteSide(
	graceContext context.Context,
	cause error,
	cancelAfterClose bool,
) ioStreamWriteShutdownResult {
	o.shutdownOnce.Do(func() {
		activeDone, sendErr := o.beginClosing()
		keepaliveDone := o.StopKeepalive()
		forced, forcedCause := o.waitForQuiescence(graceContext, keepaliveDone, activeDone)
		if forced {
			o.cancel(forcedCause)
			o.joinQuiescence(keepaliveDone, activeDone)
		}
		closeErr := o.closeSendOnce()
		terminalErr := firstError(sendErr, closeErr)
		if cancelAfterClose && !forced {
			o.cancel(firstError(terminalErr, cause))
		}
		o.stateMu.Lock()
		o.state = ioStreamWriteClosed
		o.stateMu.Unlock()
		o.shutdownResult = ioStreamWriteShutdownResult{
			Err:    terminalErr,
			Cause:  forcedCause,
			Forced: forced,
		}
	})
	return o.shutdownResult
}
