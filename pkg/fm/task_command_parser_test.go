package fm

import (
	"reflect"
	"testing"
	"testing/synctest"

	pb "github.com/nezhahq/agent/proto"
)

type taskParsedCommandDispatcher func(*Task, parsedCommand) error

var _ taskParsedCommandDispatcher = (*Task).dispatchParsedCommand

func TestTask_ParsedCommandContainsOnlyImmutableValues(t *testing.T) {
	commandType := reflect.TypeOf(parsedCommand{})
	for fieldIndex := range commandType.NumField() {
		field := commandType.Field(fieldIndex)
		switch field.Type.Kind() {
		case reflect.Slice, reflect.Map, reflect.Pointer, reflect.Interface, reflect.Func, reflect.Chan:
			t.Fatalf("parsed command field %s has reference kind %s", field.Name, field.Type.Kind())
		}
	}
}

func TestTask_DoTaskParsesBeforeSynchronousDispatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type commandBoundaryEvent byte
		const (
			parserEnter commandBoundaryEvent = iota
			parserComplete
			dispatchEnter
		)

		// Given
		parserRelease := make(chan struct{})
		dispatchRelease := make(chan struct{})
		events := make(chan commandBoundaryEvent, 3)
		dispatchEntered := make(chan parsedCommand, 1)
		doTaskReturned := make(chan struct{})
		task := newTaskIsolationTask(&taskIsolationStream{})
		task.parseCommand = func(frame []byte) (parsedCommand, error) {
			events <- parserEnter
			<-parserRelease
			command := parsedCommand{operation: commandDownload, path: string(frame[1:])}
			events <- parserComplete
			return command, nil
		}
		task.dispatchCommand = func(command parsedCommand) error {
			events <- dispatchEnter
			dispatchEntered <- command
			<-dispatchRelease
			return nil
		}

		// When
		go func() {
			task.DoTask(&pb.IOStreamData{Data: []byte{byte(commandDownload), 'a'}})
			close(doTaskReturned)
		}()

		// Wait establishes that the parser is durably blocked on parserRelease.
		synctest.Wait()
		firstEvent := <-events
		dispatchBeforeParserRelease := false
		select {
		case <-dispatchEntered:
			dispatchBeforeParserRelease = true
		default:
		}
		doTaskReturnedBeforeParserRelease := false
		select {
		case <-doTaskReturned:
			doTaskReturnedBeforeParserRelease = true
		default:
		}

		close(parserRelease)
		// Wait establishes parse completion and durable dispatcher blocking.
		synctest.Wait()
		secondEvent := <-events
		thirdEvent := <-events
		var dispatchedCommand parsedCommand
		if !dispatchBeforeParserRelease {
			dispatchedCommand = <-dispatchEntered
		}
		doTaskReturnedBeforeDispatchRelease := false
		select {
		case <-doTaskReturned:
			doTaskReturnedBeforeDispatchRelease = true
		default:
		}

		close(dispatchRelease)
		// Wait establishes that the synchronous dispatcher and DoTask completed.
		synctest.Wait()
		select {
		case <-doTaskReturned:
		default:
			t.Fatal("DoTask did not return after synchronous dispatch completed")
		}

		if firstEvent != parserEnter || secondEvent != parserComplete || thirdEvent != dispatchEnter {
			t.Fatalf("boundary events = [%d %d %d], want parse-enter, parse-complete, dispatch-enter", firstEvent, secondEvent, thirdEvent)
		}
		if dispatchBeforeParserRelease {
			t.Fatal("dispatch entered before parser release")
		}
		if doTaskReturnedBeforeParserRelease {
			t.Fatal("DoTask returned while command parser was blocked")
		}
		if dispatchedCommand.operation != commandDownload || dispatchedCommand.path != "a" {
			t.Fatalf("dispatch received %+v, want parsed download path a", dispatchedCommand)
		}
		if doTaskReturnedBeforeDispatchRelease {
			t.Fatal("DoTask returned before synchronous dispatch completed")
		}
	})
}
