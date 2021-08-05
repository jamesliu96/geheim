package geheim

import (
	"bytes"
	"io"
	"net/http"
)

type ReaderFunc func() (io.Reader, error)

func NewHTTPHandlerFuncReader(readerFn ReaderFunc, pass []byte, mode, keyMd uint16, keyIter int, dbgFn DbgFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if input, err := readerFn(); err == nil {
			Enc(input, rw, pass, mode, keyMd, keyIter, dbgFn)
		}
	}
}

func NewHTTPHandlerFuncPayload(payload []byte, pass []byte, mode, keyMd uint16, keyIter int, dbgFn DbgFunc) http.HandlerFunc {
	return NewHTTPHandlerFuncReader(func() (io.Reader, error) {
		return bytes.NewBuffer(payload), nil
	}, pass, mode, keyMd, keyIter, dbgFn)
}

type handlerReader struct {
	readerFn    ReaderFunc
	pass        []byte
	mode, keyMd uint16
	keyIter     int
	dbgFn       DbgFunc
}

func (h *handlerReader) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if input, err := h.readerFn(); err == nil {
		Enc(input, rw, h.pass, h.mode, h.keyMd, h.keyIter, h.dbgFn)
	}
}

func NewHTTPHandlerReader(readerFn ReaderFunc, pass []byte, mode, keyMd uint16, keyIter int, dbgFn DbgFunc) http.Handler {
	return &handlerReader{readerFn, pass, mode, keyMd, keyIter, dbgFn}
}

func NewHTTPHandlerPayload(payload []byte, pass []byte, mode, keyMd uint16, keyIter int, dbgFn DbgFunc) http.Handler {
	return NewHTTPHandlerFuncReader(func() (io.Reader, error) {
		return bytes.NewBuffer(payload), nil
	}, pass, mode, keyMd, keyIter, dbgFn)
}
