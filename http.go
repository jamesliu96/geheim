package geheim

import (
	"bytes"
	"io"
	"net/http"
)

type readerFunc func() (io.Reader, error)

func NewHTTPHandlerFuncReader(readerFn readerFunc, pass []byte, mode, keyMd uint16, keyIter int, dbgFn dbgFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if input, err := readerFn(); err == nil {
			Enc(input, rw, pass, mode, keyMd, keyIter, dbgFn)
		}
	}
}

func NewHTTPHandlerFuncPayload(payload []byte, pass []byte, mode, keyMd uint16, keyIter int, dbgFn dbgFunc) http.HandlerFunc {
	return NewHTTPHandlerFuncReader(func() (io.Reader, error) {
		return bytes.NewBuffer(payload), nil
	}, pass, mode, keyMd, keyIter, dbgFn)
}

type handlerReader struct {
	readerFn    readerFunc
	pass        []byte
	mode, keyMd uint16
	keyIter     int
	dbgFn       dbgFunc
}

func (h *handlerReader) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if input, err := h.readerFn(); err == nil {
		Enc(input, rw, h.pass, h.mode, h.keyMd, h.keyIter, h.dbgFn)
	}
}

func NewHTTPHandlerReader(readerFn readerFunc, pass []byte, mode, keyMd uint16, keyIter int, dbgFn dbgFunc) http.Handler {
	return &handlerReader{readerFn, pass, mode, keyMd, keyIter, dbgFn}
}

func NewHTTPHandlerPayload(payload []byte, pass []byte, mode, keyMd uint16, keyIter int, dbgFn dbgFunc) http.Handler {
	return NewHTTPHandlerFuncReader(func() (io.Reader, error) {
		return bytes.NewBuffer(payload), nil
	}, pass, mode, keyMd, keyIter, dbgFn)
}
