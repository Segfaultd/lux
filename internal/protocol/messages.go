package protocol

import "fmt"

const (
	CodeOK                     = 0x0a
	CodeFail                   = 0x0b
	CodeNotify                 = 0x0c
	CodeHello                  = 0x0d
	CodePullMetadata           = 0x0e
	CodePullMetadataResult     = 0x0f
	CodePushMetadata           = 0x10
	CodePushMetadataResult     = 0x11
	CodeDeleteHistory          = 0x18
	CodeDeleteHistoryResult    = 0x19
	CodeGetFuncHistories       = 0x2f
	CodeGetFuncHistoriesResult = 0x30
	CodeHelloResult            = 0x31
)

const (
	PushModeMask                    uint32 = 0x0F
	PushOverrideIfBetterOrDifferent uint32 = 0x00
	PushOverride                    uint32 = 0x01
	PushDoNotOverride               uint32 = 0x02
	PushMerge                       uint32 = 0x03
)

type Credentials struct {
	Username string
	Password string
}

type Hello struct {
	ProtocolVersion uint32
	LicenseData     []byte
	LicenseNumber   [6]byte
	Unknown         uint32
	Credentials     *Credentials
}

type PullFunction struct {
	Unknown uint32
	Hash    []byte
}

type PullMetadata struct {
	Unknown  uint32
	Unknowns []uint32
	Funcs    []PullFunction
}

type PushFunction struct {
	Name     string
	Length   uint32
	Metadata []byte
	Unknown  uint32
	Hash     []byte
}

type PushMetadata struct {
	Flags    uint32
	IDBPath  string
	FilePath string
	MD5      [16]byte
	Hostname string
	Funcs    []PushFunction
	Trailing []uint64
}

type DeleteHistory struct {
	FunctionHashes [][]byte
}

type GetFuncHistories struct {
	Funcs   []PullFunction
	Unknown uint32
}

type PullResultFunction struct {
	Name       string
	Length     uint32
	Metadata   []byte
	Popularity uint32
}

type FunctionHistory struct {
	Name      string
	Metadata  []byte
	Timestamp uint64
}

func DecodeHello(payload []byte) (Hello, error) {
	d := NewDecoder(payload)
	var out Hello
	var err error
	if out.ProtocolVersion, err = d.DD(); err != nil {
		return out, err
	}
	if out.LicenseData, err = d.Bytes(); err != nil {
		return out, err
	}
	v, err := d.Fixed(6)
	if err != nil {
		return out, err
	}
	copy(out.LicenseNumber[:], v)
	if out.Unknown, err = d.DD(); err != nil {
		return out, err
	}
	if out.ProtocolVersion > 2 && d.Remaining() > 0 {
		username, err := d.CString()
		if err != nil {
			return out, err
		}
		password, err := d.CString()
		if err != nil {
			return out, err
		}
		out.Credentials = &Credentials{Username: username, Password: password}
	}
	return out, nil
}

func decodePullFunctions(d *Decoder, max uint32) ([]PullFunction, error) {
	n, err := d.Count(max)
	if err != nil {
		return nil, err
	}
	out := make([]PullFunction, n)
	for i := range out {
		if out[i].Unknown, err = d.DD(); err != nil {
			return nil, err
		}
		if out[i].Hash, err = d.Bytes(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func DecodePullMetadata(payload []byte) (PullMetadata, error) {
	d := NewDecoder(payload)
	var out PullMetadata
	var err error
	if out.Unknown, err = d.DD(); err != nil {
		return out, err
	}
	if out.Unknowns, err = d.U32s(1_000_000); err != nil {
		return out, err
	}
	out.Funcs, err = decodePullFunctions(d, 1_000_000)
	return out, err
}

func DecodePushMetadata(payload []byte) (PushMetadata, error) {
	d := NewDecoder(payload)
	var out PushMetadata
	var err error
	if out.Flags, err = d.DD(); err != nil {
		return out, err
	}
	if out.Flags&PushModeMask > PushMerge {
		return out, fmt.Errorf("unsupported push mode %#x", out.Flags&PushModeMask)
	}
	if out.IDBPath, err = d.CString(); err != nil {
		return out, err
	}
	if out.FilePath, err = d.CString(); err != nil {
		return out, err
	}
	md5, err := d.Fixed(16)
	if err != nil {
		return out, err
	}
	copy(out.MD5[:], md5)
	if out.Hostname, err = d.CString(); err != nil {
		return out, err
	}
	n, err := d.Count(1_000_000)
	if err != nil {
		return out, err
	}
	out.Funcs = make([]PushFunction, n)
	for i := range out.Funcs {
		f := &out.Funcs[i]
		if f.Name, err = d.CString(); err != nil {
			return out, err
		}
		if f.Length, err = d.DD(); err != nil {
			return out, err
		}
		if f.Metadata, err = d.Bytes(); err != nil {
			return out, err
		}
		if f.Unknown, err = d.DD(); err != nil {
			return out, err
		}
		if f.Hash, err = d.Bytes(); err != nil {
			return out, err
		}
	}
	n, err = d.Count(1_000_000)
	if err != nil {
		return out, err
	}
	out.Trailing = make([]uint64, n)
	for i := range out.Trailing {
		if out.Trailing[i], err = d.DQ(); err != nil {
			return out, err
		}
	}
	return out, nil
}

func DecodeDeleteHistory(payload []byte) (DeleteHistory, error) {
	d := NewDecoder(payload)
	if _, err := d.DD(); err != nil {
		return DeleteHistory{}, err
	}
	if _, err := d.Strings(1_000_000); err != nil {
		return DeleteHistory{}, err
	}
	for range 2 {
		n, err := d.Count(1_000_000)
		if err != nil {
			return DeleteHistory{}, err
		}
		for range n {
			if _, err = d.DQ(); err != nil {
				return DeleteHistory{}, err
			}
			if _, err = d.DQ(); err != nil {
				return DeleteHistory{}, err
			}
		}
	}
	for range 4 {
		if _, err := d.Strings(1_000_000); err != nil {
			return DeleteHistory{}, err
		}
	}
	if _, err := decodeFixedSequence(d, 16, 1_000_000); err != nil {
		return DeleteHistory{}, err
	}
	hashes, err := decodeFixedSequence(d, 16, 1_000_000)
	if err != nil {
		return DeleteHistory{}, err
	}
	n, err := d.Count(1_000_000)
	if err != nil {
		return DeleteHistory{}, err
	}
	for range n {
		if _, err = d.DQ(); err != nil {
			return DeleteHistory{}, err
		}
		if _, err = d.DQ(); err != nil {
			return DeleteHistory{}, err
		}
	}
	if _, err := d.DQ(); err != nil {
		return DeleteHistory{}, err
	}
	return DeleteHistory{FunctionHashes: hashes}, nil
}

func decodeFixedSequence(d *Decoder, width int, max uint32) ([][]byte, error) {
	n, err := d.Count(max)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for i := range out {
		out[i], err = d.Fixed(width)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func DecodeGetFuncHistories(payload []byte) (GetFuncHistories, error) {
	d := NewDecoder(payload)
	funcs, err := decodePullFunctions(d, 1_000_000)
	if err != nil {
		return GetFuncHistories{}, err
	}
	unknown, err := d.DD()
	return GetFuncHistories{Funcs: funcs, Unknown: unknown}, err
}

func EncodeFail(code uint32, message string) []byte {
	var e Encoder
	e.DD(code)
	e.CString(message)
	return e.Payload()
}

func EncodeHelloResult(features uint32) []byte {
	var e Encoder
	e.CString("")
	e.CString("")
	e.CString("")
	e.CString("")
	e.DD(0)
	e.DQ(0)
	e.DD(features)
	return e.Payload()
}

func EncodePullResult(status []uint32, funcs []PullResultFunction) []byte {
	var e Encoder
	e.U32s(status)
	e.DD(uint32(len(funcs)))
	for _, f := range funcs {
		e.CString(f.Name)
		e.DD(f.Length)
		e.Bytes(f.Metadata)
		e.DD(f.Popularity)
	}
	return e.Payload()
}

func EncodePushResult(status []uint32) []byte {
	var e Encoder
	e.U32s(status)
	return e.Payload()
}

func EncodeDeleteResult(deleted uint32) []byte {
	var e Encoder
	e.DD(deleted)
	return e.Payload()
}

func EncodeHistoriesResult(status []uint32, funcs [][]FunctionHistory) []byte {
	var e Encoder
	e.U32s(status)
	e.DD(uint32(len(funcs)))
	for _, histories := range funcs {
		e.DD(uint32(len(histories)))
		for _, h := range histories {
			e.DQ(0)
			e.DQ(0)
			e.CString(h.Name)
			e.Bytes(h.Metadata)
			e.DQ(h.Timestamp)
			e.DD(0)
			e.DD(0)
		}
	}
	e.Strings(nil)
	e.Strings(nil)
	return e.Payload()
}

func ValidateHash(hash []byte) error {
	if len(hash) != 16 {
		return fmt.Errorf("%w: expected 16-byte function hash, got %d", ErrInvalidData, len(hash))
	}
	return nil
}
