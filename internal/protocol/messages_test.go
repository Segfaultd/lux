package protocol

import (
	"bytes"
	"math"
	"testing"
)

func TestDecodePullMetadata(t *testing.T) {
	var e Encoder
	e.DD(8)
	e.U32s([]uint32{1, 2})
	e.DD(2)
	e.DD(3)
	e.Bytes(bytes.Repeat([]byte{0x11}, 16))
	e.DD(4)
	e.Bytes(bytes.Repeat([]byte{0x22}, 16))
	got, err := DecodePullMetadata(e.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if got.Unknown != 8 || len(got.Unknowns) != 2 || len(got.Funcs) != 2 ||
		got.Funcs[1].Unknown != 4 || got.Funcs[1].Hash[0] != 0x22 {
		t.Fatalf("unexpected pull request: %#v", got)
	}
}

func TestDecodePushMetadata(t *testing.T) {
	var e Encoder
	e.DD(1)
	e.CString("database.i64")
	e.CString("/samples/file.bin")
	e.Fixed(bytes.Repeat([]byte{0x44}, 16))
	e.CString("host")
	e.DD(1)
	e.CString("function")
	e.DD(123)
	e.Bytes([]byte{7, 8})
	e.DD(9)
	e.Bytes(bytes.Repeat([]byte{0x55}, 16))
	e.DD(2)
	e.DQ(10)
	e.DQ(math.MaxUint64)
	got, err := DecodePushMetadata(e.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if got.Unknown != 1 || got.IDBPath != "database.i64" || got.FilePath != "/samples/file.bin" ||
		got.MD5[0] != 0x44 || got.Hostname != "host" || len(got.Funcs) != 1 {
		t.Fatalf("unexpected push header: %#v", got)
	}
	f := got.Funcs[0]
	if f.Name != "function" || f.Length != 123 || !bytes.Equal(f.Metadata, []byte{7, 8}) ||
		f.Unknown != 9 || f.Hash[0] != 0x55 {
		t.Fatalf("unexpected pushed function: %#v", f)
	}
	if len(got.Trailing) != 2 || got.Trailing[1] != math.MaxUint64 {
		t.Fatalf("unexpected trailing values: %#v", got.Trailing)
	}
}

func TestDecodeDeleteHistory(t *testing.T) {
	var e Encoder
	e.DD(8)
	e.Strings([]string{"one"})
	for range 2 {
		e.DD(1)
		e.DQ(1)
		e.DQ(2)
	}
	for range 4 {
		e.Strings([]string{"value"})
	}
	e.DD(1)
	e.Fixed(bytes.Repeat([]byte{0xaa}, 16))
	e.DD(2)
	e.Fixed(bytes.Repeat([]byte{0xbb}, 16))
	e.Fixed(bytes.Repeat([]byte{0xcc}, 16))
	e.DD(1)
	e.DQ(3)
	e.DQ(4)
	e.DQ(5)
	got, err := DecodeDeleteHistory(e.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.FunctionHashes) != 2 || got.FunctionHashes[0][0] != 0xbb ||
		got.FunctionHashes[1][0] != 0xcc {
		t.Fatalf("unexpected delete hashes: %#v", got.FunctionHashes)
	}
}

func TestDecodeGetFuncHistories(t *testing.T) {
	var e Encoder
	e.DD(1)
	e.DD(7)
	e.Bytes(bytes.Repeat([]byte{0xdd}, 16))
	e.DD(9)
	got, err := DecodeGetFuncHistories(e.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Funcs) != 1 || got.Funcs[0].Unknown != 7 || got.Unknown != 9 {
		t.Fatalf("unexpected histories request: %#v", got)
	}
}

func TestResponseEncoders(t *testing.T) {
	t.Run("fail", func(t *testing.T) {
		d := NewDecoder(EncodeFail(3, "failed"))
		code, _ := d.DD()
		message, _ := d.CString()
		if code != 3 || message != "failed" || d.Remaining() != 0 {
			t.Fatalf("bad fail encoding: %d %q", code, message)
		}
	})
	t.Run("hello", func(t *testing.T) {
		d := NewDecoder(EncodeHelloResult(2))
		for range 4 {
			if _, err := d.CString(); err != nil {
				t.Fatal(err)
			}
		}
		if karma, _ := d.DD(); karma != 0 {
			t.Fatalf("karma %d", karma)
		}
		if active, _ := d.DQ(); active != 0 {
			t.Fatalf("last active %d", active)
		}
		if features, _ := d.DD(); features != 2 {
			t.Fatalf("features %d", features)
		}
	})
	t.Run("pull", func(t *testing.T) {
		payload := EncodePullResult([]uint32{0, 1}, []PullResultFunction{{
			Name: "known", Length: 44, Metadata: []byte{1, 2}, Popularity: 3,
		}})
		d := NewDecoder(payload)
		status, _ := d.U32s(10)
		count, _ := d.Count(10)
		name, _ := d.CString()
		length, _ := d.DD()
		md, _ := d.Bytes()
		popularity, _ := d.DD()
		if len(status) != 2 || status[1] != 1 || count != 1 || name != "known" ||
			length != 44 || !bytes.Equal(md, []byte{1, 2}) || popularity != 3 {
			t.Fatalf("bad pull encoding")
		}
	})
	t.Run("push and delete", func(t *testing.T) {
		d := NewDecoder(EncodePushResult([]uint32{1, 0}))
		status, _ := d.U32s(10)
		if len(status) != 2 || status[0] != 1 {
			t.Fatalf("bad push encoding: %v", status)
		}
		d = NewDecoder(EncodeDeleteResult(7))
		if deleted, _ := d.DD(); deleted != 7 {
			t.Fatalf("bad delete encoding: %d", deleted)
		}
	})
	t.Run("histories", func(t *testing.T) {
		payload := EncodeHistoriesResult([]uint32{1}, [][]FunctionHistory{{{
			Name: "old_name", Metadata: []byte{9}, Timestamp: 1234,
		}}})
		d := NewDecoder(payload)
		status, _ := d.U32s(10)
		groups, _ := d.Count(10)
		logs, _ := d.Count(10)
		first, _ := d.DQ()
		second, _ := d.DQ()
		name, _ := d.CString()
		md, _ := d.Bytes()
		timestamp, _ := d.DQ()
		author, _ := d.DD()
		database, _ := d.DD()
		users, _ := d.Strings(10)
		dbs, _ := d.Strings(10)
		if status[0] != 1 || groups != 1 || logs != 1 || first != 0 || second != 0 ||
			name != "old_name" || md[0] != 9 || timestamp != 1234 || author != 0 ||
			database != 0 || len(users) != 0 || len(dbs) != 0 {
			t.Fatalf("bad histories encoding")
		}
	})
}

func TestMessageDecodeErrors(t *testing.T) {
	decoders := []struct {
		name string
		call func([]byte) error
	}{
		{"hello", func(v []byte) error { _, err := DecodeHello(v); return err }},
		{"pull", func(v []byte) error { _, err := DecodePullMetadata(v); return err }},
		{"push", func(v []byte) error { _, err := DecodePushMetadata(v); return err }},
		{"delete", func(v []byte) error { _, err := DecodeDeleteHistory(v); return err }},
		{"histories", func(v []byte) error { _, err := DecodeGetFuncHistories(v); return err }},
	}
	for _, decoder := range decoders {
		t.Run(decoder.name, func(t *testing.T) {
			if err := decoder.call(nil); err == nil {
				t.Fatal("expected truncated payload error")
			}
		})
	}
	if ValidateHash(make([]byte, 16)) != nil {
		t.Fatal("valid hash rejected")
	}
	if ValidateHash(make([]byte, 15)) == nil {
		t.Fatal("invalid hash accepted")
	}
}
