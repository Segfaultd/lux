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
	if got.Flags != 8 || len(got.Unknowns) != 2 || len(got.Funcs) != 2 ||
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
	if got.Flags != 1 || got.IDBPath != "database.i64" || got.FilePath != "/samples/file.bin" ||
		got.MD5[0] != 0x44 || got.Hostname != "host" || len(got.Funcs) != 1 {
		t.Fatalf("unexpected push header: %#v", got)
	}
	f := got.Funcs[0]
	if f.Name != "function" || f.Length != 123 || !bytes.Equal(f.Metadata, []byte{7, 8}) ||
		f.Unknown != 9 || f.Hash[0] != 0x55 {
		t.Fatalf("unexpected pushed function: %#v", f)
	}
	if len(got.Addresses) != 2 || got.Addresses[1] != math.MaxUint64 {
		t.Fatalf("unexpected function addresses: %#v", got.Addresses)
	}
}

func TestDecodePushMetadataRejectsUnknownMode(t *testing.T) {
	var encoded Encoder
	encoded.DD(4)
	if _, err := DecodePushMetadata(encoded.Payload()); err == nil {
		t.Fatal("unsupported push mode was accepted")
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
		d := NewDecoder(EncodeHelloResult(LuminaUser{
			LicenseID: "AB-1234-CDEF-90", LicenseName: "Analyst",
			Email: "analyst@example.test", Username: "analyst",
			Karma: -2, LastActive: 123, Features: UserIsAdmin | UserCanDeleteHistory,
		}))
		licenseID, _ := d.CString()
		licenseName, _ := d.CString()
		email, _ := d.CString()
		username, _ := d.CString()
		if licenseID != "AB-1234-CDEF-90" || licenseName != "Analyst" ||
			email != "analyst@example.test" || username != "analyst" {
			t.Fatalf("bad user profile %q %q %q %q", licenseID, licenseName, email, username)
		}
		if karma, _ := d.DD(); karma != ^uint32(1) {
			t.Fatalf("karma %d", karma)
		}
		if active, _ := d.DQ(); active != 123 {
			t.Fatalf("last active %d", active)
		}
		if features, _ := d.DD(); features != 3 {
			t.Fatalf("features %d", features)
		}
	})
	t.Run("popular functions", func(t *testing.T) {
		md5 := [16]byte{1, 2, 3}
		payload := EncodePopularResult([]PopularFunction{{
			Name: "popular", Length: 64, Metadata: []byte{4, 5},
			PatternType: 1, Pattern: []byte{6, 7}, Frequency: 99,
			Hostname: "host", FilePath: "/sample.bin", FileMD5: md5, Address: 0x401000,
		}})
		d := NewDecoder(payload)
		count, _ := d.DD()
		name, _ := d.CString()
		length, _ := d.DD()
		metadata, _ := d.Bytes()
		patternType, _ := d.DD()
		pattern, _ := d.Bytes()
		frequency, _ := d.DD()
		hostname, _ := d.CString()
		filePath, _ := d.CString()
		gotMD5, _ := d.Fixed(16)
		address, _ := d.DQ()
		if count != 1 || name != "popular" || length != 64 ||
			!bytes.Equal(metadata, []byte{4, 5}) || patternType != 1 ||
			!bytes.Equal(pattern, []byte{6, 7}) || frequency != 99 ||
			hostname != "host" || filePath != "/sample.bin" ||
			!bytes.Equal(gotMD5, md5[:]) || address != 0x401000 || d.Remaining() != 0 {
			t.Fatal("bad popular-functions encoding")
		}
	})
	t.Run("server info", func(t *testing.T) {
		payload := EncodeLuminaInfoResult(LuminaConnectionInfo{
			SessionID: 7, PeerName: "192.0.2.1:1234",
			User:        LuminaUser{Username: "analyst", Features: UserIsAdmin},
			Established: 11, ServerMAC: "00:11:22:33:44:55",
			ServerVersion: "lux-test", ServerStarted: 12, ServerTime: 13,
		})
		d := NewDecoder(payload)
		sessionID, _ := d.DD()
		peer, _ := d.CString()
		for range 3 {
			_, _ = d.CString()
		}
		username, _ := d.CString()
		_, _ = d.DD()
		_, _ = d.DQ()
		features, _ := d.DD()
		established, _ := d.DQ()
		mac, _ := d.CString()
		version, _ := d.CString()
		started, _ := d.DQ()
		current, _ := d.DQ()
		if sessionID != 7 || peer != "192.0.2.1:1234" || username != "analyst" ||
			features != UserIsAdmin || established != 11 ||
			mac != "00:11:22:33:44:55" || version != "lux-test" ||
			started != 12 || current != 13 || d.Remaining() != 0 {
			t.Fatal("bad server-info encoding")
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
		{"popular", func(v []byte) error { _, err := DecodeGetPopular(v); return err }},
		{"delete", func(v []byte) error { _, err := DecodeDeleteHistory(v); return err }},
		{"histories", func(v []byte) error { _, err := DecodeGetFuncHistories(v); return err }},
	}
	var popular Encoder
	popular.DD(1001)
	if _, err := DecodeGetPopular(popular.Payload()); err == nil {
		t.Fatal("oversized popular-functions request accepted")
	}
	var trailingPopular Encoder
	trailingPopular.DD(1)
	trailingPopular.DD(1)
	if _, err := DecodeGetPopular(trailingPopular.Payload()); err == nil {
		t.Fatal("popular-functions request with trailing data accepted")
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
