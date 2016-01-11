// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/errors"
)

func readerFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("readerFromHex: bad input")
	}
	return bytes.NewBuffer(data)
}

func TestReadKeyRing(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 2 || uint32(kring[0].PrimaryKey.KeyId) != 0xC20C31BB || uint32(kring[1].PrimaryKey.KeyId) != 0x1E35246B {
		t.Errorf("bad keyring: %#v", kring)
	}
}

func TestRereadKeyRing(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	if err != nil {
		t.Errorf("error in initial parse: %s", err)
		return
	}
	out := new(bytes.Buffer)
	err = kring[0].Serialize(out)
	if err != nil {
		t.Errorf("error in serialization: %s", err)
		return
	}
	kring, err = ReadKeyRing(out)
	if err != nil {
		t.Errorf("error in second parse: %s", err)
		return
	}

	if len(kring) != 1 || uint32(kring[0].PrimaryKey.KeyId) != 0xC20C31BB {
		t.Errorf("bad keyring: %#v", kring)
	}
}

func TestReadPrivateKeyRing(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 2 || uint32(kring[0].PrimaryKey.KeyId) != 0xC20C31BB || uint32(kring[1].PrimaryKey.KeyId) != 0x1E35246B || kring[0].PrimaryKey == nil {
		t.Errorf("bad keyring: %#v", kring)
	}
}

func TestReadDSAKey(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(dsaTestKeyHex))
	if err != nil {
		t.Error(err)
		return
	}
	if len(kring) != 1 || uint32(kring[0].PrimaryKey.KeyId) != 0x0CCC0360 {
		t.Errorf("bad parse: %#v", kring)
	}
}

func TestDSAHashTruncatation(t *testing.T) {
	// dsaKeyWithSHA512 was generated with GnuPG and --cert-digest-algo
	// SHA512 in order to require DSA hash truncation to verify correctly.
	_, err := ReadKeyRing(readerFromHex(dsaKeyWithSHA512))
	if err != nil {
		t.Error(err)
	}
}

func TestGetKeyById(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))

	keys := kring.KeysById(0xa34d7e18c20c31bb)
	if len(keys) != 1 || keys[0].Entity != kring[0] {
		t.Errorf("bad result for 0xa34d7e18c20c31bb: %#v", keys)
	}

	keys = kring.KeysById(0xfd94408d4543314f)
	if len(keys) != 1 || keys[0].Entity != kring[0] {
		t.Errorf("bad result for 0xa34d7e18c20c31bb: %#v", keys)
	}
}

func checkSignedMessage(t *testing.T, signedHex, expected string) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))

	md, err := ReadMessage(readerFromHex(signedHex), kring, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	if !md.IsSigned || md.SignedByKeyId != 0xa34d7e18c20c31bb || md.SignedBy == nil || md.IsEncrypted || md.IsSymmetricallyEncrypted || len(md.EncryptedToKeyIds) != 0 || md.IsSymmetricallyEncrypted {
		t.Errorf("bad MessageDetails: %#v", md)
	}

	contents, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}
	if string(contents) != expected {
		t.Errorf("bad UnverifiedBody got:%s want:%s", string(contents), expected)
	}
	if md.SignatureError != nil || md.Signature == nil {
		t.Errorf("failed to validate: %s", md.SignatureError)
	}
}

func TestSignedMessage(t *testing.T) {
	checkSignedMessage(t, signedMessageHex, signedInput)
}

func TestTextSignedMessage(t *testing.T) {
	checkSignedMessage(t, signedTextMessageHex, signedTextInput)
}

// The reader should detect "compressed quines", which are compressed
// packets that expand into themselves and cause an infinite recursive
// parsing loop.
// The packet in this test case comes from Taylor R. Campbell at
// http://mumble.net/~campbell/misc/pgp-quine/
func TestCampbellQuine(t *testing.T) {
	md, err := ReadMessage(readerFromHex(campbellQuine), nil, nil, nil)
	if md != nil {
		t.Errorf("Reading a compressed quine should not return any data: %#v", md)
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T", err)
	}
	if !strings.Contains(string(structural), "too many layers of packets") {
		t.Fatalf("Unexpected error: %s", err)
	}
}

var signedEncryptedMessageTests = []struct {
	keyRingHex       string
	messageHex       string
	signedByKeyId    uint64
	encryptedToKeyId uint64
}{
	{
		testKeys1And2PrivateHex,
		signedEncryptedMessageHex,
		0xa34d7e18c20c31bb,
		0x2a67d68660df41c7,
	},
	{
		dsaElGamalTestKeysHex,
		signedEncryptedMessage2Hex,
		0x33af447ccd759b09,
		0xcf6a7abcd43e3673,
	},
}

func TestSignedEncryptedMessage(t *testing.T) {
	for i, test := range signedEncryptedMessageTests {
		expected := "Signed and encrypted message\n"
		kring, _ := ReadKeyRing(readerFromHex(test.keyRingHex))
		prompt := func(keys []Key, symmetric bool) ([]byte, error) {
			if symmetric {
				t.Errorf("prompt: message was marked as symmetrically encrypted")
				return nil, errors.ErrKeyIncorrect
			}

			if len(keys) == 0 {
				t.Error("prompt: no keys requested")
				return nil, errors.ErrKeyIncorrect
			}

			err := keys[0].PrivateKey.Decrypt([]byte("passphrase"))
			if err != nil {
				t.Errorf("prompt: error decrypting key: %s", err)
				return nil, errors.ErrKeyIncorrect
			}

			return nil, nil
		}

		md, err := ReadMessage(readerFromHex(test.messageHex), kring, prompt, nil)
		if err != nil {
			t.Errorf("#%d: error reading message: %s", i, err)
			return
		}

		if !md.IsSigned || md.SignedByKeyId != test.signedByKeyId || md.SignedBy == nil || !md.IsEncrypted || md.IsSymmetricallyEncrypted || len(md.EncryptedToKeyIds) == 0 || md.EncryptedToKeyIds[0] != test.encryptedToKeyId {
			t.Errorf("#%d: bad MessageDetails: %#v", i, md)
		}

		contents, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			t.Errorf("#%d: error reading UnverifiedBody: %s", i, err)
		}
		if string(contents) != expected {
			t.Errorf("#%d: bad UnverifiedBody got:%s want:%s", i, string(contents), expected)
		}

		if md.SignatureError != nil || md.Signature == nil {
			t.Errorf("#%d: failed to validate: %s", i, md.SignatureError)
		}
	}
}

func TestUnspecifiedRecipient(t *testing.T) {
	expected := "Recipient unspecified\n"
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))

	md, err := ReadMessage(readerFromHex(recipientUnspecifiedHex), kring, nil, nil)
	if err != nil {
		t.Errorf("error reading message: %s", err)
		return
	}

	contents, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}
	if string(contents) != expected {
		t.Errorf("bad UnverifiedBody got:%s want:%s", string(contents), expected)
	}
}

func TestSymmetricallyEncrypted(t *testing.T) {
	firstTimeCalled := true

	prompt := func(keys []Key, symmetric bool) ([]byte, error) {
		if len(keys) != 0 {
			t.Errorf("prompt: len(keys) = %d (want 0)", len(keys))
		}

		if !symmetric {
			t.Errorf("symmetric is not set")
		}

		if firstTimeCalled {
			firstTimeCalled = false
			return []byte("wrongpassword"), nil
		}

		return []byte("password"), nil
	}

	md, err := ReadMessage(readerFromHex(symmetricallyEncryptedCompressedHex), nil, prompt, nil)
	if err != nil {
		t.Errorf("ReadMessage: %s", err)
		return
	}

	contents, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("ReadAll: %s", err)
	}

	expectedCreationTime := uint32(1295992998)
	if md.LiteralData.Time != expectedCreationTime {
		t.Errorf("LiteralData.Time is %d, want %d", md.LiteralData.Time, expectedCreationTime)
	}

	const expected = "Symmetrically encrypted.\n"
	if string(contents) != expected {
		t.Errorf("contents got: %s want: %s", string(contents), expected)
	}
}

func testDetachedSignature(t *testing.T, kring KeyRing, signature io.Reader, sigInput, tag string, expectedSignerKeyId uint64) {
	signed := bytes.NewBufferString(sigInput)
	signer, err := CheckDetachedSignature(kring, signed, signature)
	if err != nil {
		t.Errorf("%s: signature error: %s", tag, err)
		return
	}
	if signer == nil {
		t.Errorf("%s: signer is nil", tag)
		return
	}
	if signer.PrimaryKey.KeyId != expectedSignerKeyId {
		t.Errorf("%s: wrong signer got:%x want:%x", tag, signer.PrimaryKey.KeyId, expectedSignerKeyId)
	}
}

func TestDetachedSignature(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureHex), signedInput, "binary", testKey1KeyId)
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureTextHex), signedInput, "text", testKey1KeyId)
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureV3TextHex), signedInput, "v3", testKey1KeyId)

	incorrectSignedInput := signedInput + "X"
	_, err := CheckDetachedSignature(kring, bytes.NewBufferString(incorrectSignedInput), readerFromHex(detachedSignatureHex))
	if err == nil {
		t.Fatal("CheckDetachedSignature returned without error for bad signature")
	}
	if err == errors.ErrUnknownIssuer {
		t.Fatal("CheckDetachedSignature returned ErrUnknownIssuer when the signer was known, but the signature invalid")
	}
}

func TestDetachedSignatureDSA(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(dsaTestKeyHex))
	testDetachedSignature(t, kring, readerFromHex(detachedSignatureDSAHex), signedInput, "binary", testKey3KeyId)
}

func TestMultipleSignaturePacketsDSA(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(dsaTestKeyHex))
	testDetachedSignature(t, kring, readerFromHex(missingHashFunctionHex+detachedSignatureDSAHex), signedInput, "binary", testKey3KeyId)
}

func testHashFunctionError(t *testing.T, signatureHex string) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	_, err := CheckDetachedSignature(kring, nil, readerFromHex(signatureHex))
	if err == nil {
		t.Fatal("Packet with bad hash type was correctly parsed")
	}
	unsupported, ok := err.(errors.UnsupportedError)
	if !ok {
		t.Fatalf("Unexpected class of error: %s", err)
	}
	if !strings.Contains(string(unsupported), "hash ") {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestUnknownHashFunction(t *testing.T) {
	// unknownHashFunctionHex contains a signature packet with hash
	// function type 153 (which isn't a real hash function id).
	testHashFunctionError(t, unknownHashFunctionHex)
}

func TestMissingHashFunction(t *testing.T) {
	// missingHashFunctionHex contains a signature packet that uses
	// RIPEMD160, which isn't compiled in.  Since that's the only signature
	// packet we don't find any suitable packets and end up with ErrUnknownIssuer
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	_, err := CheckDetachedSignature(kring, nil, readerFromHex(missingHashFunctionHex))
	if err == nil {
		t.Fatal("Packet with missing hash type was correctly parsed")
	}
	if err != errors.ErrUnknownIssuer {
		t.Fatalf("Unexpected class of error: %s", err)
	}
}

func TestReadingArmoredPrivateKey(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(armoredPrivateKeyBlock))
	if err != nil {
		t.Error(err)
	}
	if len(el) != 1 {
		t.Errorf("got %d entities, wanted 1\n", len(el))
	}
}

func rawToArmored(raw []byte, priv bool) (ret string, err error) {

	var writer io.WriteCloser
	var out bytes.Buffer
	var which string

	if priv {
		which = "PRIVATE"
	} else {
		which = "PUBLIC"
	}
	hdr := fmt.Sprintf("PGP %s KEY BLOCK", which)

	writer, err = armor.Encode(&out, hdr, nil)

	if err != nil {
		return
	}
	if _, err = writer.Write(raw); err != nil {
		return
	}
	writer.Close()
	ret = out.String()
	return
}

func trySigning(e *Entity) (string, error) {
	txt := bytes.NewBufferString("Thou still unravish'd bride of quietness, Thou foster-child of silence and slow time,")
	var out bytes.Buffer
	err := ArmoredDetachSign(&out, e, txt, nil)
	return out.String(), err
}

func TestSigningSubkey(t *testing.T) {
	k := openPrivateKey(t, signingSubkey, signingSubkeyPassphrase, true, 2)
	_, err := trySigning(k)
	if err != nil {
		t.Fatal(err)
	}
}

func openPrivateKey(t *testing.T, armoredKey string, passphrase string, protected bool, nSubkeys int) *Entity {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(armoredKey))
	if err != nil {
		t.Error(err)
	}
	if len(el) != 1 {
		t.Fatalf("got %d entities, wanted 1\n", len(el))
	}
	k := el[0]
	if k.PrivateKey == nil {
		t.Fatalf("Got nil key, but wanted a private key")
	}
	if err := k.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
		t.Fatalf("failed to decrypt key: %s", err)
	}
	if err := k.PrivateKey.Decrypt([]byte(passphrase + "X")); err != nil {
		t.Fatalf("failed to decrypt key with the wrong key (it shouldn't matter): %s", err)
	}

	decryptions := 0

	// Also decrypt all subkeys (with the same password)
	for i, subkey := range k.Subkeys {
		priv := subkey.PrivateKey
		if priv == nil {
			t.Fatalf("unexpected nil subkey @%d", i)
		}
		err := priv.Decrypt([]byte(passphrase + "X"))

		if protected && err == nil {
			t.Fatalf("expected subkey decryption to fail on %d with bad PW\n", i)
		} else if !protected && err != nil {
			t.Fatalf("Without passphrase-protection, decryption shouldn't fail")
		}
		if err := priv.Decrypt([]byte(passphrase)); err != nil {
			t.Fatalf("failed to decrypt subkey %d: %s\n", i, err)
		} else {
			decryptions++
		}
	}
	if decryptions != nSubkeys {
		t.Fatalf("expected %d decryptions; got %d", nSubkeys, decryptions)
	}
	return k
}

func testGnuS2KDummy(t *testing.T, keyString string, passphrase string, nSubkeys int) *Entity {

	key := openPrivateKey(t, keyString, passphrase, true, nSubkeys)

	var buf bytes.Buffer
	err := key.SerializePrivate(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}

	armored, err := rawToArmored(buf.Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}

	return openPrivateKey(t, armored, passphrase, false, nSubkeys)
}

func TestGnuS2KDummyEncryptionSubkey(t *testing.T) {
	key := testGnuS2KDummy(t, gnuDummyS2KPrivateKey, gnuDummyS2KPrivateKeyPassphrase, 1)
	_, err := trySigning(key)
	if err == nil {
		t.Fatal("Expected a signing failure, since we don't have a signing key")
	}
}

func TestGNUS2KDummySigningSubkey(t *testing.T) {
	key := testGnuS2KDummy(t, gnuDummyS2KPrivateKeyWithSigningSubkey, gnuDummyS2KPrivateKeyWithSigningSubkeyPassphrase, 2)
	_, err := trySigning(key)
	if err != nil {
		t.Fatal("Got a signing failure: %s\n", err)
	}
}

func TestReadingArmoredPublicKey(t *testing.T) {
	el, err := ReadArmoredKeyRing(bytes.NewBufferString(e2ePublicKey))
	if err != nil {
		t.Error(err)
	}
	if len(el) != 1 {
		t.Errorf("didn't get a valid entity")
	}
}

func TestNoArmoredData(t *testing.T) {
	_, err := ReadArmoredKeyRing(bytes.NewBufferString("foo"))
	if _, ok := err.(errors.InvalidArgumentError); !ok {
		t.Errorf("error was not an InvalidArgumentError: %s", err)
	}
}

func testReadMessageError(t *testing.T, messageHex string) {
	buf, err := hex.DecodeString(messageHex)
	if err != nil {
		t.Errorf("hex.DecodeString(): %v", err)
	}

	kr, err := ReadKeyRing(new(bytes.Buffer))
	if err != nil {
		t.Errorf("ReadKeyring(): %v", err)
	}

	_, err = ReadMessage(bytes.NewBuffer(buf), kr,
		func([]Key, bool) ([]byte, error) {
			return []byte("insecure"), nil
		}, nil)

	if err == nil {
		t.Errorf("ReadMessage(): Unexpected nil error")
	}
}

func TestIssue11503(t *testing.T) {
	testReadMessageError(t, "8c040402000aa430aa8228b9248b01fc899a91197130303030")
}

func TestIssue11504(t *testing.T) {
	testReadMessageError(t, "9303000130303030303030303030983002303030303030030000000130")
}

// TestSignatureV3Message tests the verification of V3 signature, generated
// with a modern V4-style key.  Some people have their clients set to generate
// V3 signatures, so it's useful to be able to verify them.
func TestSignatureV3Message(t *testing.T) {
	sig, err := armor.Decode(strings.NewReader(signedMessageV3))
	if err != nil {
		t.Error(err)
		return
	}
	key, err := ReadArmoredKeyRing(strings.NewReader(keyV4forVerifyingSignedMessageV3))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(sig.Body, key, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}

	// We'll see a sig error here after reading in the UnverifiedBody above,
	// if there was one to see.
	if err = md.SignatureError; err != nil {
		t.Error(err)
		return
	}

	if md.SignatureV3 == nil {
		t.Errorf("No available signature after checking signature")
		return
	}
	if md.Signature != nil {
		t.Errorf("Did not expect a signature V4 back")
		return
	}
	return
}

func TestEdDSA(t *testing.T) {
	key, err := ReadArmoredKeyRing(strings.NewReader(eddsaPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.Decode(strings.NewReader(eddsaSignature))
	if err != nil {
		t.Fatal(err)
	}

	md, err := ReadMessage(sig.Body, key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	literalData, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}

	// We'll see a sig error here after reading in the UnverifiedBody above,
	// if there was one to see.
	if err = md.SignatureError; err != nil {
		t.Fatal(err)
	}

	if md.Signature == nil {
		t.Fatalf("No available signature after checking signature")
	}

	if string(literalData) != eddsaSignedMsg {
		t.Fatal("got wrong signed message")
	}
	return
}

func testKey(t *testing.T, key string, which string) {
	_, err := ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		t.Fatalf("for user %s: %v", which, err)
	}
}

func TestKeyHashMismatch(t *testing.T) {
	testKey(t, freacky22527Key, "freacky22527Key")

}

func TestCrossSignature(t *testing.T) {
	testKey(t, themaxKey, "themaxKey")
	testKey(t, kaylabsKey, "kaylabsKey")
}

func TestBadSignatureValue(t *testing.T) {
	testKey(t, reviKey, "reviKey")
}

const testKey1KeyId = 0xA34D7E18C20C31BB
const testKey3KeyId = 0x338934250CCC0360

const signedInput = "Signed message\nline 2\nline 3\n"
const signedTextInput = "Signed message\r\nline 2\r\nline 3\r\n"

const recipientUnspecifiedHex = "848c0300000000000000000103ff62d4d578d03cf40c3da998dfe216c074fa6ddec5e31c197c9666ba292830d91d18716a80f699f9d897389a90e6d62d0238f5f07a5248073c0f24920e4bc4a30c2d17ee4e0cae7c3d4aaa4e8dced50e3010a80ee692175fa0385f62ecca4b56ee6e9980aa3ec51b61b077096ac9e800edaf161268593eedb6cc7027ff5cb32745d250010d407a6221ae22ef18469b444f2822478c4d190b24d36371a95cb40087cdd42d9399c3d06a53c0673349bfb607927f20d1e122bde1e2bf3aa6cae6edf489629bcaa0689539ae3b718914d88ededc3b"

const detachedSignatureHex = "889c04000102000605024d449cd1000a0910a34d7e18c20c31bb167603ff57718d09f28a519fdc7b5a68b6a3336da04df85e38c5cd5d5bd2092fa4629848a33d85b1729402a2aab39c3ac19f9d573f773cc62c264dc924c067a79dfd8a863ae06c7c8686120760749f5fd9b1e03a64d20a7df3446ddc8f0aeadeaeba7cbaee5c1e366d65b6a0c6cc749bcb912d2f15013f812795c2e29eb7f7b77f39ce77"

const detachedSignatureTextHex = "889c04010102000605024d449d21000a0910a34d7e18c20c31bbc8c60400a24fbef7342603a41cb1165767bd18985d015fb72fe05db42db36cfb2f1d455967f1e491194fbf6cf88146222b23bf6ffbd50d17598d976a0417d3192ff9cc0034fd00f287b02e90418bbefe609484b09231e4e7a5f3562e199bf39909ab5276c4d37382fe088f6b5c3426fc1052865da8b3ab158672d58b6264b10823dc4b39"

const detachedSignatureV3TextHex = "8900950305005255c25ca34d7e18c20c31bb0102bb3f04009f6589ef8a028d6e54f6eaf25432e590d31c3a41f4710897585e10c31e5e332c7f9f409af8512adceaff24d0da1474ab07aa7bce4f674610b010fccc5b579ae5eb00a127f272fb799f988ab8e4574c141da6dbfecfef7e6b2c478d9a3d2551ba741f260ee22bec762812f0053e05380bfdd55ad0f22d8cdf71b233fe51ae8a24"

const detachedSignatureDSAHex = "884604001102000605024d6c4eac000a0910338934250ccc0360f18d00a087d743d6405ed7b87755476629600b8b694a39e900a0abff8126f46faf1547c1743c37b21b4ea15b8f83"

const testKeys1And2Hex = "988d044d3c5c10010400b1d13382944bd5aba23a4312968b5095d14f947f600eb478e14a6fcb16b0e0cac764884909c020bc495cfcc39a935387c661507bdb236a0612fb582cac3af9b29cc2c8c70090616c41b662f4da4c1201e195472eb7f4ae1ccbcbf9940fe21d985e379a5563dde5b9a23d35f1cfaa5790da3b79db26f23695107bfaca8e7b5bcd0011010001b41054657374204b6579203120285253412988b804130102002205024d3c5c10021b03060b090807030206150802090a0b0416020301021e01021780000a0910a34d7e18c20c31bbb5b304009cc45fe610b641a2c146331be94dade0a396e73ca725e1b25c21708d9cab46ecca5ccebc23055879df8f99eea39b377962a400f2ebdc36a7c99c333d74aeba346315137c3ff9d0a09b0273299090343048afb8107cf94cbd1400e3026f0ccac7ecebbc4d78588eb3e478fe2754d3ca664bcf3eac96ca4a6b0c8d7df5102f60f6b0020003b88d044d3c5c10010400b201df61d67487301f11879d514f4248ade90c8f68c7af1284c161098de4c28c2850f1ec7b8e30f959793e571542ffc6532189409cb51c3d30dad78c4ad5165eda18b20d9826d8707d0f742e2ab492103a85bbd9ddf4f5720f6de7064feb0d39ee002219765bb07bcfb8b877f47abe270ddeda4f676108cecb6b9bb2ad484a4f0011010001889f04180102000905024d3c5c10021b0c000a0910a34d7e18c20c31bb1a03040085c8d62e16d05dc4e9dad64953c8a2eed8b6c12f92b1575eeaa6dcf7be9473dd5b24b37b6dffbb4e7c99ed1bd3cb11634be19b3e6e207bed7505c7ca111ccf47cb323bf1f8851eb6360e8034cbff8dd149993c959de89f8f77f38e7e98b8e3076323aa719328e2b408db5ec0d03936efd57422ba04f925cdc7b4c1af7590e40ab0020003988d044d3c5c33010400b488c3e5f83f4d561f317817538d9d0397981e9aef1321ca68ebfae1cf8b7d388e19f4b5a24a82e2fbbf1c6c26557a6c5845307a03d815756f564ac7325b02bc83e87d5480a8fae848f07cb891f2d51ce7df83dcafdc12324517c86d472cc0ee10d47a68fd1d9ae49a6c19bbd36d82af597a0d88cc9c49de9df4e696fc1f0b5d0011010001b42754657374204b6579203220285253412c20656e637279707465642070726976617465206b65792988b804130102002205024d3c5c33021b03060b090807030206150802090a0b0416020301021e01021780000a0910d4984f961e35246b98940400908a73b6a6169f700434f076c6c79015a49bee37130eaf23aaa3cfa9ce60bfe4acaa7bc95f1146ada5867e0079babb38804891f4f0b8ebca57a86b249dee786161a755b7a342e68ccf3f78ed6440a93a6626beb9a37aa66afcd4f888790cb4bb46d94a4ae3eb3d7d3e6b00f6bfec940303e89ec5b32a1eaaacce66497d539328b0020003b88d044d3c5c33010400a4e913f9442abcc7f1804ccab27d2f787ffa592077ca935a8bb23165bd8d57576acac647cc596b2c3f814518cc8c82953c7a4478f32e0cf645630a5ba38d9618ef2bc3add69d459ae3dece5cab778938d988239f8c5ae437807075e06c828019959c644ff05ef6a5a1dab72227c98e3a040b0cf219026640698d7a13d8538a570011010001889f04180102000905024d3c5c33021b0c000a0910d4984f961e35246b26c703ff7ee29ef53bc1ae1ead533c408fa136db508434e233d6e62be621e031e5940bbd4c08142aed0f82217e7c3e1ec8de574bc06ccf3c36633be41ad78a9eacd209f861cae7b064100758545cc9dd83db71806dc1cfd5fb9ae5c7474bba0c19c44034ae61bae5eca379383339dece94ff56ff7aa44a582f3e5c38f45763af577c0934b0020003"

const testKeys1And2PrivateHex = "9501d8044d3c5c10010400b1d13382944bd5aba23a4312968b5095d14f947f600eb478e14a6fcb16b0e0cac764884909c020bc495cfcc39a935387c661507bdb236a0612fb582cac3af9b29cc2c8c70090616c41b662f4da4c1201e195472eb7f4ae1ccbcbf9940fe21d985e379a5563dde5b9a23d35f1cfaa5790da3b79db26f23695107bfaca8e7b5bcd00110100010003ff4d91393b9a8e3430b14d6209df42f98dc927425b881f1209f319220841273a802a97c7bdb8b3a7740b3ab5866c4d1d308ad0d3a79bd1e883aacf1ac92dfe720285d10d08752a7efe3c609b1d00f17f2805b217be53999a7da7e493bfc3e9618fd17018991b8128aea70a05dbce30e4fbe626aa45775fa255dd9177aabf4df7cf0200c1ded12566e4bc2bb590455e5becfb2e2c9796482270a943343a7835de41080582c2be3caf5981aa838140e97afa40ad652a0b544f83eb1833b0957dce26e47b0200eacd6046741e9ce2ec5beb6fb5e6335457844fb09477f83b050a96be7da043e17f3a9523567ed40e7a521f818813a8b8a72209f1442844843ccc7eb9805442570200bdafe0438d97ac36e773c7162028d65844c4d463e2420aa2228c6e50dc2743c3d6c72d0d782a5173fe7be2169c8a9f4ef8a7cf3e37165e8c61b89c346cdc6c1799d2b41054657374204b6579203120285253412988b804130102002205024d3c5c10021b03060b090807030206150802090a0b0416020301021e01021780000a0910a34d7e18c20c31bbb5b304009cc45fe610b641a2c146331be94dade0a396e73ca725e1b25c21708d9cab46ecca5ccebc23055879df8f99eea39b377962a400f2ebdc36a7c99c333d74aeba346315137c3ff9d0a09b0273299090343048afb8107cf94cbd1400e3026f0ccac7ecebbc4d78588eb3e478fe2754d3ca664bcf3eac96ca4a6b0c8d7df5102f60f6b00200009d01d8044d3c5c10010400b201df61d67487301f11879d514f4248ade90c8f68c7af1284c161098de4c28c2850f1ec7b8e30f959793e571542ffc6532189409cb51c3d30dad78c4ad5165eda18b20d9826d8707d0f742e2ab492103a85bbd9ddf4f5720f6de7064feb0d39ee002219765bb07bcfb8b877f47abe270ddeda4f676108cecb6b9bb2ad484a4f00110100010003fd17a7490c22a79c59281fb7b20f5e6553ec0c1637ae382e8adaea295f50241037f8997cf42c1ce26417e015091451b15424b2c59eb8d4161b0975630408e394d3b00f88d4b4e18e2cc85e8251d4753a27c639c83f5ad4a571c4f19d7cd460b9b73c25ade730c99df09637bd173d8e3e981ac64432078263bb6dc30d3e974150dd0200d0ee05be3d4604d2146fb0457f31ba17c057560785aa804e8ca5530a7cd81d3440d0f4ba6851efcfd3954b7e68908fc0ba47f7ac37bf559c6c168b70d3a7c8cd0200da1c677c4bce06a068070f2b3733b0a714e88d62aa3f9a26c6f5216d48d5c2b5624144f3807c0df30be66b3268eeeca4df1fbded58faf49fc95dc3c35f134f8b01fd1396b6c0fc1b6c4f0eb8f5e44b8eace1e6073e20d0b8bc5385f86f1cf3f050f66af789f3ef1fc107b7f4421e19e0349c730c68f0a226981f4e889054fdb4dc149e8e889f04180102000905024d3c5c10021b0c000a0910a34d7e18c20c31bb1a03040085c8d62e16d05dc4e9dad64953c8a2eed8b6c12f92b1575eeaa6dcf7be9473dd5b24b37b6dffbb4e7c99ed1bd3cb11634be19b3e6e207bed7505c7ca111ccf47cb323bf1f8851eb6360e8034cbff8dd149993c959de89f8f77f38e7e98b8e3076323aa719328e2b408db5ec0d03936efd57422ba04f925cdc7b4c1af7590e40ab00200009501fe044d3c5c33010400b488c3e5f83f4d561f317817538d9d0397981e9aef1321ca68ebfae1cf8b7d388e19f4b5a24a82e2fbbf1c6c26557a6c5845307a03d815756f564ac7325b02bc83e87d5480a8fae848f07cb891f2d51ce7df83dcafdc12324517c86d472cc0ee10d47a68fd1d9ae49a6c19bbd36d82af597a0d88cc9c49de9df4e696fc1f0b5d0011010001fe030302e9030f3c783e14856063f16938530e148bc57a7aa3f3e4f90df9dceccdc779bc0835e1ad3d006e4a8d7b36d08b8e0de5a0d947254ecfbd22037e6572b426bcfdc517796b224b0036ff90bc574b5509bede85512f2eefb520fb4b02aa523ba739bff424a6fe81c5041f253f8d757e69a503d3563a104d0d49e9e890b9d0c26f96b55b743883b472caa7050c4acfd4a21f875bdf1258d88bd61224d303dc9df77f743137d51e6d5246b88c406780528fd9a3e15bab5452e5b93970d9dcc79f48b38651b9f15bfbcf6da452837e9cc70683d1bdca94507870f743e4ad902005812488dd342f836e72869afd00ce1850eea4cfa53ce10e3608e13d3c149394ee3cbd0e23d018fcbcb6e2ec5a1a22972d1d462ca05355d0d290dd2751e550d5efb38c6c89686344df64852bf4ff86638708f644e8ec6bd4af9b50d8541cb91891a431326ab2e332faa7ae86cfb6e0540aa63160c1e5cdd5a4add518b303fff0a20117c6bc77f7cfbaf36b04c865c6c2b42754657374204b6579203220285253412c20656e637279707465642070726976617465206b65792988b804130102002205024d3c5c33021b03060b090807030206150802090a0b0416020301021e01021780000a0910d4984f961e35246b98940400908a73b6a6169f700434f076c6c79015a49bee37130eaf23aaa3cfa9ce60bfe4acaa7bc95f1146ada5867e0079babb38804891f4f0b8ebca57a86b249dee786161a755b7a342e68ccf3f78ed6440a93a6626beb9a37aa66afcd4f888790cb4bb46d94a4ae3eb3d7d3e6b00f6bfec940303e89ec5b32a1eaaacce66497d539328b00200009d01fe044d3c5c33010400a4e913f9442abcc7f1804ccab27d2f787ffa592077ca935a8bb23165bd8d57576acac647cc596b2c3f814518cc8c82953c7a4478f32e0cf645630a5ba38d9618ef2bc3add69d459ae3dece5cab778938d988239f8c5ae437807075e06c828019959c644ff05ef6a5a1dab72227c98e3a040b0cf219026640698d7a13d8538a570011010001fe030302e9030f3c783e148560f936097339ae381d63116efcf802ff8b1c9360767db5219cc987375702a4123fd8657d3e22700f23f95020d1b261eda5257e9a72f9a918e8ef22dd5b3323ae03bbc1923dd224db988cadc16acc04b120a9f8b7e84da9716c53e0334d7b66586ddb9014df604b41be1e960dcfcbc96f4ed150a1a0dd070b9eb14276b9b6be413a769a75b519a53d3ecc0c220e85cd91ca354d57e7344517e64b43b6e29823cbd87eae26e2b2e78e6dedfbb76e3e9f77bcb844f9a8932eb3db2c3f9e44316e6f5d60e9e2a56e46b72abe6b06dc9a31cc63f10023d1f5e12d2a3ee93b675c96f504af0001220991c88db759e231b3320dcedf814dcf723fd9857e3d72d66a0f2af26950b915abdf56c1596f46a325bf17ad4810d3535fb02a259b247ac3dbd4cc3ecf9c51b6c07cebb009c1506fba0a89321ec8683e3fd009a6e551d50243e2d5092fefb3321083a4bad91320dc624bd6b5dddf93553e3d53924c05bfebec1fb4bd47e89a1a889f04180102000905024d3c5c33021b0c000a0910d4984f961e35246b26c703ff7ee29ef53bc1ae1ead533c408fa136db508434e233d6e62be621e031e5940bbd4c08142aed0f82217e7c3e1ec8de574bc06ccf3c36633be41ad78a9eacd209f861cae7b064100758545cc9dd83db71806dc1cfd5fb9ae5c7474bba0c19c44034ae61bae5eca379383339dece94ff56ff7aa44a582f3e5c38f45763af577c0934b0020000"

const dsaElGamalTestKeysHex = "9501e1044dfcb16a110400aa3e5c1a1f43dd28c2ffae8abf5cfce555ee874134d8ba0a0f7b868ce2214beddc74e5e1e21ded354a95d18acdaf69e5e342371a71fbb9093162e0c5f3427de413a7f2c157d83f5cd2f9d791256dc4f6f0e13f13c3302af27f2384075ab3021dff7a050e14854bbde0a1094174855fc02f0bae8e00a340d94a1f22b32e48485700a0cec672ac21258fb95f61de2ce1af74b2c4fa3e6703ff698edc9be22c02ae4d916e4fa223f819d46582c0516235848a77b577ea49018dcd5e9e15cff9dbb4663a1ae6dd7580fa40946d40c05f72814b0f88481207e6c0832c3bded4853ebba0a7e3bd8e8c66df33d5a537cd4acf946d1080e7a3dcea679cb2b11a72a33a2b6a9dc85f466ad2ddf4c3db6283fa645343286971e3dd700703fc0c4e290d45767f370831a90187e74e9972aae5bff488eeff7d620af0362bfb95c1a6c3413ab5d15a2e4139e5d07a54d72583914661ed6a87cce810be28a0aa8879a2dd39e52fb6fe800f4f181ac7e328f740cde3d09a05cecf9483e4cca4253e60d4429ffd679d9996a520012aad119878c941e3cf151459873bdfc2a9563472fe0303027a728f9feb3b864260a1babe83925ce794710cfd642ee4ae0e5b9d74cee49e9c67b6cd0ea5dfbb582132195a121356a1513e1bca73e5b80c58c7ccb4164453412f456c47616d616c2054657374204b65792031886204131102002205024dfcb16a021b03060b090807030206150802090a0b0416020301021e01021780000a091033af447ccd759b09fadd00a0b8fd6f5a790bad7e9f2dbb7632046dc4493588db009c087c6a9ba9f7f49fab221587a74788c00db4889ab00200009d0157044dfcb16a1004008dec3f9291205255ccff8c532318133a6840739dd68b03ba942676f9038612071447bf07d00d559c5c0875724ea16a4c774f80d8338b55fca691a0522e530e604215b467bbc9ccfd483a1da99d7bc2648b4318fdbd27766fc8bfad3fddb37c62b8ae7ccfe9577e9b8d1e77c1d417ed2c2ef02d52f4da11600d85d3229607943700030503ff506c94c87c8cab778e963b76cf63770f0a79bf48fb49d3b4e52234620fc9f7657f9f8d56c96a2b7c7826ae6b57ebb2221a3fe154b03b6637cea7e6d98e3e45d87cf8dc432f723d3d71f89c5192ac8d7290684d2c25ce55846a80c9a7823f6acd9bb29fa6cd71f20bc90eccfca20451d0c976e460e672b000df49466408d527affe0303027a728f9feb3b864260abd761730327bca2aaa4ea0525c175e92bf240682a0e83b226f97ecb2e935b62c9a133858ce31b271fa8eb41f6a1b3cd72a63025ce1a75ee4180dcc284884904181102000905024dfcb16a021b0c000a091033af447ccd759b09dd0b009e3c3e7296092c81bee5a19929462caaf2fff3ae26009e218c437a2340e7ea628149af1ec98ec091a43992b00200009501e1044dfcb1be1104009f61faa61aa43df75d128cbe53de528c4aec49ce9360c992e70c77072ad5623de0a3a6212771b66b39a30dad6781799e92608316900518ec01184a85d872365b7d2ba4bacfb5882ea3c2473d3750dc6178cc1cf82147fb58caa28b28e9f12f6d1efcb0534abed644156c91cca4ab78834268495160b2400bc422beb37d237c2300a0cac94911b6d493bda1e1fbc6feeca7cb7421d34b03fe22cec6ccb39675bb7b94a335c2b7be888fd3906a1125f33301d8aa6ec6ee6878f46f73961c8d57a3e9544d8ef2a2cbfd4d52da665b1266928cfe4cb347a58c412815f3b2d2369dec04b41ac9a71cc9547426d5ab941cccf3b18575637ccfb42df1a802df3cfe0a999f9e7109331170e3a221991bf868543960f8c816c28097e503fe319db10fb98049f3a57d7c80c420da66d56f3644371631fad3f0ff4040a19a4fedc2d07727a1b27576f75a4d28c47d8246f27071e12d7a8de62aad216ddbae6aa02efd6b8a3e2818cda48526549791ab277e447b3a36c57cefe9b592f5eab73959743fcc8e83cbefec03a329b55018b53eec196765ae40ef9e20521a603c551efe0303020950d53a146bf9c66034d00c23130cce95576a2ff78016ca471276e8227fb30b1ffbd92e61804fb0c3eff9e30b1a826ee8f3e4730b4d86273ca977b4164453412f456c47616d616c2054657374204b65792032886204131102002205024dfcb1be021b03060b090807030206150802090a0b0416020301021e01021780000a0910a86bf526325b21b22bd9009e34511620415c974750a20df5cb56b182f3b48e6600a0a9466cb1a1305a84953445f77d461593f1d42bc1b00200009d0157044dfcb1be1004009565a951da1ee87119d600c077198f1c1bceb0f7aa54552489298e41ff788fa8f0d43a69871f0f6f77ebdfb14a4260cf9fbeb65d5844b4272a1904dd95136d06c3da745dc46327dd44a0f16f60135914368c8039a34033862261806bb2c5ce1152e2840254697872c85441ccb7321431d75a747a4bfb1d2c66362b51ce76311700030503fc0ea76601c196768070b7365a200e6ddb09307f262d5f39eec467b5f5784e22abdf1aa49226f59ab37cb49969d8f5230ea65caf56015abda62604544ed526c5c522bf92bed178a078789f6c807b6d34885688024a5bed9e9f8c58d11d4b82487b44c5f470c5606806a0443b79cadb45e0f897a561a53f724e5349b9267c75ca17fe0303020950d53a146bf9c660bc5f4ce8f072465e2d2466434320c1e712272fafc20e342fe7608101580fa1a1a367e60486a7cd1246b7ef5586cf5e10b32762b710a30144f12dd17dd4884904181102000905024dfcb1be021b0c000a0910a86bf526325b21b2904c00a0b2b66b4b39ccffda1d10f3ea8d58f827e30a8b8e009f4255b2d8112a184e40cde43a34e8655ca7809370b0020000"

const signedMessageHex = "a3019bc0cbccc0c4b8d8b74ee2108fe16ec6d3ca490cbe362d3f8333d3f352531472538b8b13d353b97232f352158c20943157c71c16064626063656269052062e4e01987e9b6fccff4b7df3a34c534b23e679cbec3bc0f8f6e64dfb4b55fe3f8efa9ce110ddb5cd79faf1d753c51aecfa669f7e7aa043436596cccc3359cb7dd6bbe9ecaa69e5989d9e57209571edc0b2fa7f57b9b79a64ee6e99ce1371395fee92fec2796f7b15a77c386ff668ee27f6d38f0baa6c438b561657377bf6acff3c5947befd7bf4c196252f1d6e5c524d0300"

const signedTextMessageHex = "a3019bc0cbccc8c4b8d8b74ee2108fe16ec6d36a250cbece0c178233d3f352531472538b8b13d35379b97232f352158ca0b4312f57c71c1646462606365626906a062e4e019811591798ff99bf8afee860b0d8a8c2a85c3387e3bcf0bb3b17987f2bbcfab2aa526d930cbfd3d98757184df3995c9f3e7790e36e3e9779f06089d4c64e9e47dd6202cb6e9bc73c5d11bb59fbaf89d22d8dc7cf199ddf17af96e77c5f65f9bbed56f427bd8db7af37f6c9984bf9385efaf5f184f986fb3e6adb0ecfe35bbf92d16a7aa2a344fb0bc52fb7624f0200"

const signedEncryptedMessageHex = "848c032a67d68660df41c70103ff5789d0de26b6a50c985a02a13131ca829c413a35d0e6fa8d6842599252162808ac7439c72151c8c6183e76923fe3299301414d0c25a2f06a2257db3839e7df0ec964773f6e4c4ac7ff3b48c444237166dd46ba8ff443a5410dc670cb486672fdbe7c9dfafb75b4fea83af3a204fe2a7dfa86bd20122b4f3d2646cbeecb8f7be8d2c03b018bd210b1d3791e1aba74b0f1034e122ab72e760492c192383cf5e20b5628bd043272d63df9b923f147eb6091cd897553204832aba48fec54aa447547bb16305a1024713b90e77fd0065f1918271947549205af3c74891af22ee0b56cd29bfec6d6e351901cd4ab3ece7c486f1e32a792d4e474aed98ee84b3f591c7dff37b64e0ecd68fd036d517e412dcadf85840ce184ad7921ad446c4ee28db80447aea1ca8d4f574db4d4e37688158ddd19e14ee2eab4873d46947d65d14a23e788d912cf9a19624ca7352469b72a83866b7c23cb5ace3deab3c7018061b0ba0f39ed2befe27163e5083cf9b8271e3e3d52cc7ad6e2a3bd81d4c3d7022f8d"

const signedEncryptedMessage2Hex = "85010e03cf6a7abcd43e36731003fb057f5495b79db367e277cdbe4ab90d924ddee0c0381494112ff8c1238fb0184af35d1731573b01bc4c55ecacd2aafbe2003d36310487d1ecc9ac994f3fada7f9f7f5c3a64248ab7782906c82c6ff1303b69a84d9a9529c31ecafbcdb9ba87e05439897d87e8a2a3dec55e14df19bba7f7bd316291c002ae2efd24f83f9e3441203fc081c0c23dc3092a454ca8a082b27f631abf73aca341686982e8fbda7e0e7d863941d68f3de4a755c2964407f4b5e0477b3196b8c93d551dd23c8beef7d0f03fbb1b6066f78907faf4bf1677d8fcec72651124080e0b7feae6b476e72ab207d38d90b958759fdedfc3c6c35717c9dbfc979b3cfbbff0a76d24a5e57056bb88acbd2a901ef64bc6e4db02adc05b6250ff378de81dca18c1910ab257dff1b9771b85bb9bbe0a69f5989e6d1710a35e6dfcceb7d8fb5ccea8db3932b3d9ff3fe0d327597c68b3622aec8e3716c83a6c93f497543b459b58ba504ed6bcaa747d37d2ca746fe49ae0a6ce4a8b694234e941b5159ff8bd34b9023da2814076163b86f40eed7c9472f81b551452d5ab87004a373c0172ec87ea6ce42ccfa7dbdad66b745496c4873d8019e8c28d6b3"

const symmetricallyEncryptedCompressedHex = "8c0d04030302eb4a03808145d0d260c92f714339e13de5a79881216431925bf67ee2898ea61815f07894cd0703c50d0a76ef64d482196f47a8bc729af9b80bb6"

const dsaTestKeyHex = "9901a2044d6c49de110400cb5ce438cf9250907ac2ba5bf6547931270b89f7c4b53d9d09f4d0213a5ef2ec1f26806d3d259960f872a4a102ef1581ea3f6d6882d15134f21ef6a84de933cc34c47cc9106efe3bd84c6aec12e78523661e29bc1a61f0aab17fa58a627fd5fd33f5149153fbe8cd70edf3d963bc287ef875270ff14b5bfdd1bca4483793923b00a0fe46d76cb6e4cbdc568435cd5480af3266d610d303fe33ae8273f30a96d4d34f42fa28ce1112d425b2e3bf7ea553d526e2db6b9255e9dc7419045ce817214d1a0056dbc8d5289956a4b1b69f20f1105124096e6a438f41f2e2495923b0f34b70642607d45559595c7fe94d7fa85fc41bf7d68c1fd509ebeaa5f315f6059a446b9369c277597e4f474a9591535354c7e7f4fd98a08aa60400b130c24ff20bdfbf683313f5daebf1c9b34b3bdadfc77f2ddd72ee1fb17e56c473664bc21d66467655dd74b9005e3a2bacce446f1920cd7017231ae447b67036c9b431b8179deacd5120262d894c26bc015bffe3d827ba7087ad9b700d2ca1f6d16cc1786581e5dd065f293c31209300f9b0afcc3f7c08dd26d0a22d87580b4db41054657374204b65792033202844534129886204131102002205024d6c49de021b03060b090807030206150802090a0b0416020301021e01021780000a0910338934250ccc03607e0400a0bdb9193e8a6b96fc2dfc108ae848914b504481f100a09c4dc148cb693293a67af24dd40d2b13a9e36794"

const dsaTestKeyPrivateHex = "9501bb044d6c49de110400cb5ce438cf9250907ac2ba5bf6547931270b89f7c4b53d9d09f4d0213a5ef2ec1f26806d3d259960f872a4a102ef1581ea3f6d6882d15134f21ef6a84de933cc34c47cc9106efe3bd84c6aec12e78523661e29bc1a61f0aab17fa58a627fd5fd33f5149153fbe8cd70edf3d963bc287ef875270ff14b5bfdd1bca4483793923b00a0fe46d76cb6e4cbdc568435cd5480af3266d610d303fe33ae8273f30a96d4d34f42fa28ce1112d425b2e3bf7ea553d526e2db6b9255e9dc7419045ce817214d1a0056dbc8d5289956a4b1b69f20f1105124096e6a438f41f2e2495923b0f34b70642607d45559595c7fe94d7fa85fc41bf7d68c1fd509ebeaa5f315f6059a446b9369c277597e4f474a9591535354c7e7f4fd98a08aa60400b130c24ff20bdfbf683313f5daebf1c9b34b3bdadfc77f2ddd72ee1fb17e56c473664bc21d66467655dd74b9005e3a2bacce446f1920cd7017231ae447b67036c9b431b8179deacd5120262d894c26bc015bffe3d827ba7087ad9b700d2ca1f6d16cc1786581e5dd065f293c31209300f9b0afcc3f7c08dd26d0a22d87580b4d00009f592e0619d823953577d4503061706843317e4fee083db41054657374204b65792033202844534129886204131102002205024d6c49de021b03060b090807030206150802090a0b0416020301021e01021780000a0910338934250ccc03607e0400a0bdb9193e8a6b96fc2dfc108ae848914b504481f100a09c4dc148cb693293a67af24dd40d2b13a9e36794"

const armoredPrivateKeyBlock = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.10 (GNU/Linux)

lQHYBE2rFNoBBADFwqWQIW/DSqcB4yCQqnAFTJ27qS5AnB46ccAdw3u4Greeu3Bp
idpoHdjULy7zSKlwR1EA873dO/k/e11Ml3dlAFUinWeejWaK2ugFP6JjiieSsrKn
vWNicdCS4HTWn0X4sjl0ZiAygw6GNhqEQ3cpLeL0g8E9hnYzJKQ0LWJa0QARAQAB
AAP/TB81EIo2VYNmTq0pK1ZXwUpxCrvAAIG3hwKjEzHcbQznsjNvPUihZ+NZQ6+X
0HCfPAdPkGDCLCb6NavcSW+iNnLTrdDnSI6+3BbIONqWWdRDYJhqZCkqmG6zqSfL
IdkJgCw94taUg5BWP/AAeQrhzjChvpMQTVKQL5mnuZbUCeMCAN5qrYMP2S9iKdnk
VANIFj7656ARKt/nf4CBzxcpHTyB8+d2CtPDKCmlJP6vL8t58Jmih+kHJMvC0dzn
gr5f5+sCAOOe5gt9e0am7AvQWhdbHVfJU0TQJx+m2OiCJAqGTB1nvtBLHdJnfdC9
TnXXQ6ZXibqLyBies/xeY2sCKL5qtTMCAKnX9+9d/5yQxRyrQUHt1NYhaXZnJbHx
q4ytu0eWz+5i68IYUSK69jJ1NWPM0T6SkqpB3KCAIv68VFm9PxqG1KmhSrQIVGVz
dCBLZXmIuAQTAQIAIgUCTasU2gIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AA
CgkQO9o98PRieSoLhgQAkLEZex02Qt7vGhZzMwuN0R22w3VwyYyjBx+fM3JFETy1
ut4xcLJoJfIaF5ZS38UplgakHG0FQ+b49i8dMij0aZmDqGxrew1m4kBfjXw9B/v+
eIqpODryb6cOSwyQFH0lQkXC040pjq9YqDsO5w0WYNXYKDnzRV0p4H1pweo2VDid
AdgETasU2gEEAN46UPeWRqKHvA99arOxee38fBt2CI08iiWyI8T3J6ivtFGixSqV
bRcPxYO/qLpVe5l84Nb3X71GfVXlc9hyv7CD6tcowL59hg1E/DC5ydI8K8iEpUmK
/UnHdIY5h8/kqgGxkY/T/hgp5fRQgW1ZoZxLajVlMRZ8W4tFtT0DeA+JABEBAAEA
A/0bE1jaaZKj6ndqcw86jd+QtD1SF+Cf21CWRNeLKnUds4FRRvclzTyUMuWPkUeX
TaNNsUOFqBsf6QQ2oHUBBK4VCHffHCW4ZEX2cd6umz7mpHW6XzN4DECEzOVksXtc
lUC1j4UB91DC/RNQqwX1IV2QLSwssVotPMPqhOi0ZLNY7wIA3n7DWKInxYZZ4K+6
rQ+POsz6brEoRHwr8x6XlHenq1Oki855pSa1yXIARoTrSJkBtn5oI+f8AzrnN0BN
oyeQAwIA/7E++3HDi5aweWrViiul9cd3rcsS0dEnksPhvS0ozCJiHsq/6GFmy7J8
QSHZPteedBnZyNp5jR+H7cIfVN3KgwH/Skq4PsuPhDq5TKK6i8Pc1WW8MA6DXTdU
nLkX7RGmMwjC0DBf7KWAlPjFaONAX3a8ndnz//fy1q7u2l9AZwrj1qa1iJ8EGAEC
AAkFAk2rFNoCGwwACgkQO9o98PRieSo2/QP/WTzr4ioINVsvN1akKuekmEMI3LAp
BfHwatufxxP1U+3Si/6YIk7kuPB9Hs+pRqCXzbvPRrI8NHZBmc8qIGthishdCYad
AHcVnXjtxrULkQFGbGvhKURLvS9WnzD/m1K2zzwxzkPTzT9/Yf06O6Mal5AdugPL
VrM0m72/jnpKo04=
=zNCn
-----END PGP PRIVATE KEY BLOCK-----`

const e2ePublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Charset: UTF-8

xv8AAABSBAAAAAATCCqGSM49AwEHAgME1LRoXSpOxtHXDUdmuvzchyg6005qIBJ4
sfaSxX7QgH9RV2ONUhC+WiayCNADq+UMzuR/vunSr4aQffXvuGnR383/AAAAFDxk
Z2lsQHlhaG9vLWluYy5jb20+wv8AAACGBBATCAA4/wAAAAWCVGvAG/8AAAACiwn/
AAAACZC2VkQCOjdvYf8AAAAFlQgJCgv/AAAAA5YBAv8AAAACngEAAE1BAP0X8veD
24IjmI5/C6ZAfVNXxgZZFhTAACFX75jUA3oD6AEAzoSwKf1aqH6oq62qhCN/pekX
+WAsVMBhNwzLpqtCRjLO/wAAAFYEAAAAABIIKoZIzj0DAQcCAwT50ain7vXiIRv8
B1DO3x3cE/aattZ5sHNixJzRCXi2vQIA5QmOxZ6b5jjUekNbdHG3SZi1a2Ak5mfX
fRxC/5VGAwEIB8L/AAAAZQQYEwgAGP8AAAAFglRrwBz/AAAACZC2VkQCOjdvYQAA
FJAA9isX3xtGyMLYwp2F3nXm7QEdY5bq5VUcD/RJlj792VwA/1wH0pCzVLl4Q9F9
ex7En5r7rHR5xwX82Msc+Rq9dSyO
=7MrZ
-----END PGP PUBLIC KEY BLOCK-----`

const dsaKeyWithSHA512 = `9901a2044f04b07f110400db244efecc7316553ee08d179972aab87bb1214de7692593fcf5b6feb1c80fba268722dd464748539b85b81d574cd2d7ad0ca2444de4d849b8756bad7768c486c83a824f9bba4af773d11742bdfb4ac3b89ef8cc9452d4aad31a37e4b630d33927bff68e879284a1672659b8b298222fc68f370f3e24dccacc4a862442b9438b00a0ea444a24088dc23e26df7daf8f43cba3bffc4fe703fe3d6cd7fdca199d54ed8ae501c30e3ec7871ea9cdd4cf63cfe6fc82281d70a5b8bb493f922cd99fba5f088935596af087c8d818d5ec4d0b9afa7f070b3d7c1dd32a84fca08d8280b4890c8da1dde334de8e3cad8450eed2a4a4fcc2db7b8e5528b869a74a7f0189e11ef097ef1253582348de072bb07a9fa8ab838e993cef0ee203ff49298723e2d1f549b00559f886cd417a41692ce58d0ac1307dc71d85a8af21b0cf6eaa14baf2922d3a70389bedf17cc514ba0febbd107675a372fe84b90162a9e88b14d4b1c6be855b96b33fb198c46f058568817780435b6936167ebb3724b680f32bf27382ada2e37a879b3d9de2abe0c3f399350afd1ad438883f4791e2e3b4184453412068617368207472756e636174696f6e207465737488620413110a002205024f04b07f021b03060b090807030206150802090a0b0416020301021e01021780000a0910ef20e0cefca131581318009e2bf3bf047a44d75a9bacd00161ee04d435522397009a03a60d51bd8a568c6c021c8d7cf1be8d990d6417b0020003`

const unknownHashFunctionHex = `8a00000040040001990006050253863c24000a09103b4fe6acc0b21f32ffff01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101`

const missingHashFunctionHex = `8a00000040040001030006050253863c24000a09103b4fe6acc0b21f32ffff0101010101010101010101010101010101010101010101010101010101010101010101010101`

const campbellQuine = `a0b001000300fcffa0b001000d00f2ff000300fcffa0b001000d00f2ff8270a01c00000500faff8270a01c00000500faff000500faff001400ebff8270a01c00000500faff000500faff001400ebff428821c400001400ebff428821c400001400ebff428821c400001400ebff428821c400001400ebff428821c400000000ffff000000ffff000b00f4ff428821c400000000ffff000000ffff000b00f4ff0233214c40000100feff000233214c40000100feff0000`

const keyV4forVerifyingSignedMessageV3 = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

mI0EVfxoFQEEAMBIqmbDfYygcvP6Phr1wr1XI41IF7Qixqybs/foBF8qqblD9gIY
BKpXjnBOtbkcVOJ0nljd3/sQIfH4E0vQwK5/4YRQSI59eKOqd6Fx+fWQOLG+uu6z
tewpeCj9LLHvibx/Sc7VWRnrznia6ftrXxJ/wHMezSab3tnGC0YPVdGNABEBAAG0
JEdvY3J5cHRvIFRlc3QgS2V5IDx0aGVtYXhAZ21haWwuY29tPoi5BBMBCgAjBQJV
/GgVAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQeXnQmhdGW9PFVAP+
K7TU0qX5ArvIONIxh/WAweyOk884c5cE8f+3NOPOOCRGyVy0FId5A7MmD5GOQh4H
JseOZVEVCqlmngEvtHZb3U1VYtVGE5WZ+6rQhGsMcWP5qaT4soYwMBlSYxgYwQcx
YhN9qOr292f9j2Y//TTIJmZT4Oa+lMxhWdqTfX+qMgG4jQRV/GgVAQQArhFSiij1
b+hT3dnapbEU+23Z1yTu1DfF6zsxQ4XQWEV3eR8v+8mEDDNcz8oyyF56k6UQ3rXi
UMTIwRDg4V6SbZmaFbZYCOwp/EmXJ3rfhm7z7yzXj2OFN22luuqbyVhuL7LRdB0M
pxgmjXb4tTvfgKd26x34S+QqUJ7W6uprY4sAEQEAAYifBBgBCgAJBQJV/GgVAhsM
AAoJEHl50JoXRlvT7y8D/02ckx4OMkKBZo7viyrBw0MLG92i+DC2bs35PooHR6zz
786mitjOp5z2QWNLBvxC70S0qVfCIz8jKupO1J6rq6Z8CcbLF3qjm6h1omUBf8Nd
EfXKD2/2HV6zMKVknnKzIEzauh+eCKS2CeJUSSSryap/QLVAjRnckaES/OsEWhNB
=RZia
-----END PGP PUBLIC KEY BLOCK-----
`

const signedMessageV3 = `-----BEGIN PGP MESSAGE-----
Comment: GPGTools - https://gpgtools.org

owGbwMvMwMVYWXlhlrhb9GXG03JJDKF/MtxDMjKLFYAoUaEktbhEITe1uDgxPVWP
q5NhKjMrWAVcC9evD8z/bF/uWNjqtk/X3y5/38XGRQHm/57rrDRYuGnTw597Xqka
uM3137/hH3Os+Jf2dc0fXOITKwJvXJvecPVs0ta+Vg7ZO1MLn8w58Xx+6L58mbka
DGHyU9yTueZE8D+QF/Tz28Y78dqtF56R1VPn9Xw4uJqrWYdd7b3vIZ1V6R4Nh05d
iT57d/OhWwA=
=hG7R
-----END PGP MESSAGE-----
`

const gnuDummyS2KPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQCVBFNVKE4BBADjD9Xq+1wml4VS3hxkCuyhWp003ki7yN/ZAb5cUHyIzgY7BR9v
ydz7R2s5dkRksxqiD8qg/u/UwMGteREhA8ML8JXSZ5T/TMH8DJNB1HsoKlm2q/W4
/S04jy5X/+M9GvRi47gZyOmLsu57rXdJimrUf9r9qtKSPViWlzrq4cAE0wARAQAB
/gNlAkdOVQG0IFdpbGxpYW0gV29yZHN3b3J0aCA8d3dAb3guYWMudWs+iL4EEwEK
ACgFAlNVKE4CGwMFCRLMAwAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEJLY
KARjvfT1roEEAJ140DFf7DV0d51KMmwz8iwuU7OWOOMoOObdLOHox3soScrHvGqM
0dg7ZZUhQSIETQUDk2Fkcjpqizhs7sJinbWYcpiaEKv7PWYHLyIIH+RcYKv18hla
EFHaOoUdRfzZsNSwNznnlCSCJOwkVMa1eJGJrEElzoktqPeDsforPFKhnQH+BFNV
KE4BBACwsTltWOQUEjjKDXW28u7skuIT2jtGFc/bbzXcfg2bzTpoJlMNOBMdRDPD
TVccJhAYj8kX9WJDSj+gluMvt319lLrAXjaroZHvHFqJQDxlqyR3mCkITjL09UF/
wVy3sF7wek8KlJthYSiBZT496o1MOsj5k+E8Y/vOHQbvg9uK0wARAQAB/gMDAmEI
mZFRPn111gNki6npnVhXyDhv7FWJw/aLHkEISwmK4fDKOnx+Ueef64K5kZdUmnBC
r9HEAUZA8mKuhWnpDTCLYZwaucqMjD0KyVJiApyGl9QHU41LDyfobDWn/LabKb6t
8uz6qkGzg87fYz8XLDgLvolImbTbeqQa9wuBRK9XfRLVgWv7qemNeDCSdLFEDA6W
ENR+YjDJTZzZDlaH0yLMvudJO4lKnsS+5lhX69qeBJpfp+eMsPh/K8dCOi6mYuSP
SF2JI7hVpk9PurDO1ne20mLuqZvmuDHcddWM88FjXotytDtuHScaX94+vVLXQAKz
mROs4Z7GkNs2om03kWCqsGmAV1B0+bbmcxTH14/vwAFrYSJwcvHsaDhshcCoxJa8
pKxttlHlUYQ6YQZflIMnxvbZAIryDDK9kwut3GGStfoJXoi5jA8uh+WG+avn+iNI
k8lR0SSgo6n5/vyWS6l/ZBbF1JwX6oQ4ep7piKUEGAEKAA8FAlNVKE4CGwwFCRLM
AwAACgkQktgoBGO99PUaKAQAiK1zQQQIOVkqBa/E9Jx5UpCVF/fi0XsTfU2Y0Slg
FV7j9Bqe0obycJ2LFRNDndVReJQQj5vpwZ/B5dAoUqaMXmAD3DD+7ZY756u+g0rU
21Z4Nf+we9PfyA5+lxw+6PXNpYcxvU9wXf+t5vvTLrdnVAdR0hSxKWdOCgIS1VlQ
uxs=
=NolW
-----END PGP PRIVATE KEY BLOCK-----`

const gnuDummyS2KPrivateKeyPassphrase = "lucy"

const gnuDummyS2KPrivateKeyWithSigningSubkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

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
CQJMlh5V7RMenq01TpLPvc8=
=tI6t
-----END PGP PRIVATE KEY BLOCK-----

`
const gnuDummyS2KPrivateKeyWithSigningSubkeyPassphrase = "urn"

const signingSubkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

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
=3zTL
-----END PGP PRIVATE KEY BLOCK-----
`

const signingSubkeyPassphrase = "abcd"

const eddsaPublicKey = `
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mDMEVcdzEhYJKwYBBAHaRw8BAQdABLH577R+X2tGKoTX7GVYInAoCPaSpsaJqA52
nopSLsa0K0Vhcmx5IEFkb3B0ZXIgKFBXIGlzIGFiY2QpIDxlYXJseUBhZG9wdC5l
cj6IeQQTFggAIQUCVcdzEgIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRBY
ZCLvtzlOPSS/AQDVhDyt1Si33VqLEmtlKnLs/2Kvi9FeM7yKU3Faj5ki4AEAyaMO
3LKLyzMhYn7GavsS2wlP6hpuw8Vavjk2kWE7iwA=
=IE4q
-----END PGP PUBLIC KEY BLOCK-----
`

const eddsaSignature = `-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owGbwMvMwCEWkaL0frulny3jaeckhtDjM5g9UnNy8hVSE4tyKhUSU/ILSlKLivUU
PFKLUhUyixWK83NTFVxTXIIdFYpLCwryi0r0FEIyUhVKMjKLUvS4OuJYGMQ4GNhY
mUBGMXBxCsDMP7GA4X/4JlF9p1uHWr2yn/o+l1uRdcFn6xp7zq2/PzDZyqr0h+xk
+J9mYZEyTzxYwov3+41tk1POxp2d4xzP7qhw+vSpjus5sswA
=Eywk
-----END PGP MESSAGE-----
`

const eddsaSignedMsg = "Hello early adopters. Here is some EdDSA support. The third.\n"

const freacky22527Key = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

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
=BIqK
-----END PGP PUBLIC KEY BLOCK-----`

const themaxKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

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
omJSXSk=
=f42K
-----END PGP PUBLIC KEY BLOCK-----`

const kaylabsKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQINBFUL+MUBEADC4kiPTXVvYncK7YetrcRZEFdB+6uonJgCzBE/EH7vPOQRV7rq
PQDFzo+XQXMYWUUWgfMwG00DxmbCyv45tJzXiEZChnyi0EC63kRoNKtyDM6MKTgr
tr77TGc1nMAVkwZIW2THHded445nLiZgk1RCz5XzlqSPlqNhRpXC1bFrSUs/rMTZ
EN/lSpvIs/ykn0ZY9gzMgkFUprNkzAMosNIt02FyY3Afoc7zKxra6BNyhbUBEAi1
qwPf7FfPC9y0tT1DYqQOgmzAjc9UtMrV+6HqPIlBkYKdBCWuCK4l/+9VziHnu82y
F1z0wFkFgzCRydb9dlAREmxPl0PV9cKQtibR/ycGd71JmI4yv5d7OT4eYn/Ds5ix
MOxHxjKLRLADsJNItbqZa+g1HSCPjhF2tCLi2cLOkJzLTn8SBngjGPl0IQ9tliyb
Nio/NJa4nfKp7GNbdtJo8daLTODpOFwbN8NCbrBdwr0SzSRZXSkh5E3r/gwDYrsL
B0EypcEEeCsCSIlrOqDEEDBJd1HpVlaZokDtOMT5ZQFM0k5fIzu6mmAHwg6sJCXG
kFxxlgVywnR4X2HnzmvxJZhIne8602ElsgkBMt33SprYd3hLRgCNwl2LFvVjmTvd
GiBcUXgxQ4GXBxfVInEZFTrTgN0EvrQI8ubvLwPayNiDxzZtNJp4AYcC8wARAQAB
tB5Kb2VybiBLdWVobCA8a2F5bGFic0BhcmNvci5kZT6JAj4EEwECACgFAlUL+PgC
Gy8FCQPDuIAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJELfXlrsyoycxzVUP
+wUjErOAL/cCc59aMyFcUZvT1qg8xHAU/mblS3KCkv3joU48rk6yDkNHGzCbsqST
RIizMjKSIPPfVyV33+tYoT62+WaXEjlmCue6fBwt4wZDBQ0KOn7FKm/hz/4/tog2
lO/DPrpFAusuQ0sYuLbuyPMuPBDi8pdRcMzGGy33Ywvbh3gLZpTKek5T/xrstiUF
AoXjuHKMms5HfdImME2dOBjolw3sjbZkK4BgyPg421hSvXr1yco1nlOesmZAvrry
3Y9NQphSNq67IInsjgHMQd0Irkb9UFo3C/Gm9vHIhF8FDWhtMh25v/yYTkb+Y/Rx
tOfnHUH0OGqN/A1yAiTwOmra7EdvMAI5ohia+vslua7eOgNK73aW3E3cDrGhWGmz
Wj40l9drtfG57qv0wyCO5K81uEeERz8nxNVS3JSAOUDENfYVVl+Ag+JZ40D6lPST
OXE9kUb+8GtG+ruJ76U5qsg8kUhlBqmC6N69+vFoioA2lTfPJTfzbaw3n2TL9htq
LGzdyzbV0JJpsk6zHwIXktJ/7Keso2cvPCbBrEgvoc3TX3ALvISauhIeIU1vFbrn
zI9J/5Pe67biqcQGV11l5jQrmHrk7nV+IXyDgKYf/IkeccyjQ8b2VtjdSukYM3hn
DeDq3ESgpW9DrZmk+TixwADCtblq/TosE9n5VUiYDy3ztCFKb2VybiBLdWVobCA8
ai5rdWVobEBsZW5uZXRhbC5ldT6JAkEEEwECACsCGy8FCQPDuIAGCwkIBwMCBhUI
AgkKCwQWAgMBAh4BAheABQJWZgE6AhkBAAoJELfXlrsyoycxTR8P/0CaOWf4Rtjd
a2bfWOV6HCKbazbkIZK5KXQ40fYx3fbZ8e6axo2vulLLFSD9NcVMkII87FUzZDIa
D+o0kCJK7wn+2+DIuT0I699438c7BCi/dkYngj/Ka2M6SVt13ASmbrJg4v5P7w9W
cDUIpM0LLxl5lPqN7N9wK22P27bfiOlMFFo0Vzq9tyhdjNBi1aksB1MpHjQbJ/yO
REEnBBWUOMRTetwzAfryuIf/y7t2Mc1HZ0MAqE/y3i7c+bpk1LLu+xIwSw6Gy/xR
w1SkZ104ZkoG5OKVYaQzlVETgyGqZbIctqQEb6MZ11YRGjpMTAhNrZU/4wopFhy7
DQCyfsnrK3eMLBOTH8DI42YSlFGhb7pLEKZdmRuxcM9nmCmYJ2bL+tLIzzSqMRLu
5KTUWqb9bwm7zNaQuWfbYNbXHfrZNma4xBsTIhYevzLSiWs2kDxZ97RSbIdF5Jo/
wTBSDZAFaSNFlLA2qNIQNyhsRHNsrBCMATNxlMS5N1wsEWDswdqyhB1OBhSUEZf4
6BfQJngz6Duxf3X2y+AktrRgPVOUPauhGPTubUxPxWTX5g9cxSuZewuz25isl2C3
NF5GHdITy0mxZr9q0VxLIua0vCewLuksrchCxqTPtGMMidiBmxKfT5J+CcthTjxC
B1SH/erBPy8hOOlw/HZSAgr0QDUOZfV+tCFKb2VybiBLdWVobCA8ai5rdWVobEBp
dC10ZWFtLmJpej6JAj4EEwECACgFAlUL+PMCGy8FCQPDuIAGCwkIBwMCBhUIAgkK
CwQWAgMBAh4BAheAAAoJELfXlrsyoycx+78QAIDFEs6hdwV4Ltop/WsD62Op/xBB
Cy+4j0itpOnO0iWJIhbgwlBPGiYrVEqFJQLxUp3CovbP1tBAI7rWCeIyNMqmd0Qs
9DeSxGtIJNPRolKHHXTHiFcszo2SefmHIu3l8HH3hdo+XzpYbV13IFOoABIqfbj2
CBHEyV+4DSKXvJ1j1d6sMFOIyBkwYMhvrXYXIngAK1qTNMQkkJI9ZaNKwIZIlZnl
YavkyuHTD/4oCTf1f7boB447ac7RWCByDP/kfARLsJ8TwrOO4+cD6+Z/dBMrvBe1
0tDM0GnXJV/03PsxNqkPrDzMh0ShSddJlEZZ0lNcnrDdXGr7vn5BWj3rpHUKL4mj
XGbJSFj5anwxnSwSi15HRSbz5GcuIqbLorsRcoEY7D7y+ZkN8d/5fqDDulCA56rv
5HIl4Ztm1DgDmIIUq24OaIQevLmjI1ZexuxdSDdWC5BEJd/YAUbw8sadoahhVrte
xzY8rHy3lrZ4RX4KScPukKVU3Jq95sfDSo9Mrux4CfFDg2e4dA+1Okhy7yli2mis
ta9GLHPeLNPlaHZG2d31BGqXTk29m4hwCfuY5Iuo9Am1CRRbw2Vbz+YSF7Ojn9F6
m8Nf9lvEJBc3ffYbEnyXZwT8pLy1iRfNUGW8OhN/VqDFADMQbKs2YTlHNiJS56hk
/ByseXKAUA0VuHTRuQINBFUL+MUBEADAl3F5c+VoEKC6CecqdrHr77sOFRpyVHw4
rCDo54TI0wzJtHQyzOV6L6sGpUMUD/NTZ0FO/csOViQfBYinfiqdOVu/bDiq6rlG
nWXVw1s6AjXD+b0/wGvKLkaEk+lajmM+ifcrJPHJ34wzMdqohf7yST/suMGcpODt
/m1LN+15uxdItuqZnolKzdB/vOjuGZEE22NhpzumZk652Z5WosOIDVdn1sKROr+O
ziZooVYiWY20l6QLS4tcuAaCizbWOGnF9bQzLZlQ/BPFk+j6EzRwpmYSWBT/qXdd
wz2L288uiiCZjx85wvIcv6WMEWBf/ahYMwzTOn4sz2vu5RQ2FJgBdgEuEV38LzTY
J0mso4Ch+x5WnZ7Lg3iPCjQJUIeKIEo6gWDhjYzZru4qcbjoBLCSzHQgsuD5ICfd
OQdaLk3pvLFyJqFCQHuR3hL0pyvW0a6gNzxjZtGKbs8W6H6Sd8mlTBfECqkMa1pE
rS7VrMo6fBtbYArqK8QnA1FPCPeh/r23PGtYhtM3Mi1eRNRoDbsbx/ufQ6BxivJB
dILRUO37ubxik+MEUU/4CxRX9ArOW67IWcdZxtwXryiaiZFtkcaky7tSG9G97F72
CBgKwwLE0HscHG9yh79taUc60KB5ApSeeZHAnXAUW0gSW+atddcZKdGy3KlCtV+k
z0xYpzEu7QARAQABiQREBBgBAgAPBQJVC/jFAhsuBQkDw7iAAikJELfXlrsyoycx
wV0gBBkBAgAGBQJVC/jFAAoJEB7sRj7oDEeE3LYQALkYiq5K4GPm17V4aXIyyVOS
81VzhSvxhBl6uJLVeEHGEGMhdUg6xz4MqQOadNmG+SAWeZPWRRwmnYFHs+Mp+YXJ
fGxqq/DFPnKDYyL610k06tAyup3071PXqIBHQuzFAZWxqW7xMsu+PVXVQOq/PTso
WZdB3/KPweh/led4lLq45odQeEq/hILNBwAzxeuwAdeBg7aeK9YJCLhyNT7hRV06
BQ6Ypohbi9nvyCOuThJ4UFwlRl/mYEKwqTto7wh9txoaVaplUYmgE1vxlRny5Y/l
ESrDaNBo2qQ08qg4fLJgDHkZfkenLOsJEzinlqfqCMZ4a/X5eKxywoi6lOTlGscj
03BddTRInV5yTzJar7zvHzwT0J868NAoh9EQdkxna3TOr5oFhG/dxuDmPEPUI9PP
9f8iM+W1w15it94LJOWQ5+/YApmnZqaiCUU+DzwoU43RkGP37wBbWtGywmqlFH6s
xA7kdy680B2FnNoN96eI5WkXCOxxFVCx/8/z5h7dPo0hwIj5NDP5qGRp2/GSM+P3
46kh5lON2rFDebKJsAlUT6JeYAVJ8sueMp7vZLV/cfY5vrkULG6Z0q+lOk4Dmc/z
CqlN0LZF30lwZvyC15zeh13uSP9MSLyH0y4bTAEkTGCSLmRo1Mo8XnJWVNuEghBR
JIhVcE4LQp0cKrWLWuTL+ccP/jBfOLHFVBZkJ29T83+c8N4DsgKNGyZy6dVoaK/y
iRTrKZeCjGt5clgnezPsTi3Q3bggmAbsZnBhDw1i0e99eCuAjWGS8bt8xPQ6eKHF
1fgBjinNpUojQulEicM3jsrjFfv6Ozn6SxhuUYzHfPjeGF1Pwt8tGmcDTVqiagdF
MqKVI8Bx4TD4PY7PJF+JDgqnc59MRF2EQZeeGyWncR/Q13Wh9XIIYMFgqGx7QlRY
qOsXsei/0xmTwFv56ymrlM8DrQZM07b5C0EvTe4HlXCFRYrwpbvwk8dpsNGcCalK
S1UClQewg4ceqp1vflbVqR0r4cugYpM4MjO/Xg52kuO/9q+uXegHm9lReEfNoXZv
5M+kp5zhSz735LoBTR7fyH26S/V9m9INPLUb7KWC4yLEF+byXOalL/ts3ixHuUEM
0jUxCCUUHrkHCoj9NEIzWvcWsd6MxmD7J07+7d+jn5UOv8z3few80Y30K2Irsa4k
8KlDL7t14lzL8K4HLXkE55SyDMeCbwLWfuesETOT/LznPHlR7RVYGe2E9VHxhd0y
VguYv7vyVx7u0TAr1EoSxEkKzYEyQhJQ0m2Kxp9lZEHc5yHtWvhvZQj0NdzPiGn9
Ut3r1bY/37uoEIQfxsaqOZxcX/lx2q9t8ylaV123yZ8zFNrB+eCcVRVUZpkvw+xE
blYJ
=7oW5
-----END PGP PUBLIC KEY BLOCK-----`

const reviKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

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
VZy0MA==
=LD7q
-----END PGP PUBLIC KEY BLOCK-----`
