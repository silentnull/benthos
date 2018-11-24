// Copyright (c) 2018 Ashley Jeffs
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package processor

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/Jeffail/benthos/lib/log"
	"github.com/Jeffail/benthos/lib/message"
	"github.com/Jeffail/benthos/lib/metrics"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func TestEncryptBadAlgo(t *testing.T) {
	conf := NewConfig()
	conf.Encrypt.Scheme = "does not exist"

	if _, err := NewEncrypt(conf, nil, log.Noop(), metrics.Noop()); err == nil {
		t.Error("Expected error from un-supported scheme")
	}
}

func TestEncryptPgp(t *testing.T) {
	conf := NewConfig()
	conf.Encrypt.Scheme = "pgp"
	conf.Encrypt.Key = "./testdata/pgp_public.key"

	key, err := ioutil.ReadFile("./testdata/pgp_private.key")
	if err != nil {
		t.Fatal(err)
	}
	// decode armor
	keyBlock, err := armor.Decode(bytes.NewReader(key))
	if err != nil {
		t.Fatal(err)
	}
	// check key type
	if keyBlock.Type != openpgp.PrivateKeyType {
		t.Fatal(err)
	}
	keyReader := packet.NewReader(keyBlock.Body)
	keyEntity, err := openpgp.ReadEntity(keyReader)
	if err != nil {
		t.Fatal(err)
	}
	entityList := &openpgp.EntityList{keyEntity}

	input := [][]byte{
		[]byte("hello world first part"),
		[]byte("hello world second part"),
		[]byte("third part"),
		[]byte("fourth"),
		[]byte("5"),
	}

	proc, err := NewEncrypt(conf, nil, log.Noop(), metrics.Noop())
	if err != nil {
		t.Fatal(err)
	}

	msgs, res := proc.ProcessMessage(message.New(input))
	if len(msgs) != 1 {
		t.Fatal("Encrypt failed")
	} else if res != nil {
		t.Errorf("Expected nil response: %v", res)
	}

	outputs := message.GetAllBytes(msgs[0])
	for i, output := range outputs {
		if act, notexp := string(output), string(input[i]); act == notexp {
			t.Errorf("Unexpected output: %s == %s", act, notexp)
		}

		m := bytes.NewReader(output)
		messageBlock, err := armor.Decode(m)
		if err != nil {
			t.Fatal(err)
		}
		message, err := openpgp.ReadMessage(messageBlock.Body, entityList, nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		actBytes, err := ioutil.ReadAll(message.UnverifiedBody)
		if err != nil {
			t.Fatal(err)
		}

		if act, exp := string(actBytes), string(input[i]); act != exp {
			t.Errorf("Unexpected output: %s != %s", act, exp)
		}
	}
}
