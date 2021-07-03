// Kiebitz - Privacy-Friendly Appointment Scheduling
// Copyright (C) 2021-2021 The Kiebitz Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package crypto

import (
	"encoding/base64"
	"testing"
)

var mediatorKeyPairStr = &StringKeyPair{
	PublicKey:  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2/CshpmLh7tNOpHfzjlaVG/uPPESTIfEBwAi34mOfgv05+xO2UYhiJ1sJhBIBZj5B/EsGrIexgiOHPnP1R6szA==",
	PrivateKey: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTQC14mzj7PCvV7D6SNgBisYA2+Ue1g+wmFusbAbL8TShRANCAATb8KyGmYuHu006kd/OOVpUb+488RJMh8QHACLfiY5+C/Tn7E7ZRiGInWwmEEgFmPkH8Swash7GCI4c+c/VHqzM",
}

var mediatorSignature, _ = base64.StdEncoding.DecodeString("oyZ739CCFErHP7deXnlZS7l99SNdShKEOFASrQ3Ul5cxkJOMXOWrfgH4PH6nCuN+bhwaaYi4uKOEfJ6JWdmOyA==")
var mediatorPublicKey, _ = base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHYzaq9/ZDs+eQvKYFYtFsyKhO6dS0iw5I/jNVIOCZjmHTQW/2ohEGN0oiLRFUTtbyX9+PP7d18WbsJl1ne2Srg==")

// the JSON is ASCII-encoded
var mediatorSignedData = &SignedData{
	Signature: mediatorSignature,
	Data:      []byte(`{"signing":"g5FZ+uqweopJgNV9OUQjCk3mpkxojMzBRAAl/2koM7A=","encryption":"jtMum/FovAknQ7P+IObA9t/htwVSBCRlXti5+HqisUk=","zipCode":"10734","queues":["jCEXaOa9Xzpd7p13Gxf8/6XNgYa0MwtkFGfis/Ug1xs="]}`),
	PublicKey: mediatorPublicKey,
}

func TestSignAndVerify(t *testing.T) {

	keyPair, err := KeyPairFromStrings(mediatorKeyPairStr)

	if err != nil {
		t.Fatal(err)
	}

	if signature, err := Sign([]byte(mediatorSignedData.Data), keyPair.PrivateKey); err != nil {
		t.Fatal(err)
	} else if ok, err := Verify([]byte(mediatorSignedData.Data), append(signature.R.Bytes(), signature.S.Bytes()...), keyPair.PublicKey); !ok {
		t.Fatalf("signature does not match...")
	} else if err != nil {
		t.Fatal(err)
	}

	if ok, err := mediatorSignedData.Verify(keyPair.PublicKey); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatalf("Expected a valid signature")
	}

}
