// httpsig
// Copyright (C) GoToSocial Authors admin@gotosocial.org
// Copyright (C) go-fed
// SPDX-License-Identifier: BSD-3-Clause
//
// BSD 3-Clause License
//
// Copyright (c) 2018, go-fed
// Copyright (c) 2024, GoToSocial Authors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package httpsig

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

type DigestAlgorithm string

const (
	DigestSha256 DigestAlgorithm = "SHA-256"
	DigestSha512 DigestAlgorithm = "SHA-512"
)

var digestToDef = map[DigestAlgorithm]crypto.Hash{
	DigestSha256: crypto.SHA256,
	DigestSha512: crypto.SHA512,
}

// IsSupportedDigestAlgorithm returns true if the string is supported by this
// library, is not a hash known to be weak, and is supported by the hardware.
func IsSupportedDigestAlgorithm(algo string) bool {
	uc := DigestAlgorithm(strings.ToUpper(algo))
	c, ok := digestToDef[uc]
	return ok && c.Available()
}

func getHash(alg DigestAlgorithm) (h hash.Hash, toUse DigestAlgorithm, err error) {
	upper := DigestAlgorithm(strings.ToUpper(string(alg)))
	c, ok := digestToDef[upper]
	switch {
	case !ok:
		err = fmt.Errorf("unknown or unsupported Digest algorithm: %s", alg)
	case !c.Available():
		err = fmt.Errorf("unavailable Digest algorithm: %s", alg)
	default:
		h = c.New()
		toUse = upper
	}
	return
}

const (
	digestHeader = "Digest"
	digestDelim  = "="
)

func addDigest(r *http.Request, algo DigestAlgorithm, b []byte) (err error) {
	_, ok := r.Header[digestHeader]
	if ok {
		err = fmt.Errorf("cannot add Digest: Digest is already set")
		return
	}
	var h hash.Hash
	var a DigestAlgorithm
	h, a, err = getHash(algo)
	if err != nil {
		return
	}
	h.Write(b)
	sum := h.Sum(nil)
	r.Header.Add(digestHeader,
		fmt.Sprintf("%s%s%s",
			a,
			digestDelim,
			base64.StdEncoding.EncodeToString(sum)))
	return
}

func addDigestResponse(r http.ResponseWriter, algo DigestAlgorithm, b []byte) (err error) {
	_, ok := r.Header()[digestHeader]
	if ok {
		err = fmt.Errorf("cannot add Digest: Digest is already set")
		return
	}
	var h hash.Hash
	var a DigestAlgorithm
	h, a, err = getHash(algo)
	if err != nil {
		return
	}
	h.Write(b)
	sum := h.Sum(nil)
	r.Header().Add(digestHeader,
		fmt.Sprintf("%s%s%s",
			a,
			digestDelim,
			base64.StdEncoding.EncodeToString(sum)))
	return
}
