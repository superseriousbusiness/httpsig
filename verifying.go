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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var _ VerifierWithOptions = &verifier{}

type verifier struct {
	header      http.Header
	kID         string
	signature   string
	created     int64
	expires     int64
	headers     []string
	sigStringFn func(http.Header, []string, int64, int64, SignatureOption) (string, error)
}

func newVerifier(h http.Header, sigStringFn func(http.Header, []string, int64, int64, SignatureOption) (string, error)) (*verifier, error) {
	scheme, s, err := getSignatureScheme(h)
	if err != nil {
		return nil, err
	}
	kID, sig, headers, created, expires, err := getSignatureComponents(scheme, s)
	if created != 0 {
		// check if created is not in the future, we assume a maximum clock offset of 10 seconds
		now := time.Now().Unix()
		if created-now > 10 {
			return nil, errors.New("created is in the future")
		}
	}
	if expires != 0 {
		// check if expires is in the past, we assume a maximum clock offset of 10 seconds
		now := time.Now().Unix()
		if now-expires > 10 {
			return nil, errors.New("signature expired")
		}
	}
	if err != nil {
		return nil, err
	}
	return &verifier{
		header:      h,
		kID:         kID,
		signature:   sig,
		created:     created,
		expires:     expires,
		headers:     headers,
		sigStringFn: sigStringFn,
	}, nil
}

func (v *verifier) KeyID() string {
	return v.kID
}

func (v *verifier) Verify(pKey crypto.PublicKey, algo Algorithm) error {
	return v.VerifyWithOptions(pKey, algo, SignatureOption{})
}

func (v *verifier) VerifyWithOptions(pKey crypto.PublicKey, algo Algorithm, opts SignatureOption) error {
	s, err := signerFromString(string(algo))
	if err == nil {
		return v.asymmVerify(s, pKey, opts)
	}
	m, err := macerFromString(string(algo))
	if err == nil {
		return v.macVerify(m, pKey, opts)
	}
	return fmt.Errorf("no crypto implementation available for %q: %s", algo, err)
}

func (v *verifier) macVerify(m macer, pKey crypto.PublicKey, opts SignatureOption) error {
	key, ok := pKey.([]byte)
	if !ok {
		return fmt.Errorf("public key for MAC verifying must be of type []byte")
	}
	signature, err := v.sigStringFn(v.header, v.headers, v.created, v.expires, opts)
	if err != nil {
		return err
	}
	actualMAC, err := base64.StdEncoding.DecodeString(v.signature)
	if err != nil {
		return err
	}
	ok, err = m.Equal([]byte(signature), actualMAC, key)
	if err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("invalid http signature")
	}
	return nil
}

func (v *verifier) asymmVerify(s signer, pKey crypto.PublicKey, opts SignatureOption) error {
	toHash, err := v.sigStringFn(v.header, v.headers, v.created, v.expires, opts)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(v.signature)
	if err != nil {
		return err
	}
	err = s.Verify(pKey, []byte(toHash), signature)
	if err != nil {
		return err
	}
	return nil
}

func getSignatureScheme(h http.Header) (scheme SignatureScheme, val string, err error) {
	s := h.Get(string(Signature))
	sigHasAll := strings.Contains(s, keyIDParameter) ||
		strings.Contains(s, headersParameter) ||
		strings.Contains(s, signatureParameter)
	a := h.Get(string(Authorization))
	authHasAll := strings.Contains(a, keyIDParameter) ||
		strings.Contains(a, headersParameter) ||
		strings.Contains(a, signatureParameter)
	switch {
	case sigHasAll && authHasAll:
		err = fmt.Errorf("both %q and %q have signature parameters", Signature, Authorization)
		return
	case !sigHasAll && !authHasAll:
		err = fmt.Errorf("neither %q nor %q have signature parameters", Signature, Authorization)
		return
	case sigHasAll:
		val = s
		scheme = Signature
		return
	default:
		val = a
		scheme = Authorization
		return
	}
}

func getSignatureComponents(scheme SignatureScheme, s string) (kID, sig string, headers []string, created int64, expires int64, err error) {
	if as := scheme.authScheme(); len(as) > 0 {
		s = strings.TrimPrefix(s, as+prefixSeparater)
	}
	params := strings.Split(s, parameterSeparater)
	for _, p := range params {
		kv := strings.SplitN(p, parameterKVSeparater, 2)
		if len(kv) != 2 {
			err = fmt.Errorf("malformed http signature parameter: %v", kv)
			return
		}
		k := kv[0]
		v := strings.Trim(kv[1], parameterValueDelimiter)
		switch k {
		case keyIDParameter:
			kID = v
		case createdKey:
			created, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return
			}
		case expiresKey:
			expires, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return
			}
		case algorithmParameter:
			// Deprecated, ignore
		case headersParameter:
			headers = strings.Split(v, headerParameterValueDelim)
		case signatureParameter:
			sig = v
		default:
			// Ignore unrecognized parameters
		}
	}
	switch {
	case len(kID) == 0:
		err = fmt.Errorf("missing %q parameter in http signature", keyIDParameter)
	case len(sig) == 0:
		err = fmt.Errorf("missing %q parameter in http signature", signatureParameter)
	case len(headers) == 0:
		headers = defaultHeaders
	}
	return
}
