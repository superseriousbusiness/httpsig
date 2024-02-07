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
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	// Signature Parameters
	keyIDParameter            = "keyId"
	algorithmParameter        = "algorithm"
	headersParameter          = "headers"
	signatureParameter        = "signature"
	prefixSeparater           = " "
	parameterKVSeparater      = "="
	parameterValueDelimiter   = "\""
	parameterSeparater        = ","
	headerParameterValueDelim = " "
	// RequestTarget specifies to include the http request method and
	// entire URI in the signature. Pass it as a header to NewSigner.
	RequestTarget = "(request-target)"
	createdKey    = "created"
	expiresKey    = "expires"
	dateHeader    = "date"

	// Signature String Construction
	headerFieldDelimiter   = ": "
	headersDelimiter       = "\n"
	headerValueDelimiter   = ", "
	requestTargetSeparator = " "
)

var defaultHeaders = []string{dateHeader}

var _ SignerWithOptions = &macSigner{}

type macSigner struct {
	m            macer
	dAlgo        DigestAlgorithm
	headers      []string
	targetHeader SignatureScheme
	prefix       string
	created      int64
	expires      int64
}

func (m *macSigner) SignRequest(pKey crypto.PrivateKey, pubKeyID string, r *http.Request, body []byte) error {
	return m.SignRequestWithOptions(pKey, pubKeyID, r, body, SignatureOption{})
}

func (m *macSigner) SignRequestWithOptions(pKey crypto.PrivateKey, pubKeyID string, r *http.Request, body []byte, opts SignatureOption) error {
	if body != nil {
		err := addDigest(r, m.dAlgo, body)
		if err != nil {
			return err
		}
	}
	s, err := m.signatureString(r, opts)
	if err != nil {
		return err
	}
	enc, err := m.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header, string(m.targetHeader), m.prefix, pubKeyID, m.m.String(), enc, m.headers, m.created, m.expires)
	return nil
}

func (m *macSigner) SignResponse(pKey crypto.PrivateKey, pubKeyID string, r http.ResponseWriter, body []byte) error {
	return m.SignResponseWithOptions(pKey, pubKeyID, r, body, SignatureOption{})
}

func (m *macSigner) SignResponseWithOptions(pKey crypto.PrivateKey, pubKeyID string, r http.ResponseWriter, body []byte, _ SignatureOption) error {
	if body != nil {
		err := addDigestResponse(r, m.dAlgo, body)
		if err != nil {
			return err
		}
	}
	s, err := m.signatureStringResponse(r)
	if err != nil {
		return err
	}
	enc, err := m.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header(), string(m.targetHeader), m.prefix, pubKeyID, m.m.String(), enc, m.headers, m.created, m.expires)
	return nil
}

func (m *macSigner) signSignature(pKey crypto.PrivateKey, s string) (string, error) {
	pKeyBytes, ok := pKey.([]byte)
	if !ok {
		return "", fmt.Errorf("private key for MAC signing must be of type []byte")
	}
	sig, err := m.m.Sign([]byte(s), pKeyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(sig)
	return enc, nil
}

func (m *macSigner) signatureString(r *http.Request, opts SignatureOption) (string, error) {
	return signatureString(r.Header, m.headers, addRequestTarget(r, opts), m.created, m.expires)
}

func (m *macSigner) signatureStringResponse(r http.ResponseWriter) (string, error) {
	return signatureString(r.Header(), m.headers, requestTargetNotPermitted, m.created, m.expires)
}

var _ SignerWithOptions = &asymmSigner{}

type asymmSigner struct {
	s            signer
	dAlgo        DigestAlgorithm
	headers      []string
	targetHeader SignatureScheme
	prefix       string
	created      int64
	expires      int64
}

func (a *asymmSigner) SignRequest(pKey crypto.PrivateKey, pubKeyID string, r *http.Request, body []byte) error {
	return a.SignRequestWithOptions(pKey, pubKeyID, r, body, SignatureOption{})
}

func (a *asymmSigner) SignRequestWithOptions(pKey crypto.PrivateKey, pubKeyID string, r *http.Request, body []byte, opts SignatureOption) error {
	if body != nil {
		err := addDigest(r, a.dAlgo, body)
		if err != nil {
			return err
		}
	}
	s, err := a.signatureString(r, opts)
	if err != nil {
		return err
	}
	enc, err := a.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header, string(a.targetHeader), a.prefix, pubKeyID, a.s.String(), enc, a.headers, a.created, a.expires)
	return nil
}

func (a *asymmSigner) SignResponse(pKey crypto.PrivateKey, pubKeyID string, r http.ResponseWriter, body []byte) error {
	return a.SignResponseWithOptions(pKey, pubKeyID, r, body, SignatureOption{})
}

func (a *asymmSigner) SignResponseWithOptions(pKey crypto.PrivateKey, pubKeyID string, r http.ResponseWriter, body []byte, _ SignatureOption) error {
	if body != nil {
		err := addDigestResponse(r, a.dAlgo, body)
		if err != nil {
			return err
		}
	}
	s, err := a.signatureStringResponse(r)
	if err != nil {
		return err
	}
	enc, err := a.signSignature(pKey, s)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header(), string(a.targetHeader), a.prefix, pubKeyID, a.s.String(), enc, a.headers, a.created, a.expires)
	return nil
}

func (a *asymmSigner) signSignature(pKey crypto.PrivateKey, s string) (string, error) {
	sig, err := a.s.Sign(rand.Reader, pKey, []byte(s))
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(sig)
	return enc, nil
}

func (a *asymmSigner) signatureString(r *http.Request, opts SignatureOption) (string, error) {
	return signatureString(r.Header, a.headers, addRequestTarget(r, opts), a.created, a.expires)
}

func (a *asymmSigner) signatureStringResponse(r http.ResponseWriter) (string, error) {
	return signatureString(r.Header(), a.headers, requestTargetNotPermitted, a.created, a.expires)
}

var _ SSHSigner = &asymmSSHSigner{}

type asymmSSHSigner struct {
	*asymmSigner
}

func (a *asymmSSHSigner) SignRequest(pubKeyID string, r *http.Request, body []byte) error {
	return a.asymmSigner.SignRequest(nil, pubKeyID, r, body)
}

func (a *asymmSSHSigner) SignResponse(pubKeyID string, r http.ResponseWriter, body []byte) error {
	return a.asymmSigner.SignResponse(nil, pubKeyID, r, body)
}

func setSignatureHeader(h http.Header, targetHeader, prefix, pubKeyID, algo, enc string, headers []string, created int64, expires int64) {
	if len(headers) == 0 {
		headers = defaultHeaders
	}
	var b bytes.Buffer
	// KeyID
	b.WriteString(prefix)
	if len(prefix) > 0 {
		b.WriteString(prefixSeparater)
	}
	b.WriteString(keyIDParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(pubKeyID)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)
	// Algorithm
	b.WriteString(algorithmParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString("hs2019") // real algorithm is hidden, see newest version of spec draft
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)

	hasCreated := false
	hasExpires := false
	for _, h := range headers {
		val := strings.ToLower(h)
		if val == "("+createdKey+")" {
			hasCreated = true
		} else if val == "("+expiresKey+")" {
			hasExpires = true
		}
	}

	// Created
	if hasCreated {
		b.WriteString(createdKey)
		b.WriteString(parameterKVSeparater)
		b.WriteString(strconv.FormatInt(created, 10))
		b.WriteString(parameterSeparater)
	}

	// Expires
	if hasExpires {
		b.WriteString(expiresKey)
		b.WriteString(parameterKVSeparater)
		b.WriteString(strconv.FormatInt(expires, 10))
		b.WriteString(parameterSeparater)
	}

	// Headers
	b.WriteString(headersParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	for i, h := range headers {
		b.WriteString(strings.ToLower(h))
		if i != len(headers)-1 {
			b.WriteString(headerParameterValueDelim)
		}
	}
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)
	// Signature
	b.WriteString(signatureParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(enc)
	b.WriteString(parameterValueDelimiter)
	h.Add(targetHeader, b.String())
}

func requestTargetNotPermitted(b *bytes.Buffer) error {
	return fmt.Errorf("cannot sign with %q on anything other than an http request", RequestTarget)
}

func addRequestTarget(r *http.Request, opts SignatureOption) func(b *bytes.Buffer) error {
	return func(b *bytes.Buffer) error {
		b.WriteString(RequestTarget)
		b.WriteString(headerFieldDelimiter)
		b.WriteString(strings.ToLower(r.Method))
		b.WriteString(requestTargetSeparator)
		b.WriteString(r.URL.Path)

		if !opts.ExcludeQueryStringFromPathPseudoHeader && r.URL.RawQuery != "" {
			b.WriteString("?")
			b.WriteString(r.URL.RawQuery)
		}

		return nil
	}
}

func signatureString(values http.Header, include []string, requestTargetFn func(b *bytes.Buffer) error, created int64, expires int64) (string, error) {
	if len(include) == 0 {
		include = defaultHeaders
	}
	var b bytes.Buffer
	for n, i := range include {
		i := strings.ToLower(i)
		switch {
		case i == RequestTarget:
			err := requestTargetFn(&b)
			if err != nil {
				return "", err
			}
		case i == "("+expiresKey+")":
			if expires == 0 {
				return "", fmt.Errorf("missing expires value")
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			b.WriteString(strconv.FormatInt(expires, 10))
		case i == "("+createdKey+")":
			if created == 0 {
				return "", fmt.Errorf("missing created value")
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			b.WriteString(strconv.FormatInt(created, 10))
		default:
			hv, ok := values[textproto.CanonicalMIMEHeaderKey(i)]
			if !ok {
				return "", fmt.Errorf("missing header %q", i)
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			for i, v := range hv {
				b.WriteString(strings.TrimSpace(v))
				if i < len(hv)-1 {
					b.WriteString(headerValueDelimiter)
				}
			}
		}
		if n < len(include)-1 {
			b.WriteString(headersDelimiter)
		}
	}
	return b.String(), nil
}
