// Copyright (c) 2019 Somia Reality Oy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/sqs"
)

var sess = session.Must(session.NewSession())
var queueURL string
var githubSecret []byte

func main() {
	queueURL = os.Getenv("QUEUE_URL")
	if queueURL == "" {
		panic("QUEUE_URL environment variable is empty")
	}

	encoded := os.Getenv("GITHUB_SECRET")
	if encoded == "" {
		panic("GITHUB_SECRET environment variable is empty")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(fmt.Sprintf("GITHUB_SECRET environment variable base64-decoding: %v", err))
	}

	output, err := kms.New(sess).Decrypt(&kms.DecryptInput{
		CiphertextBlob: []byte(ciphertext),
	})
	if err != nil {
		panic(fmt.Sprintf("GITHUB_SECRET environment variable decryption: %v", err))
	}

	githubSecret = output.Plaintext

	lambda.Start(handle)
}

func handle(ctx context.Context, req events.APIGatewayProxyRequest) (res events.APIGatewayProxyResponse, err error) {
	res.StatusCode = http.StatusInternalServerError

	if req.HTTPMethod != http.MethodPost {
		res.StatusCode = http.StatusMethodNotAllowed
		return
	}

	// Canonicalize header case.
	h := make(http.Header)
	for k, v := range req.Headers {
		h.Set(k, v)
	}

	if s := h.Get("Content-Type"); s != "application/json" {
		res.StatusCode = http.StatusUnsupportedMediaType
		return
	}

	s := h.Get("X-Hub-Signature")
	if !strings.HasPrefix(s, "sha1=") {
		res.StatusCode = http.StatusBadRequest
		return
	}
	allegedDigest, e := hex.DecodeString(s[len("sha1="):])
	if e != nil {
		res.StatusCode = http.StatusBadRequest
		return
	}

	mac := hmac.New(sha1.New, githubSecret)
	mac.Write([]byte(req.Body))
	if !hmac.Equal(mac.Sum(nil), allegedDigest) {
		res.StatusCode = http.StatusUnauthorized
		return
	}

	_, err = sqs.New(sess).SendMessageWithContext(ctx, &sqs.SendMessageInput{
		MessageBody: &req.Body,
		QueueUrl:    &queueURL,
	})
	if err != nil {
		if err == context.DeadlineExceeded {
			res.StatusCode = http.StatusGatewayTimeout
		} else {
			res.StatusCode = http.StatusBadGateway
		}
		return
	}

	res.StatusCode = http.StatusOK
	return
}
