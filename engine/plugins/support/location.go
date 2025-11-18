// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/open-asset-model/contact"
)

type parsedComponent struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type parsed struct {
	Parts []parsedComponent `json:"parts"`
}

type parseRequest struct {
	Address  string `json:"addr"`
	Language string `json:"lang"`
	Country  string `json:"country"`
}

var postalHost, postalPort string

func init() {
	postalHost = os.Getenv("POSTAL_SERVER_HOST")
	if postalHost == "" {
		postalHost = "0.0.0.0"
	}

	postalPort = os.Getenv("POSTAL_SERVER_PORT")
	if postalPort == "" {
		postalPort = "4001"
	}
}

func StreetAddressToLocation(address string) *contact.Location {
	if address == "" {
		return nil
	}

	parts, err := postalServerParseAddress(address)
	if err != nil {
		return nil
	}

	loc := &contact.Location{Address: address}
	for _, part := range parts {
		switch part.Label {
		case "house":
			loc.Building = part.Value
		case "house_number":
			loc.BuildingNumber = part.Value
		case "road":
			loc.StreetName = part.Value
		case "unit":
			loc.Unit = part.Value
		case "po_box":
			loc.POBox = part.Value
		case "city":
			loc.City = part.Value
		case "state":
			loc.Province = part.Value
		case "postcode":
			loc.PostalCode = part.Value
		case "country":
			loc.Country = part.Value
		case "suburb":
			fallthrough
		case "city_district":
			if s := part.Value; s != "" {
				loc.Locality = s
			}
		}
	}
	return loc
}

func postalServerParseAddress(address string) ([]parsedComponent, error) {
	reqJSON, err := json.Marshal(parseRequest{Address: address})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := http.RequestWebPage(ctx, &http.Request{
		Method: "POST",
		URL:    "http://" + postalHost + ":" + postalPort + "/parse",
		Body:   string(reqJSON),
	})
	if err != nil {
		return nil, err
	}

	var p parsed
	if err := json.Unmarshal([]byte("{\"parts\":"+resp.Body+"}"), &p); err != nil {
		return nil, err
	}
	return p.Parts, nil
}
