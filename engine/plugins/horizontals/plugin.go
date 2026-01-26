// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type horizPlugin struct {
	name       string
	log        *slog.Logger
	horfqdn    *horfqdn
	horaddr    *horaddr
	horContact *horContact
	horDomRec  *horDomRec
	source     *et.Source
}

func NewHorizontals() et.Plugin {
	return &horizPlugin{
		name: "Horizontals",
		source: &et.Source{
			Name:       "Horizontals",
			Confidence: 50,
		},
	}
}

func (h *horizPlugin) Name() string {
	return h.name
}

func (h *horizPlugin) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	h.horfqdn = &horfqdn{
		name:   h.name + "-FQDN-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horfqdn.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     h.horfqdn.check,
	}); err != nil {
		return err
	}

	h.horaddr = &horaddr{
		name:   h.name + "-IPAddress-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horaddr.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.IPAddress,
		Callback:     h.horaddr.check,
	}); err != nil {
		return err
	}

	h.horContact = &horContact{
		name:   h.name + "-ContactRecord-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horContact.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms: []string{
			string(oam.Organization),
			string(oam.Location),
			string(oam.Identifier),
		},
		EventType: oam.ContactRecord,
		Callback:  h.horContact.check,
	}); err != nil {
		return err
	}

	h.horDomRec = &horDomRec{
		name:   h.name + "-DomainRecord-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horfqdn.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.DomainRecord)},
		EventType:    oam.DomainRecord,
		Callback:     h.horDomRec.check,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *horizPlugin) Stop() {
	h.log.Info("Plugin stopped")
}

func assetToContentFilters(a oam.Asset) dbt.ContentFilters {
	filters := make(dbt.ContentFilters)

	switch v := a.(type) {
	case *oamdns.FQDN:
		filters["name"] = v.Name
	case *oamnet.IPAddress:
		filters["address"] = v.Address.String()
	case *oamnet.Netblock:
		filters["cidr"] = v.CIDR.String()
	case *oamnet.AutonomousSystem:
		filters["number"] = v.Number
	case *oamreg.DomainRecord:
		filters["domain"] = v.Domain
	case *oamreg.IPNetRecord:
		filters["handle"] = v.Handle
	case *oamreg.AutnumRecord:
		filters["handle"] = v.Handle
	case *oamgen.Identifier:
		filters["unique_id"] = v.UniqueID
	case *oamcert.TLSCertificate:
		filters["serial_number"] = v.SerialNumber
	case *oamurl.URL:
		filters["url"] = v.Raw
	case *oamorg.Organization:
		filters["unique_id"] = v.ID
	case *oamcon.Location:
		filters["address"] = v.Address
	}
	return filters
}

func (h *horizPlugin) submitIPAddress(e *et.Event, asset *oamnet.IPAddress, src *et.Source) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	// ensure we do not work on an IP address that was processed previously
	_, err := e.Session.DB().FindEntitiesByContent(ctx, oam.IPAddress, e.Session.StartTime(), 1, dbt.ContentFilters{
		"address": asset.Address.String(),
	})
	if err == nil {
		return
	}

	addr, err := e.Session.DB().CreateAsset(ctx, asset)
	if err == nil && addr != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, addr, &oamgen.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    addr.Asset.Key(),
			Entity:  addr,
			Session: e.Session,
		})
	}
}

func (h *horizPlugin) getContactRecordOrganizations(e *et.Event, cr *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.ContactRecord), string(oam.Organization), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, cr, since, "organization")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero organizations found")
	}

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamorg.Organization); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the organization")
	}
	return results, nil
}

func (h *horizPlugin) getContactRecordLocations(e *et.Event, cr *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.ContactRecord), string(oam.Location), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, cr, since, "location")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero locations found")
	}

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamorg.Organization); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the locations")
	}
	return results, nil
}
