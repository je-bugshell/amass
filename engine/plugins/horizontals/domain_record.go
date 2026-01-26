// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type horDomRec struct {
	name   string
	plugin *horizPlugin
}

func (h *horDomRec) Name() string {
	return h.name
}

func (h *horDomRec) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamreg.DomainRecord)
	if !ok {
		return errors.New("failed to extract the DomainRecord asset")
	}

	if !h.isDomainRecordNameInScope(e) {
		return nil
	}

	cr, err := h.getRegistrantContactRecord(e)
	if err != nil {
		return nil
	}

	if ents, err := h.plugin.getContactRecordLocations(e, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			e.Session.Scope().Add(ent.Asset)
		}
	}

	if ents, err := h.plugin.getContactRecordOrganizations(e, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if o, valid := ent.Asset.(*oamorg.Organization); valid {
				e.Session.Scope().AddOrgByName(o.Name)
				if o.LegalName != "" {
					e.Session.Scope().AddOrgByName(o.LegalName)
				}
			}
		}
	}
	return nil
}

func (h *horDomRec) isDomainRecordNameInScope(e *et.Event) bool {
	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	ents, err := e.Session.DB().FindEntitiesByContent(ctx,
		e.Entity.Asset.AssetType(), since, 1, assetToContentFilters(e.Entity.Asset))
	if err != nil || len(ents) != 1 {
		return false
	}
	fqdn := ents[0]

	if _, conf := e.Session.Scope().IsAssetInScope(fqdn.Asset, 0); conf > 0 {
		return true
	}
	return false
}

func (h *horDomRec) getRegistrantContactRecord(e *et.Event) (*dbt.Entity, error) {
	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.DomainRecord), string(oam.ContactRecord), h.plugin.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, since, "registrant_contact")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("failed to obtain the registrant contact record")
	}

	to, err := e.Session.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	if err != nil {
		return nil, err
	}

	if _, valid := to.Asset.(*oamcon.ContactRecord); valid {
		return to, nil
	}
	return nil, errors.New("failed to extract the registrant ContactRecord entity")
}
