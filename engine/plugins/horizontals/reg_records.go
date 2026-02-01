// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type horRegRec struct {
	name   string
	plugin *horizPlugin
}

func (h *horRegRec) Name() string {
	return h.name
}

func (h *horRegRec) check(e *et.Event) error {
	var rlabel string
	t := e.Entity.Asset.AssetType()

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	switch t {
	case oam.AutnumRecord:
		rlabel = "registrant"
	case oam.DomainRecord:
		rlabel = "registrant_contact"
	case oam.IPNetRecord:
		rlabel = "registrant"
	default:
		return fmt.Errorf("asset type not supported: %s", t)
	}

	orgs, locs := h.lookupRegistrantOrgsAndLocations(e, rlabel)
	if len(orgs) == 0 && len(locs) == 0 {
		return nil
	}

	switch t {
	case oam.AutnumRecord:
		h.processAutnumRecord(e, orgs, locs)
	case oam.DomainRecord:
		h.processDomainRecord(e, orgs, locs)
	case oam.IPNetRecord:
		h.processIPNetRecord(e, orgs, locs)
	}
	return nil
}

func (h *horRegRec) lookupRegistrantOrgsAndLocations(e *et.Event, rlabel string) ([]*oamorg.Organization, []*oamcon.Location) {
	cr, err := h.getRegistrantContactRecord(e, rlabel)
	if err != nil {
		return nil, nil
	}

	var orgents []*dbt.Entity
	var resorgs []*oamorg.Organization
	if ents, err := h.plugin.getContactRecordOrganizations(e, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if o, valid := ent.Asset.(*oamorg.Organization); valid {
				resorgs = append(resorgs, o)
				orgents = append(orgents, ent)
			}
		}
	}

	set := stringset.New()
	defer set.Close()

	var reslocs []*oamcon.Location
	for _, o := range orgents {
		if ents, err := h.plugin.getOrganizationLocations(e, o); err == nil && len(ents) > 0 {
			for _, ent := range ents {
				if set.Has(ent.ID) {
					continue
				}

				if loc, valid := ent.Asset.(*oamcon.Location); valid {
					set.Insert(ent.ID)
					reslocs = append(reslocs, loc)
				}
			}
		}
	}

	if ents, err := h.plugin.getContactRecordLocations(e, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if set.Has(ent.ID) {
				continue
			}

			if loc, valid := ent.Asset.(*oamcon.Location); valid {
				set.Insert(ent.ID)
				reslocs = append(reslocs, loc)
			}
		}
	}

	return resorgs, reslocs
}

func (h *horRegRec) getRegistrantContactRecord(e *et.Event, label string) (*dbt.Entity, error) {
	since, err := support.TTLStartTime(e.Session.Config(),
		string(e.Entity.Asset.AssetType()), string(oam.ContactRecord), h.plugin.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, since, label)
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

func (h *horRegRec) processAutnumRecord(e *et.Event, orgs []*oamorg.Organization, locs []*oamcon.Location) {
	// check if the autnum record / registered autonomous system is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf > 0 {
		for _, o := range orgs {
			e.Session.Scope().Add(o)
		}
		for _, loc := range locs {
			e.Session.Scope().Add(loc)
		}
		return
	}

	var found bool
	for _, o := range orgs {
		if _, conf := e.Session.Scope().IsAssetInScope(o, 0); conf > 0 {
			found = true
			break
		}
	}

	if !found {
		for _, loc := range locs {
			if _, conf := e.Session.Scope().IsAssetInScope(loc, 0); conf > 0 {
				found = true
				break
			}
		}
	}

	if found {
		// the autonomous system should be added to the scope
		if an, valid := e.Entity.Asset.(*oamreg.AutnumRecord); valid {
			e.Session.Scope().AddASN(an.Number)
		}
		for _, o := range orgs {
			e.Session.Scope().Add(o)
		}
		for _, loc := range locs {
			e.Session.Scope().Add(loc)
		}
	}
}

func (h *horRegRec) processDomainRecord(e *et.Event, orgs []*oamorg.Organization, locs []*oamcon.Location) {
	// check if the domain record / registered domain name is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf > 0 {
		for _, o := range orgs {
			e.Session.Scope().Add(o)
		}
		for _, loc := range locs {
			e.Session.Scope().Add(loc)
		}
		return
	}
}

func (h *horRegRec) processIPNetRecord(e *et.Event, orgs []*oamorg.Organization, locs []*oamcon.Location) {
	// check if the ipnet record / registered netblock is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf > 0 {
		for _, o := range orgs {
			e.Session.Scope().Add(o)
		}
		for _, loc := range locs {
			e.Session.Scope().Add(loc)
		}
		return
	}

	var found bool
	for _, o := range orgs {
		if _, conf := e.Session.Scope().IsAssetInScope(o, 0); conf > 0 {
			found = true
			break
		}
	}

	if !found {
		for _, loc := range locs {
			if _, conf := e.Session.Scope().IsAssetInScope(loc, 0); conf > 0 {
				found = true
				break
			}
		}
	}

	if found {
		// the autonomous system should be added to the scope
		if iprec, valid := e.Entity.Asset.(*oamreg.IPNetRecord); valid {
			e.Session.Scope().AddCIDR(iprec.CIDR.String())
		}
		for _, o := range orgs {
			e.Session.Scope().Add(o)
		}
		for _, loc := range locs {
			e.Session.Scope().Add(loc)
		}
	}
}
