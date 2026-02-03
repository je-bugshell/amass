// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"fmt"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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

	cr, err := h.plugin.getContactRecord(e.Session, e.Entity, rlabel)
	if err != nil {
		return nil
	}

	orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, cr)
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

func (h *horRegRec) processAutnumRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the autnum record / registered autonomous system is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf > 0 {
		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
		for _, loc := range locs {
			_ = e.Session.Scope().Add(loc.Asset)
		}
		return
	}

	var confidence int
	otype := string(oam.Organization)
	if matches, err := e.Session.Config().CheckTransformations(otype, otype); err == nil && matches != nil {
		if conf := matches.Confidence(otype); conf >= 0 {
			confidence = conf
		}
	}

	var found bool
	if confidence > 0 {
		for _, o := range orgs {
			if _, conf := e.Session.Scope().IsAssetInScope(o.Asset, confidence); conf >= confidence {
				found = true
				break
			}
		}
	}

	confidence = 0
	ltype := string(oam.Location)
	if matches, err := e.Session.Config().CheckTransformations(ltype, ltype); err == nil && matches != nil {
		if conf := matches.Confidence(ltype); conf >= 0 {
			confidence = conf
		}
	}

	if !found && confidence > 0 {
		for _, loc := range locs {
			if _, conf := e.Session.Scope().IsAssetInScope(loc.Asset, confidence); conf >= confidence {
				found = true
				break
			}
		}
	}

	if found {
		// the autonomous system should be added to the scope
		if an, valid := e.Entity.Asset.(*oamreg.AutnumRecord); valid {
			_ = e.Session.Scope().AddASN(an.Number)
			h.plugin.addASNetblocksToScope(e.Session, an.Number)
		}
		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
		for _, loc := range locs {
			_ = e.Session.Scope().Add(loc.Asset)
		}
	}
}

func (h *horRegRec) processDomainRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the domain record / registered domain name is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf > 0 {
		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
		for _, loc := range locs {
			_ = e.Session.Scope().Add(loc.Asset)
		}
		return
	}
}

func (h *horRegRec) processIPNetRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the ipnet record / registered netblock is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf > 0 {
		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
		for _, loc := range locs {
			_ = e.Session.Scope().Add(loc.Asset)
		}
		return
	}

	var found bool
	for _, o := range orgs {
		if _, conf := e.Session.Scope().IsAssetInScope(o.Asset, 0); conf > 0 {
			found = true
			break
		}
	}

	if !found {
		for _, loc := range locs {
			if _, conf := e.Session.Scope().IsAssetInScope(loc.Asset, 0); conf > 0 {
				found = true
				break
			}
		}
	}

	if found {
		// the autonomous system should be added to the scope
		if iprec, valid := e.Entity.Asset.(*oamreg.IPNetRecord); valid {
			_ = e.Session.Scope().AddCIDR(iprec.CIDR.String())
		}
		for _, o := range orgs {
			_ = e.Session.Scope().Add(o.Asset)
		}
		for _, loc := range locs {
			_ = e.Session.Scope().Add(loc.Asset)
		}
	}
}
