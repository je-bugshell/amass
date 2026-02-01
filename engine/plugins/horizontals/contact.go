// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

type horContact struct {
	name   string
	plugin *horizPlugin
}

func (h *horContact) Name() string {
	return h.name
}

func (h *horContact) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamcon.ContactRecord)
	if !ok {
		return errors.New("failed to extract the ContactRecord asset")
	}

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	if ents, err := h.plugin.getContactRecordLocations(e, e.Entity); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if assocs := h.lookup(e, ent); len(assocs) > 0 {
				for _, assoc := range assocs {
					if assoc.ScopeChange {
						e.Session.Log().Info(assoc.Rationale)
					}
				}
			}
		}
	}

	if ents, err := h.plugin.getContactRecordOrganizations(e, e.Entity); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if assocs := h.lookup(e, ent); len(assocs) > 0 {
				for _, assoc := range assocs {
					if assoc.ScopeChange {
						e.Session.Log().Info(assoc.Rationale)
					}
				}
			}
		}
	}
	return nil
}

func (h *horContact) lookup(e *et.Event, asset *dbt.Entity) []*et.Association {
	if assocs, err := e.Session.Scope().IsAssociated(&et.Association{
		Submission:  asset,
		ScopeChange: true,
	}); err == nil {
		return assocs
	}
	return nil
}
