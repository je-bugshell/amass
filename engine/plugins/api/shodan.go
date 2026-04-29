// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type shodan struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewShodan() et.Plugin {
	limit := rate.Every(time.Second)

	return &shodan{
		name:   "Shodan",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Shodan",
			Confidence: 80,
		},
	}
}

func (s *shodan) Name() string {
	return s.name
}

func (s *shodan) Start(r et.Registry) error {
	s.log = r.Log().WithGroup("plugin").With("name", s.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       s,
		Name:         s.name + "-Handler",
		Position:     26,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     s.check,
	}); err != nil {
		return err
	}

	s.log.Info("Plugin started")
	return nil
}

func (s *shodan) Stop() {
	s.log.Info("Plugin stopped")
}

func (s *shodan) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(s.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), s.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, s.source, since) {
		names = append(names, s.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, s.source)
	}

	if len(names) > 0 {
		s.process(e, names)
	}
	return nil
}

func (s *shodan) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

loop:
	for _, key := range keys {
		page := 1
		for page <= 500 {
			_ = s.rlimit.Wait(e.Session.Ctx())
			e.Session.NetSem().Acquire()

			ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
			resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
				URL: "https://api.shodan.io/dns/domain/" + name +
					"?key=" + key + "&page=" + strconv.Itoa(page),
			})
			cancel()
			e.Session.NetSem().Release()
			if err != nil || resp.Body == "" {
				break
			}

			var j struct {
				Domain     string   `json:"domain"`
				Subdomains []string `json:"subdomains"`
				Data       []struct {
					Subdomain string `json:"subdomain"`
					Type      string `json:"type"`
					Value     string `json:"value"`
				} `json:"data"`
				More bool `json:"more"`
			}
			if err := json.Unmarshal([]byte(resp.Body), &j); err != nil {
				break
			}

			for _, sub := range j.Subdomains {
				s.collect(e, subs, sub, name)
			}
			for _, rec := range j.Data {
				s.collect(e, subs, rec.Subdomain, name)
			}

			if !j.More {
				break loop
			}
			page++
		}
	}

	return s.store(e, subs.Slice())
}

func (s *shodan) collect(e *et.Event, set *stringset.Set, prefix, domain string) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	prefix = strings.TrimSuffix(prefix, ".")

	var full string
	if prefix == "" {
		full = domain
	} else {
		full = prefix + "." + domain
	}

	if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: full}, 0); conf > 0 {
		set.Insert(full)
	}
}

func (s *shodan) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, s.source, s.name, s.name+"-Handler")
}

func (s *shodan) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, s.source)
}
