// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package brute

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type brute struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewFQDNBruteForce() et.Plugin {
	return &brute{
		name: "FQDN-BruteForce",
		source: &et.Source{
			Name:       "FQDN-BruteForce",
			Confidence: 0,
		},
	}
}

func (b *brute) Name() string { return b.name }

func (b *brute) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       b,
		Name:         b.name + "-Handler",
		Priority:     8,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     b.check,
	}); err != nil {
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *brute) Stop() { b.log.Info("Plugin stopped") }

func (b *brute) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	cfg := e.Session.Config()
	if cfg == nil || !cfg.BruteForcing || len(cfg.Wordlist) == 0 {
		return nil
	}

	if e.Meta == nil {
		return nil
	}

	// Mirror the v4 script's has_addr / has_cname filters: only brute from
	// names that resolved directly to an address, skipping CNAME aliases.
	if support.HasDNSRecordType(e, int(dns.TypeCNAME)) {
		return nil
	}
	if !support.HasDNSRecordType(e, int(dns.TypeA)) && !support.HasDNSRecordType(e, int(dns.TypeAAAA)) {
		return nil
	}

	var dom string
	name := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if dfqdn, ok := a.(*oamdns.FQDN); !ok || dfqdn == nil {
		return nil
	} else {
		dom = dfqdn.Name
	}

	if !cfg.Recursive && name != dom {
		return nil
	}

	if cfg.MaxDepth > 0 {
		nparts := strings.Count(name, ".") + 1
		dparts := strings.Count(dom, ".") + 1
		if nparts > dparts+cfg.MaxDepth {
			return nil
		}
	}

	since, err := support.TTLStartTime(cfg, "FQDN", "FQDN", b.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, b.source, since) {
		return nil
	}

	guesses := make([]string, 0, len(cfg.Wordlist))
	for _, w := range cfg.Wordlist {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		guesses = append(guesses, w+"."+name)
	}
	if len(guesses) == 0 {
		return nil
	}

	assets := support.StoreFQDNsWithSource(e.Session, guesses, b.source, b.name, b.name+"-Handler")
	if len(assets) > 0 {
		support.ProcessFQDNsWithSource(e, assets, b.source)
		support.MarkAssetMonitored(e.Session, e.Entity, b.source)
	}
	return nil
}
