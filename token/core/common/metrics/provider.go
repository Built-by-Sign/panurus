/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"github.com/LFDT-Panurus/panurus/token"
)

const (
	NetworkLabel   MetricLabel = "network"
	ChannelLabel   MetricLabel = "channel"
	NamespaceLabel MetricLabel = "namespace"
)

type tmsProvider struct {
	tmsLabels []string
	provider  Provider
}

// NewTMSProvider returns a new metrics provider for the passed TMS ID and provider.
func NewTMSProvider(tmsID token.TMSID, provider Provider) *tmsProvider {
	return &tmsProvider{
		tmsLabels: []string{
			NetworkLabel, tmsID.Network,
			ChannelLabel, tmsID.Channel,
			NamespaceLabel, tmsID.Namespace,
		},
		provider: provider,
	}
}

// NewCounter returns a new counter for the passed options.
func (p *tmsProvider) NewCounter(o CounterOpts) Counter {
	return p.provider.NewCounter(o).With(p.tmsLabels...)
}

// NewGauge returns a new gauge for the passed options.
func (p *tmsProvider) NewGauge(o GaugeOpts) Gauge {
	return p.provider.NewGauge(o).With(p.tmsLabels...)
}

// NewHistogram returns a new histogram for the passed options.
func (p *tmsProvider) NewHistogram(o HistogramOpts) Histogram {
	return p.provider.NewHistogram(o).With(p.tmsLabels...)
}
