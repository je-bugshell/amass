// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteGraphOutputJSONIncludesNodeType(t *testing.T) {
	buf := bytes.NewBufferString("")

	err := writeGraphOutputJSON(buf, testNodes(), testEdges())
	require.NoError(t, err)

	var graph jsonGraph
	err = json.Unmarshal(buf.Bytes(), &graph)
	require.NoError(t, err)
	require.Len(t, graph.Nodes, 2)

	assert.Equal(t, "FQDN", graph.Nodes[0].Type)
	assert.Equal(t, "IPAddress", graph.Nodes[1].Type)
	assert.Equal(t, 1, graph.Max)
}
