// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ui // import "miniflux.app/v2/ui"

import (
	"net/http"

	"miniflux.app/v2/http/request"
	"miniflux.app/v2/http/response/html"
	"miniflux.app/v2/ui/session"
	"miniflux.app/v2/ui/view"
)

func (h *handler) showOfflinePage(w http.ResponseWriter, r *http.Request) {
	sess := session.New(h.store, request.SessionID(r))
	view := view.New(h.tpl, r, sess)
	html.OK(w, r, view.Render("offline"))
}
