// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ui // import "miniflux.app/v2/ui"

import (
	"net/http"

	"miniflux.app/v2/config"
	"miniflux.app/v2/http/cookie"
	"miniflux.app/v2/http/request"
	"miniflux.app/v2/http/response/html"
	"miniflux.app/v2/http/route"
	"miniflux.app/v2/logger"
	"miniflux.app/v2/ui/session"
)

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	sess := session.New(h.store, request.SessionID(r))
	user, err := h.store.UserByID(request.UserID(r))
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	sess.SetLanguage(user.Language)
	sess.SetTheme(user.Theme)

	if err := h.store.RemoveUserSessionByToken(user.ID, request.UserSessionToken(r)); err != nil {
		logger.Error("[UI:Logout] %v", err)
	}

	http.SetCookie(w, cookie.Expired(
		cookie.CookieUserSessionID,
		config.Opts.HTTPS,
		config.Opts.BasePath(),
	))

	html.Redirect(w, r, route.Path(h.router, "login"))
}
