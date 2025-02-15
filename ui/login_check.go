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
	"miniflux.app/v2/ui/form"
	"miniflux.app/v2/ui/session"
	"miniflux.app/v2/ui/view"
)

func (h *handler) checkLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := request.ClientIP(r)
	sess := session.New(h.store, request.SessionID(r))
	authForm := form.NewAuthForm(r)

	view := view.New(h.tpl, r, sess)
	view.Set("errorMessage", "error.bad_credentials")
	view.Set("form", authForm)

	if err := authForm.Validate(); err != nil {
		logger.Error("[UI:CheckLogin] %v", err)
		html.OK(w, r, view.Render("login"))
		return
	}

	if err := h.store.CheckPassword(authForm.Username, authForm.Password); err != nil {
		logger.Error("[UI:CheckLogin] [ClientIP=%s] %v", clientIP, err)
		html.OK(w, r, view.Render("login"))
		return
	}

	sessionToken, userID, err := h.store.CreateUserSessionFromUsername(authForm.Username, r.UserAgent(), clientIP)
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	logger.Info("[UI:CheckLogin] username=%s just logged in", authForm.Username)
	h.store.SetLastLogin(userID)

	user, err := h.store.UserByID(userID)
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	sess.SetLanguage(user.Language)
	sess.SetTheme(user.Theme)

	http.SetCookie(w, cookie.New(
		cookie.CookieUserSessionID,
		sessionToken,
		config.Opts.HTTPS,
		config.Opts.BasePath(),
	))

	html.Redirect(w, r, route.Path(h.router, user.DefaultHomePage))
}
