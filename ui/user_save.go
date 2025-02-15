// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ui // import "miniflux.app/v2/ui"

import (
	"net/http"

	"miniflux.app/v2/http/request"
	"miniflux.app/v2/http/response/html"
	"miniflux.app/v2/http/route"
	"miniflux.app/v2/logger"
	"miniflux.app/v2/model"
	"miniflux.app/v2/ui/form"
	"miniflux.app/v2/ui/session"
	"miniflux.app/v2/ui/view"
	"miniflux.app/v2/validator"
)

func (h *handler) saveUser(w http.ResponseWriter, r *http.Request) {
	user, err := h.store.UserByID(request.UserID(r))
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	if !user.IsAdmin {
		html.Forbidden(w, r)
		return
	}

	userForm := form.NewUserForm(r)

	sess := session.New(h.store, request.SessionID(r))
	view := view.New(h.tpl, r, sess)
	view.Set("menu", "settings")
	view.Set("user", user)
	view.Set("countUnread", h.store.CountUnreadEntries(user.ID))
	view.Set("countErrorFeeds", h.store.CountUserFeedsWithErrors(user.ID))
	view.Set("form", userForm)

	if err := userForm.ValidateCreation(); err != nil {
		view.Set("errorMessage", err.Error())
		html.OK(w, r, view.Render("create_user"))
		return
	}

	if h.store.UserExists(userForm.Username) {
		view.Set("errorMessage", "error.user_already_exists")
		html.OK(w, r, view.Render("create_user"))
		return
	}

	userCreationRequest := &model.UserCreationRequest{
		Username: userForm.Username,
		Password: userForm.Password,
		IsAdmin:  userForm.IsAdmin,
	}

	if validationErr := validator.ValidateUserCreationWithPassword(h.store, userCreationRequest); validationErr != nil {
		view.Set("errorMessage", validationErr.TranslationKey)
		html.OK(w, r, view.Render("create_user"))
		return
	}

	if _, err := h.store.CreateUser(userCreationRequest); err != nil {
		logger.Error("[UI:SaveUser] %v", err)
		view.Set("errorMessage", "error.unable_to_create_user")
		html.OK(w, r, view.Render("create_user"))
		return
	}

	html.Redirect(w, r, route.Path(h.router, "users"))
}
