// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package worker // import "miniflux.app/v2/worker"

import (
	"time"

	"miniflux.app/v2/config"
	"miniflux.app/v2/logger"
	"miniflux.app/v2/metric"
	"miniflux.app/v2/model"
	feedHandler "miniflux.app/v2/reader/handler"
	"miniflux.app/v2/storage"
)

// Worker refreshes a feed in the background.
type Worker struct {
	id    int
	store *storage.Storage
}

// Run wait for a job and refresh the given feed.
func (w *Worker) Run(c chan model.Job) {
	logger.Debug("[Worker] #%d started", w.id)

	for {
		job := <-c
		logger.Debug("[Worker #%d] Received feed #%d for user #%d", w.id, job.FeedID, job.UserID)

		startTime := time.Now()
		refreshErr := feedHandler.RefreshFeed(w.store, job.UserID, job.FeedID, false)

		if config.Opts.HasMetricsCollector() {
			status := "success"
			if refreshErr != nil {
				status = "error"
			}
			metric.BackgroundFeedRefreshDuration.WithLabelValues(status).Observe(time.Since(startTime).Seconds())
		}

		if refreshErr != nil {
			logger.Error("[Worker] Refreshing the feed #%d returned this error: %v", job.FeedID, refreshErr)
		}
	}
}
