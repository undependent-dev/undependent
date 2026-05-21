// Package queue provides a SQLite-backed job queue with retry logic.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/undep/undep/internal/db"
)

// Queue wraps the DB layer with job lifecycle management.
type Queue struct {
	db *db.DB
}

// New creates a new Queue backed by the given DB.
func New(db *db.DB) *Queue {
	return &Queue{db: db}
}

// Enqueue adds a job to the queue. Returns the job ID.
func (q *Queue) Enqueue(jobType string, payload any) (string, error) {
	id := fmt.Sprintf("%s-%d", jobType, time.Now().UnixNano())
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	if err := q.db.CreateJob(id, jobType, string(payloadJSON)); err != nil {
		return "", fmt.Errorf("create job: %w", err)
	}
	return id, nil
}

// EnqueueWithID adds a job with a specific ID.
func (q *Queue) EnqueueWithID(id, jobType string, payload any) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	return q.db.CreateJob(id, jobType, string(payloadJSON))
}

// Dequeue fetches the next pending job of the given type.
// Returns nil if no jobs are pending.
func (q *Queue) Dequeue(ctx context.Context, jobType string) (*db.Job, error) {
	j, err := q.db.DequeueJob(jobType)
	if err != nil {
		if err.Error() == "no pending jobs" {
			return nil, nil
		}
		return nil, err
	}
	return j, nil
}

// Complete marks a job as done.
func (q *Queue) Complete(jobID string) error {
	return q.db.MarkJobComplete(jobID)
}

// Failed marks a job as failed with an error message.
// If attempts < 3, requeues the job with exponential backoff.
func (q *Queue) Failed(ctx context.Context, job *db.Job, errMsg string) error {
	if job.Attempts < 3 {
		// Exponential backoff: 1s, 4s, 16s
		backoff := time.Duration(1<<(job.Attempts-1)) * time.Second
		select {
		case <-time.After(backoff):
			return q.db.RequeueJob(job.ID)
		case <-ctx.Done():
			return q.db.MarkJobFailed(job.ID, errMsg)
		}
	}
	return q.db.MarkJobFailed(job.ID, errMsg)
}