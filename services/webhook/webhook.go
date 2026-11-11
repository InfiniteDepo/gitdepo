// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/git"
	linearglob "forgejo.org/modules/glob"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/queue"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/services/forms"
	"forgejo.org/services/webhook/sourcehut"
)

type Handler interface {
	Type() webhook_module.HookType
	Metadata(*webhook_model.Webhook) any
	// UnmarshalForm provides a function to bind the request to the form.
	// If form implements the [binding.Validator] interface, the Validate method will be called
	UnmarshalForm(bind func(form any)) forms.WebhookForm
	NewRequest(context.Context, *webhook_model.Webhook, *webhook_model.HookTask) (req *http.Request, body []byte, err error)
	Icon(size int) template.HTML
}

var webhookHandlers = []Handler{
	defaultHandler{true},
	defaultHandler{false},
	gogsHandler{},

	slackHandler{},
	discordHandler{},
	dingtalkHandler{},
	telegramHandler{},
	msteamsHandler{},
	feishuHandler{},
	matrixHandler{},
	wechatworkHandler{},
	packagistHandler{},
	sourcehut.BuildsHandler{},
}

// GetWebhookHandler return the handler for a given webhook type (nil if not found)
func GetWebhookHandler(name webhook_module.HookType) Handler {
	for _, h := range webhookHandlers {
		if h.Type() == name {
			return h
		}
	}
	return nil
}

// List provides a list of the supported webhooks
func List() []Handler {
	return webhookHandlers
}

// EnabledList provides a list of the webhook types the site admins have not disabled
func EnabledList(ctx context.Context) []Handler {
	return slices.DeleteFunc(slices.Clone(webhookHandlers), func(h Handler) bool { return !setting.IsWebhookTypeEnabled(ctx, h.Type()) })
}

// DisabledTypes returns the disabled types, to mark the existing hooks of these types
func DisabledTypes(ctx context.Context) map[string]bool {
	m := map[string]bool{}
	for _, t := range setting.Config().WebhookTypes.Value(ctx).Disabled {
		m[t] = true
	}
	return m
}

// CheckTypeEnabled returns a [util.ErrInvalidArgument] if site admins disabled the webhook type.
func CheckTypeEnabled(ctx context.Context, hookType string) error {
	if !setting.IsWebhookTypeEnabled(ctx, hookType) {
		return util.NewInvalidArgumentErrorf("webhook type %q is disabled by the site administrator", hookType)
	}
	return nil
}

// SetDisabledTypes stores the disabled webhook types. Unknown names are refused; duplicates are dropped.
func SetDisabledTypes(ctx context.Context, doer *user_model.User, disabled []string) error {
	s := setting.WebhookTypesState{}
	for _, t := range disabled {
		if !IsValidHookTaskType(t) {
			return util.NewInvalidArgumentErrorf("unknown webhook type %q", t)
		}
		if !slices.Contains(s.Disabled, t) {
			s.Disabled = append(s.Disabled, t)
		}
	}
	v, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().WebhookTypes.DynKey(): string(v)}); err != nil {
		return err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return nil
}

// IsValidHookTaskType returns true if a webhook registered
func IsValidHookTaskType(name string) bool {
	return GetWebhookHandler(name) != nil
}

// hookQueue is a global queue of web hooks
var hookQueue *queue.WorkerPoolQueue[int64]

// getPayloadBranch returns branch for hook event, if applicable.
func getPayloadBranch(p api.Payloader) string {
	var ref string
	switch pp := p.(type) {
	case *api.CreatePayload:
		ref = pp.Ref
	case *api.DeletePayload:
		ref = pp.Ref
	case *api.PushPayload:
		ref = pp.Ref
	case *api.MergeGroupPayload:
		ref = pp.MergeGroup.BaseRef // the branch the queue merges into
	}
	if strings.HasPrefix(ref, git.BranchPrefix) {
		return ref[len(git.BranchPrefix):]
	}
	return ""
}

// EventSource represents the source of a webhook action. Repository and/or Owner must be set.
type EventSource struct {
	Repository *repo_model.Repository
	Owner      *user_model.User
}

// handler delivers hook tasks
func handler(items ...int64) []int64 {
	ctx := graceful.GetManager().HammerContext()

	for _, taskID := range items {
		task, err := webhook_model.GetHookTaskByID(ctx, taskID)
		if err != nil {
			if errors.Is(err, util.ErrNotExist) {
				log.Warn("GetHookTaskByID[%d] warn: %v", taskID, err)
			} else {
				log.Error("GetHookTaskByID[%d] failed: %v", taskID, err)
			}
			continue
		}

		if task.IsDelivered {
			// Already delivered in the meantime
			log.Trace("Task[%d] has already been delivered", task.ID)
			continue
		}

		if err := Deliver(ctx, task); err != nil {
			log.Error("Unable to deliver webhook task[%d]: %v", task.ID, err)
		}
	}

	return nil
}

func enqueueHookTask(taskID int64) error {
	err := hookQueue.Push(taskID)
	if err != nil && err != queue.ErrAlreadyInQueue {
		return err
	}
	return nil
}

func checkBranch(w *webhook_model.Webhook, branch string) bool {
	if w.BranchFilter == "" || w.BranchFilter == "*" {
		return true
	}

	g, err := linearglob.CompileExact(w.BranchFilter)
	if err != nil {
		// should not really happen as BranchFilter is validated
		log.Error("CheckBranch failed: %s", err)
		return false
	}

	return g.MatchString(branch)
}

// PrepareWebhook creates a hook task and enqueues it for processing.
// The payload is saved as-is. The adjustments depending on the webhook type happen
// right before delivery, in the [Deliver] method.
func PrepareWebhook(ctx context.Context, w *webhook_model.Webhook, event webhook_module.HookEventType, p api.Payloader) error {
	// Skip sending if webhooks are disabled.
	if setting.DisableWebhooks {
		return nil
	}

	for _, e := range w.EventCheckers() {
		if event == e.Type {
			if !e.Has() {
				return nil
			}

			break
		}
	}

	// Avoid sending "0 new commits" to non-integration relevant webhooks (e.g. slack, discord, etc.).
	// Integration webhooks (e.g. drone) still receive the required data.
	if pushEvent, ok := p.(*api.PushPayload); ok &&
		w.Type != webhook_module.FORGEJO && w.Type != webhook_module.GITEA && w.Type != webhook_module.GOGS &&
		len(pushEvent.Commits) == 0 {
		return nil
	}

	// Merge queue builds are for CI: chat services don't get them
	if event == webhook_module.HookEventMergeGroup &&
		w.Type != webhook_module.FORGEJO && w.Type != webhook_module.GITEA && w.Type != webhook_module.GOGS {
		return nil
	}

	// If payload has no associated branch (e.g. it's a new tag, issue, etc.),
	// branch filter has no effect.
	if branch := getPayloadBranch(p); branch != "" {
		if !checkBranch(w, branch) {
			log.Info("Branch %q doesn't match branch filter %q, skipping", branch, w.BranchFilter)
			return nil
		}
	}

	payload, err := p.JSONPayload()
	if err != nil {
		return fmt.Errorf("JSONPayload for %s: %w", event, err)
	}

	task, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{
		HookID:         w.ID,
		PayloadContent: string(payload),
		EventType:      event,
		PayloadVersion: 2,
	})
	if err != nil {
		return fmt.Errorf("CreateHookTask for %s: %w", event, err)
	}

	return enqueueHookTask(task.ID)
}

// PrepareTestWebhook creates a hook task for test delivery and enqueues it for processing.
// It simulates a "push" event even though the webhook might not be enabled for that event.
func PrepareTestWebhook(ctx context.Context, w *webhook_model.Webhook, p api.Payloader) error {
	// Skip sending if webhooks are disabled.
	if setting.DisableWebhooks {
		return errors.New("webhooks are globally disabled")
	}

	payload, err := p.JSONPayload()
	if err != nil {
		return fmt.Errorf("JSONPayload for Test: %w", err)
	}

	task, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{
		HookID:         w.ID,
		PayloadContent: string(payload),
		EventType:      webhook_module.HookEventPush,
		PayloadVersion: 2,
	})
	if err != nil {
		return fmt.Errorf("CreateHookTask for Test: %w", err)
	}

	return enqueueHookTask(task.ID)
}

// PrepareWebhooks adds new webhooks to task queue for given payload.
func PrepareWebhooks(ctx context.Context, source EventSource, event webhook_module.HookEventType, p api.Payloader) error {
	if source.Repository != nil && source.Repository.IsTrashed() {
		return nil
	}
	owner := source.Owner

	var ws []*webhook_model.Webhook

	if source.Repository != nil {
		repoHooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{
			RepoID:   source.Repository.ID,
			IsActive: optional.Some(true),
		})
		if err != nil {
			return fmt.Errorf("ListWebhooksByOpts: %w", err)
		}
		ws = append(ws, repoHooks...)

		owner = source.Repository.MustOwner(ctx)

		// the hooks of its project, read from the repository as it is now: a move switches them
		if source.Repository.GroupID != 0 {
			groupHooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{
				OwnerID:  source.Repository.OwnerID,
				GroupID:  source.Repository.GroupID,
				IsActive: optional.Some(true),
			})
			if err != nil {
				return fmt.Errorf("ListWebhooksByOpts: %w", err)
			}
			ws = append(ws, groupHooks...)
		}
	}

	// append additional webhooks of a user or organization
	if owner != nil {
		ownerHooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{
			OwnerID:  owner.ID,
			IsActive: optional.Some(true),
		})
		if err != nil {
			return fmt.Errorf("ListWebhooksByOpts: %w", err)
		}
		ws = append(ws, ownerHooks...)
	}

	// Add any admin-defined system webhooks
	systemHooks, _, err := webhook_model.GetSystemWebhooks(ctx, db.ListOptions{ListAll: true}, true)
	if err != nil {
		return fmt.Errorf("GetSystemWebhooks: %w", err)
	}
	ws = append(ws, systemHooks...)

	if len(ws) == 0 {
		return nil
	}

	for _, w := range ws {
		if err := PrepareWebhook(ctx, w, event, p); err != nil {
			return err
		}
	}
	return nil
}

// ReplayHookTask replays a webhook task
func ReplayHookTask(ctx context.Context, w *webhook_model.Webhook, uuid string) error {
	task, err := webhook_model.ReplayHookTask(ctx, w.ID, uuid)
	if err != nil {
		return err
	}

	return enqueueHookTask(task.ID)
}
