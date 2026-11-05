// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package org

import (
	"context"

	"forgejo.org/models"
	org_model "forgejo.org/models/organization"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/services/mailer"
)

// CreateTeamInviteByEmail makes a persistent invite in db for someone without an account and mails it to them.
func CreateTeamInviteByEmail(ctx context.Context, inviter *user_model.User, team *org_model.Team, uname string) error {
	invite, err := org_model.CreateTeamInviteByEmail(ctx, inviter, team, uname)
	if err != nil {
		return err
	}

	return mailer.MailTeamInvite(ctx, inviter, team, invite)
}

// CreateTeamInviteByUser makes a persistent invite in db for someone with an account already and mails it.
func CreateTeamInviteByUser(ctx context.Context, inviter, invited *user_model.User, team *org_model.Team) error {
	invite, err := org_model.CreateTeamInviteForUser(ctx, inviter, invited, team)
	if err != nil {
		return err
	}
	// TODO: instead of only sending an email, also create an in-app notification
	return mailer.MailTeamInvite(ctx, inviter, team, invite)
}

// InviteOrAddTeamMember invites the user to the team if all team changes should go through invites, or adds them directly otherwise.
func InviteOrAddTeamMember(ctx context.Context, inviter, invited *user_model.User, team *org_model.Team) error {
	if setting.Service.AddMembersByInvitations && inviter.ID != invited.ID {
		// refuse before the invitation mail goes out; accepting it checks again
		if isMember, err := org_model.IsOrganizationMember(ctx, team.OrgID, invited.ID); err != nil {
			return err
		} else if !isMember {
			if err := org_model.CheckVerifiedDomainGate(ctx, team.OrgID, invited.ID); err != nil {
				return err
			}
		}
		return CreateTeamInviteByUser(ctx, inviter, invited, team)
	}
	return models.AddTeamMemberByCooptation(ctx, team, invited.ID, inviter.ID)
}

// AcceptInvite adds the doer to the invited team, deleting the invite
func AcceptInvite(ctx context.Context, team *org_model.Team, invite *org_model.TeamInvite, doer *user_model.User, hideMembership bool) error {
	if team.ID != invite.TeamID {
		return org_model.ErrTeamInviteNotFound{}
	}
	if org, err := org_model.GetOrgByID(ctx, team.OrgID); err != nil {
		return err
	} else if org.IsArchived {
		return org_model.ErrOrgArchived{Name: org.Name}
	}
	linkedToUser, invitedUserID := invite.InvitedID.Get()
	if linkedToUser && invitedUserID != doer.ID {
		return org_model.ErrTeamInviteNotFound{}
	}
	if invite.IsExpired() {
		return org_model.ErrTeamInviteExpired{}
	}
	if err := org_model.CheckInviteIsOwnAct(ctx, team, invite); err != nil {
		return err
	}
	if err := models.AddTeamMemberByCooptation(ctx, team, doer.ID, invite.InviterID); err != nil {
		return err
	}

	if err := org_model.ChangeOrgUserStatus(ctx, team.OrgID, doer.ID, !hideMembership); err != nil {
		return err
	}

	if err := org_model.RemoveInviteByID(ctx, invite.ID, team.ID); err != nil {
		log.Error("RemoveInviteByID: %v", err)
	}
	return nil
}

// DeclineInvite turns down an invitation to a team
func DeclineInvite(ctx context.Context, invite *org_model.TeamInvite) error {
	// TODO: notify the inviter here
	return org_model.RemoveInviteByID(ctx, invite.ID, invite.TeamID)
}
