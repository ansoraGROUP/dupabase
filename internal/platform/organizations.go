package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OrgService manages organizations, memberships, and invites.
type OrgService struct {
	db *pgxpool.Pool
}

// NewOrgService creates a new OrgService.
func NewOrgService(db *pgxpool.Pool) *OrgService {
	return &OrgService{db: db}
}

// --- Types ---

// Organization represents a platform organization.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedBy string    `json:"created_by"`
	Role      string    `json:"role,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OrgDetail is an organization with member count.
type OrgDetail struct {
	Organization
	MemberCount int `json:"member_count"`
}

// OrgMember represents a member in an organization.
type OrgMember struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// OrgInvite represents an invitation to join an organization.
type OrgInvite struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	InvitedBy  string     `json:"invited_by"`
	Token      string     `json:"token"`
	AcceptedAt *time.Time `json:"accepted_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateOrgRequest is the request body for creating an organization.
type CreateOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// UpdateOrgRequest is the request body for updating an organization.
type UpdateOrgRequest struct {
	Name *string `json:"name,omitempty"`
	Slug *string `json:"slug,omitempty"`
}

// CreateOrgInviteRequest is the request body for creating an org invite.
type CreateOrgInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// --- Validation ---

var orgSlugRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{1,48}[a-z0-9]$`)

var roleHierarchy = map[string]int{
	"viewer":    1,
	"developer": 2,
	"admin":     3,
	"owner":     4,
}

// HasMinRole returns true if userRole is at least minRole in the hierarchy.
func HasMinRole(userRole, minRole string) bool {
	return roleHierarchy[userRole] >= roleHierarchy[minRole]
}

// --- Methods ---

// CreateOrg creates a new organization and adds the user as owner.
func (s *OrgService) CreateOrg(ctx context.Context, userID string, req CreateOrgRequest) (*Organization, int, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("name is required")
	}
	if len(name) > 100 {
		return nil, http.StatusBadRequest, fmt.Errorf("name must be at most 100 characters")
	}

	slug := strings.TrimSpace(req.Slug)
	if !orgSlugRegex.MatchString(slug) {
		return nil, http.StatusBadRequest, fmt.Errorf("slug must be 3-50 lowercase letters, numbers, or hyphens, starting with a letter")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var org Organization
	err = tx.QueryRow(ctx, `
		INSERT INTO platform.organizations (name, slug, created_by)
		VALUES ($1, $2, $3)
		RETURNING id, name, slug, created_by, created_at, updated_at
	`, name, slug, userID).Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedBy, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return nil, http.StatusConflict, fmt.Errorf("slug already taken")
		}
		return nil, http.StatusInternalServerError, fmt.Errorf("insert org: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO platform.org_members (org_id, user_id, role)
		VALUES ($1, $2, 'owner')
	`, org.ID, userID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("insert owner member: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("commit: %w", err)
	}

	org.Role = "owner"
	return &org, http.StatusCreated, nil
}

// ListOrgs returns all organizations the user is a member of.
func (s *OrgService) ListOrgs(ctx context.Context, userID string) ([]Organization, error) {
	rows, err := s.db.Query(ctx, `
		SELECT o.id, o.name, o.slug, o.created_by, o.created_at, o.updated_at, om.role
		FROM platform.organizations o
		JOIN platform.org_members om ON om.org_id = o.id
		WHERE om.user_id = $1
		ORDER BY o.created_at ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt, &o.Role); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	if orgs == nil {
		orgs = []Organization{}
	}
	return orgs, nil
}

// GetOrg returns an organization with member count.
func (s *OrgService) GetOrg(ctx context.Context, orgID string) (*OrgDetail, int, error) {
	var d OrgDetail
	err := s.db.QueryRow(ctx, `
		SELECT o.id, o.name, o.slug, o.created_by, o.created_at, o.updated_at,
			(SELECT COUNT(*) FROM platform.org_members WHERE org_id = o.id)
		FROM platform.organizations o
		WHERE o.id = $1
	`, orgID).Scan(&d.ID, &d.Name, &d.Slug, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.MemberCount)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("organization not found")
	}
	return &d, http.StatusOK, nil
}

// UpdateOrg updates an organization's name and/or slug.
func (s *OrgService) UpdateOrg(ctx context.Context, orgID string, req UpdateOrgRequest) (*Organization, int, error) {
	var current Organization
	err := s.db.QueryRow(ctx, `
		SELECT id, name, slug, created_by, created_at, updated_at
		FROM platform.organizations WHERE id = $1
	`, orgID).Scan(&current.ID, &current.Name, &current.Slug, &current.CreatedBy, &current.CreatedAt, &current.UpdatedAt)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("organization not found")
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return nil, http.StatusBadRequest, fmt.Errorf("name is required")
		}
		if len(name) > 100 {
			return nil, http.StatusBadRequest, fmt.Errorf("name must be at most 100 characters")
		}
		current.Name = name
	}
	if req.Slug != nil {
		slug := strings.TrimSpace(*req.Slug)
		if !orgSlugRegex.MatchString(slug) {
			return nil, http.StatusBadRequest, fmt.Errorf("slug must be 3-50 lowercase letters, numbers, or hyphens, starting with a letter")
		}
		current.Slug = slug
	}

	err = s.db.QueryRow(ctx, `
		UPDATE platform.organizations
		SET name = $1, slug = $2, updated_at = now()
		WHERE id = $3
		RETURNING updated_at
	`, current.Name, current.Slug, orgID).Scan(&current.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return nil, http.StatusConflict, fmt.Errorf("slug already taken")
		}
		return nil, http.StatusInternalServerError, fmt.Errorf("update org: %w", err)
	}

	return &current, http.StatusOK, nil
}

// DeleteOrg deletes an organization. Caller must be owner. Personal orgs cannot be deleted.
func (s *OrgService) DeleteOrg(ctx context.Context, orgID, userID string) (int, error) {
	// Verify caller is owner
	role, err := s.CheckOrgRole(ctx, orgID, userID)
	if err != nil {
		return http.StatusForbidden, fmt.Errorf("not a member of this organization")
	}
	if role != "owner" {
		return http.StatusForbidden, fmt.Errorf("only the owner can delete an organization")
	}

	// Check if personal org
	var slug string
	err = s.db.QueryRow(ctx, `SELECT slug FROM platform.organizations WHERE id = $1`, orgID).Scan(&slug)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("organization not found")
	}
	if strings.HasPrefix(slug, "personal-") {
		return http.StatusBadRequest, fmt.Errorf("cannot delete personal organization")
	}

	// Mark projects as deleted (don't DROP databases)
	_, err = s.db.Exec(ctx, `
		UPDATE platform.projects SET status = 'deleted', updated_at = NOW()
		WHERE org_id = $1 AND status != 'deleted'
	`, orgID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("mark projects deleted: %w", err)
	}

	// Delete org (CASCADE handles members + invites)
	_, err = s.db.Exec(ctx, `DELETE FROM platform.organizations WHERE id = $1`, orgID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("delete org: %w", err)
	}

	return http.StatusOK, nil
}

// ListMembers returns all members of an organization.
func (s *OrgService) ListMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	rows, err := s.db.Query(ctx, `
		SELECT om.id, om.org_id, om.user_id, u.email, om.role, om.created_at
		FROM platform.org_members om
		JOIN platform.users u ON u.id = om.user_id
		WHERE om.org_id = $1
		ORDER BY om.created_at ASC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []OrgMember
	for rows.Next() {
		var m OrgMember
		if err := rows.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Email, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	if members == nil {
		members = []OrgMember{}
	}
	return members, nil
}

// CreateInvite creates an invitation to join an organization.
func (s *OrgService) CreateInvite(ctx context.Context, orgID, inviterID string, req CreateOrgInviteRequest) (*OrgInvite, int, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid email format")
	}

	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "owner" {
		return nil, http.StatusBadRequest, fmt.Errorf("cannot invite as owner")
	}
	if _, ok := roleHierarchy[role]; !ok || role == "owner" {
		return nil, http.StatusBadRequest, fmt.Errorf("role must be admin, developer, or viewer")
	}

	// Check if user with this email is already a member
	var alreadyMember bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM platform.org_members om
			JOIN platform.users u ON u.id = om.user_id
			WHERE om.org_id = $1 AND u.email = $2
		)
	`, orgID, email).Scan(&alreadyMember)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("check membership: %w", err)
	}
	if alreadyMember {
		return nil, http.StatusConflict, fmt.Errorf("user is already a member of this organization")
	}

	// Generate 32-byte hex token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	var invite OrgInvite
	err = s.db.QueryRow(ctx, `
		INSERT INTO platform.org_invites (org_id, email, role, invited_by, token, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, org_id, email, role, invited_by, token, accepted_at, expires_at, created_at
	`, orgID, email, role, inviterID, token, expiresAt).Scan(
		&invite.ID, &invite.OrgID, &invite.Email, &invite.Role,
		&invite.InvitedBy, &invite.Token, &invite.AcceptedAt, &invite.ExpiresAt, &invite.CreatedAt,
	)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create invite: %w", err)
	}

	return &invite, http.StatusCreated, nil
}

// AcceptInvite accepts an organization invite by token.
func (s *OrgService) AcceptInvite(ctx context.Context, userID, token string) (*Organization, int, error) {
	var invite OrgInvite
	err := s.db.QueryRow(ctx, `
		SELECT id, org_id, email, role, invited_by, token, accepted_at, expires_at, created_at
		FROM platform.org_invites WHERE token = $1
	`, token).Scan(
		&invite.ID, &invite.OrgID, &invite.Email, &invite.Role,
		&invite.InvitedBy, &invite.Token, &invite.AcceptedAt, &invite.ExpiresAt, &invite.CreatedAt,
	)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("invite not found")
	}

	if invite.AcceptedAt != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invite already accepted")
	}
	if time.Now().After(invite.ExpiresAt) {
		return nil, http.StatusBadRequest, fmt.Errorf("invite has expired")
	}

	// Check user not already a member
	var alreadyMember bool
	err = s.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM platform.org_members WHERE org_id = $1 AND user_id = $2)
	`, invite.OrgID, userID).Scan(&alreadyMember)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("check membership: %w", err)
	}
	if alreadyMember {
		return nil, http.StatusConflict, fmt.Errorf("already a member of this organization")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO platform.org_members (org_id, user_id, role)
		VALUES ($1, $2, $3)
	`, invite.OrgID, userID, invite.Role)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("insert member: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE platform.org_invites SET accepted_at = now() WHERE id = $1
	`, invite.ID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("mark invite accepted: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("commit: %w", err)
	}

	var org Organization
	err = s.db.QueryRow(ctx, `
		SELECT id, name, slug, created_by, created_at, updated_at
		FROM platform.organizations WHERE id = $1
	`, invite.OrgID).Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedBy, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("get org: %w", err)
	}
	org.Role = invite.Role
	return &org, http.StatusOK, nil
}

// RemoveMember removes a member from an organization.
func (s *OrgService) RemoveMember(ctx context.Context, orgID, targetUserID string) (int, error) {
	// Check target's role
	var targetRole string
	err := s.db.QueryRow(ctx, `
		SELECT role FROM platform.org_members WHERE org_id = $1 AND user_id = $2
	`, orgID, targetUserID).Scan(&targetRole)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("member not found")
	}
	if targetRole == "owner" {
		return http.StatusForbidden, fmt.Errorf("cannot remove the organization owner")
	}

	tag, err := s.db.Exec(ctx, `
		DELETE FROM platform.org_members WHERE org_id = $1 AND user_id = $2
	`, orgID, targetUserID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("remove member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return http.StatusNotFound, fmt.Errorf("member not found")
	}
	return http.StatusOK, nil
}

// UpdateMemberRole updates a member's role in an organization.
func (s *OrgService) UpdateMemberRole(ctx context.Context, orgID, targetUserID, newRole string) (int, error) {
	// Validate new role
	if newRole == "owner" {
		return http.StatusBadRequest, fmt.Errorf("cannot set role to owner")
	}
	if _, ok := roleHierarchy[newRole]; !ok {
		return http.StatusBadRequest, fmt.Errorf("role must be admin, developer, or viewer")
	}

	// Check target's current role
	var currentRole string
	err := s.db.QueryRow(ctx, `
		SELECT role FROM platform.org_members WHERE org_id = $1 AND user_id = $2
	`, orgID, targetUserID).Scan(&currentRole)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("member not found")
	}
	if currentRole == "owner" {
		return http.StatusForbidden, fmt.Errorf("cannot change the owner's role")
	}

	_, err = s.db.Exec(ctx, `
		UPDATE platform.org_members SET role = $1 WHERE org_id = $2 AND user_id = $3
	`, newRole, orgID, targetUserID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("update role: %w", err)
	}
	return http.StatusOK, nil
}

// ListInvites returns pending invites for an organization.
func (s *OrgService) ListInvites(ctx context.Context, orgID string) ([]OrgInvite, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, org_id, email, role, invited_by, token, accepted_at, expires_at, created_at
		FROM platform.org_invites
		WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []OrgInvite
	for rows.Next() {
		var inv OrgInvite
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role,
			&inv.InvitedBy, &inv.Token, &inv.AcceptedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		invites = append(invites, inv)
	}
	if invites == nil {
		invites = []OrgInvite{}
	}
	return invites, nil
}

// RevokeInvite deletes an invite.
func (s *OrgService) RevokeInvite(ctx context.Context, orgID, inviteID string) (int, error) {
	tag, err := s.db.Exec(ctx, `
		DELETE FROM platform.org_invites WHERE id = $1 AND org_id = $2
	`, inviteID, orgID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("delete invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return http.StatusNotFound, fmt.Errorf("invite not found")
	}
	return http.StatusOK, nil
}

// CheckOrgRole returns the user's role in the org, or an error if not a member.
func (s *OrgService) CheckOrgRole(ctx context.Context, orgID, userID string) (string, error) {
	var role string
	err := s.db.QueryRow(ctx, `
		SELECT role FROM platform.org_members WHERE org_id = $1 AND user_id = $2
	`, orgID, userID).Scan(&role)
	if err != nil {
		return "", fmt.Errorf("not a member of this organization")
	}
	return role, nil
}

// GetPersonalOrgID returns the personal org ID for a user. Creates one if missing.
func (s *OrgService) GetPersonalOrgID(ctx context.Context, userID string) (string, error) {
	var orgID string
	err := s.db.QueryRow(ctx, `
		SELECT o.id FROM platform.organizations o
		WHERE o.slug = $1
	`, "personal-"+userID).Scan(&orgID)
	if err != nil {
		return "", fmt.Errorf("personal org not found for user %s", userID)
	}
	return orgID, nil
}
