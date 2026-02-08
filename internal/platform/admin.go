package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AdminService struct {
	db *pgxpool.Pool
}

func NewAdminService(db *pgxpool.Pool) *AdminService {
	return &AdminService{db: db}
}

// AdminUser is the admin-facing view of a user.
type AdminUser struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	DisplayName  *string   `json:"display_name"`
	PgUsername   string    `json:"pg_username"`
	IsAdmin      bool      `json:"is_admin"`
	ProjectCount int       `json:"project_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// PaginatedUsers holds a page of users plus total count.
type PaginatedUsers struct {
	Users []AdminUser `json:"users"`
	Total int         `json:"total"`
	Page  int         `json:"page"`
	PerPage int       `json:"per_page"`
}

// ListUsers returns a paginated list of platform users with their project counts.
func (s *AdminService) ListUsers(ctx context.Context, page, perPage int) (*PaginatedUsers, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	// Get total count
	var total int
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM platform.users`).Scan(&total); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("count users: %w", err)
	}

	rows, err := s.db.Query(ctx, `
		SELECT u.id, u.email, u.display_name, COALESCE(p.pg_username, ''), u.is_admin, u.created_at,
			(SELECT COUNT(*) FROM platform.projects WHERE user_id = u.id AND status != 'deleted')
		FROM platform.users u
		LEFT JOIN platform.pg_users p ON p.user_id = u.id
		ORDER BY u.created_at ASC
		LIMIT $1 OFFSET $2
	`, perPage, offset)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []AdminUser
	for rows.Next() {
		var u AdminUser
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.PgUsername, &u.IsAdmin, &u.CreatedAt, &u.ProjectCount); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if users == nil {
		users = []AdminUser{}
	}
	return &PaginatedUsers{Users: users, Total: total, Page: page, PerPage: perPage}, http.StatusOK, nil
}

// DeleteUser deletes a platform user. Cannot delete yourself or other admins.
func (s *AdminService) DeleteUser(ctx context.Context, callerID, targetID string) (int, error) {
	if callerID == targetID {
		return http.StatusBadRequest, fmt.Errorf("cannot delete yourself")
	}

	var isAdmin bool
	err := s.db.QueryRow(ctx, `SELECT is_admin FROM platform.users WHERE id = $1`, targetID).Scan(&isAdmin)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("user not found")
	}
	if isAdmin {
		return http.StatusForbidden, fmt.Errorf("cannot delete an admin user")
	}

	// Delete user (CASCADE will clean up pg_users, projects, etc.)
	_, err = s.db.Exec(ctx, `DELETE FROM platform.users WHERE id = $1`, targetID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("delete user: %w", err)
	}
	return http.StatusOK, nil
}

// PlatformSettings holds platform-wide configuration.
type PlatformSettings struct {
	RegistrationMode string `json:"registration_mode"`
}

// GetSettings returns the platform settings.
func (s *AdminService) GetSettings(ctx context.Context) (*PlatformSettings, int, error) {
	var mode string
	err := s.db.QueryRow(ctx, `SELECT value FROM platform.settings WHERE key = 'registration_mode'`).Scan(&mode)
	if err != nil {
		mode = "open"
	}
	return &PlatformSettings{RegistrationMode: mode}, http.StatusOK, nil
}

// UpdateSettings updates the platform settings.
func (s *AdminService) UpdateSettings(ctx context.Context, settings PlatformSettings) (int, error) {
	valid := map[string]bool{"open": true, "invite": true, "disabled": true}
	if !valid[settings.RegistrationMode] {
		return http.StatusBadRequest, fmt.Errorf("registration_mode must be 'open', 'invite', or 'disabled'")
	}

	_, err := s.db.Exec(ctx, `
		INSERT INTO platform.settings (key, value, updated_at) VALUES ('registration_mode', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, settings.RegistrationMode)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("update settings: %w", err)
	}
	return http.StatusOK, nil
}

// Invite represents an invitation code.
type Invite struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Email     *string   `json:"email"`
	CreatedBy string    `json:"created_by"`
	UsedBy    *string   `json:"used_by"`
	UsedAt    *time.Time `json:"used_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateInviteRequest struct {
	Email     string `json:"email,omitempty"`
	ExpiresIn int    `json:"expires_in_hours,omitempty"` // default 72 hours
}

// CreateInvite generates a new invite code.
func (s *AdminService) CreateInvite(ctx context.Context, createdBy string, req CreateInviteRequest) (*Invite, int, error) {
	// Generate 16-byte hex code
	codeBytes := make([]byte, 16)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate code: %w", err)
	}
	code := hex.EncodeToString(codeBytes)

	expiresHours := req.ExpiresIn
	if expiresHours <= 0 {
		expiresHours = 72
	}
	expiresAt := time.Now().Add(time.Duration(expiresHours) * time.Hour)

	var email *string
	if req.Email != "" {
		email = &req.Email
	}

	var invite Invite
	err := s.db.QueryRow(ctx, `
		INSERT INTO platform.invites (code, email, created_by, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, code, email, created_by, used_by, used_at, expires_at, created_at
	`, code, email, createdBy, expiresAt).Scan(
		&invite.ID, &invite.Code, &invite.Email, &invite.CreatedBy,
		&invite.UsedBy, &invite.UsedAt, &invite.ExpiresAt, &invite.CreatedAt,
	)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create invite: %w", err)
	}

	return &invite, http.StatusCreated, nil
}

// ListInvites returns all invites.
func (s *AdminService) ListInvites(ctx context.Context) ([]Invite, int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, code, email, created_by, used_by, used_at, expires_at, created_at
		FROM platform.invites
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query invites: %w", err)
	}
	defer rows.Close()

	var invites []Invite
	for rows.Next() {
		var inv Invite
		if err := rows.Scan(&inv.ID, &inv.Code, &inv.Email, &inv.CreatedBy, &inv.UsedBy, &inv.UsedAt, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan invite: %w", err)
		}
		invites = append(invites, inv)
	}
	if invites == nil {
		invites = []Invite{}
	}
	return invites, http.StatusOK, nil
}

// DeleteInvite revokes an invite by ID.
func (s *AdminService) DeleteInvite(ctx context.Context, inviteID string) (int, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM platform.invites WHERE id = $1`, inviteID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("delete invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return http.StatusNotFound, fmt.Errorf("invite not found")
	}
	return http.StatusOK, nil
}
