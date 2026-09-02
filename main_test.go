package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Helper function to create a test OvpnAdmin instance
func newTestOvpnAdmin() *OvpnAdmin {
	funcMap := template.FuncMap{
		"hasModule": func(modules []string, module string) bool {
			for _, m := range modules {
				if m == module {
					return true
				}
			}
			return false
		},
		"add": func(a, b int) int {
			return a + b
		},
		"humanBytes": humanBytes,
		"dict": func(values ...interface{}) map[string]interface{} {
			dict := make(map[string]interface{})
			for i := 0; i < len(values); i += 2 {
				key, _ := values[i].(string)
				dict[key] = values[i+1]
			}
			return dict
		},
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))
	template.Must(tmpl.ParseGlob("templates/partials/*.html"))

	return &OvpnAdmin{
		role:                   "master",
		lastSuccessfulSyncTime: "2025-01-01 12:00:00",
		clients:                []OpenvpnClient{},
		modules:                []string{"core"},
		createUserMutex:        &sync.Mutex{},
		htmlTemplates:          tmpl,
	}
}

// =============================================================================
// DashboardStats Tests
// =============================================================================

func TestCalculateStats_EmptyClients(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{}

	stats := oAdmin.calculateStats()

	if stats.TotalUsers != 0 {
		t.Errorf("Expected TotalUsers=0, got %d", stats.TotalUsers)
	}
	if stats.ActiveConnections != 0 {
		t.Errorf("Expected ActiveConnections=0, got %d", stats.ActiveConnections)
	}
	if stats.RevokedUsers != 0 {
		t.Errorf("Expected RevokedUsers=0, got %d", stats.RevokedUsers)
	}
	if stats.ExpiringSoon != 0 {
		t.Errorf("Expected ExpiringSoon=0, got %d", stats.ExpiringSoon)
	}
}

func TestCalculateStats_WithActiveUsers(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", Connections: 2, ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "user2", AccountStatus: "Active", Connections: 1, ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "user3", AccountStatus: "Active", Connections: 0, ExpirationDate: "2099-12-31 23:59:59"},
	}

	stats := oAdmin.calculateStats()

	if stats.TotalUsers != 3 {
		t.Errorf("Expected TotalUsers=3, got %d", stats.TotalUsers)
	}
	if stats.ActiveConnections != 3 {
		t.Errorf("Expected ActiveConnections=3, got %d", stats.ActiveConnections)
	}
	if stats.RevokedUsers != 0 {
		t.Errorf("Expected RevokedUsers=0, got %d", stats.RevokedUsers)
	}
}

func TestCalculateStats_WithRevokedUsers(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", Connections: 1, ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "user2", AccountStatus: "Revoked", Connections: 0, RevocationDate: "2025-01-01 00:00:00"},
		{Identity: "user3", AccountStatus: "Revoked", Connections: 0, RevocationDate: "2025-01-02 00:00:00"},
	}

	stats := oAdmin.calculateStats()

	if stats.TotalUsers != 3 {
		t.Errorf("Expected TotalUsers=3, got %d", stats.TotalUsers)
	}
	if stats.RevokedUsers != 2 {
		t.Errorf("Expected RevokedUsers=2, got %d", stats.RevokedUsers)
	}
}

func TestCalculateStats_WithExpiringSoon(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// Create dates relative to now
	now := time.Now()
	in10Days := now.AddDate(0, 0, 10).Format("2006-01-02 15:04:05")
	in25Days := now.AddDate(0, 0, 25).Format("2006-01-02 15:04:05")
	in60Days := now.AddDate(0, 0, 60).Format("2006-01-02 15:04:05")
	past := now.AddDate(0, 0, -5).Format("2006-01-02 15:04:05")

	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", ExpirationDate: in10Days},  // Expiring soon
		{Identity: "user2", AccountStatus: "Active", ExpirationDate: in25Days},  // Expiring soon
		{Identity: "user3", AccountStatus: "Active", ExpirationDate: in60Days},  // Not expiring soon
		{Identity: "user4", AccountStatus: "Active", ExpirationDate: past},      // Already expired (not counted)
		{Identity: "user5", AccountStatus: "Revoked", ExpirationDate: in10Days}, // Revoked, not counted
	}

	stats := oAdmin.calculateStats()

	if stats.TotalUsers != 5 {
		t.Errorf("Expected TotalUsers=5, got %d", stats.TotalUsers)
	}
	if stats.ExpiringSoon != 2 {
		t.Errorf("Expected ExpiringSoon=2, got %d", stats.ExpiringSoon)
	}
}

func TestCalculateStats_MixedScenario(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	now := time.Now()
	in15Days := now.AddDate(0, 0, 15).Format("2006-01-02 15:04:05")
	in90Days := now.AddDate(0, 0, 90).Format("2006-01-02 15:04:05")

	oAdmin.clients = []OpenvpnClient{
		{Identity: "alice", AccountStatus: "Active", Connections: 2, ExpirationDate: in90Days},
		{Identity: "bob", AccountStatus: "Active", Connections: 1, ExpirationDate: in15Days},
		{Identity: "charlie", AccountStatus: "Revoked", Connections: 0, ExpirationDate: in90Days},
		{Identity: "dave", AccountStatus: "Expired", Connections: 0, ExpirationDate: "2024-01-01 00:00:00"},
	}

	stats := oAdmin.calculateStats()

	if stats.TotalUsers != 4 {
		t.Errorf("Expected TotalUsers=4, got %d", stats.TotalUsers)
	}
	if stats.ActiveConnections != 3 {
		t.Errorf("Expected ActiveConnections=3, got %d", stats.ActiveConnections)
	}
	if stats.RevokedUsers != 1 {
		t.Errorf("Expected RevokedUsers=1, got %d", stats.RevokedUsers)
	}
	if stats.ExpiringSoon != 1 {
		t.Errorf("Expected ExpiringSoon=1, got %d", stats.ExpiringSoon)
	}
}

// =============================================================================
// HTTP Handler Tests
// =============================================================================

func TestIndexPageHandler_ReturnsHTML(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "testuser", AccountStatus: "Active", Connections: 1, ExpirationDate: "2099-12-31 23:59:59"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type text/html, got %s", contentType)
	}

	body := w.Body.String()

	// Verify key UI elements are present
	if !strings.Contains(body, "OpenVPN Admin") {
		t.Error("Response should contain 'OpenVPN Admin' title")
	}
	if !strings.Contains(body, "stats-grid") {
		t.Error("Response should contain stats grid")
	}
	if !strings.Contains(body, "User Management") {
		t.Error("Response should contain 'User Management' panel")
	}
}

func TestIndexPageHandler_MasterRole(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "master"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Master should have Add User button
	if !strings.Contains(body, "Add User") {
		t.Error("Master role should have 'Add User' button")
	}
	if !strings.Contains(body, "Primary") {
		t.Error("Master role should show 'Primary' badge")
	}
}

func TestIndexPageHandler_SlaveRole(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "slave"
	oAdmin.lastSuccessfulSyncTime = "2025-01-15 10:30:00"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Slave should show Replica badge with sync time
	if !strings.Contains(body, "Replica") {
		t.Error("Slave role should show 'Replica' badge")
	}
	if !strings.Contains(body, "Last sync") {
		t.Error("Slave role should show last sync time")
	}
}

func TestIndexPageHandler_StatusFilterCookie(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "statusFilter", Value: "revoked"})
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// The persisted filter marks its segment pressed on the initial render.
	if !strings.Contains(body, `data-status="revoked" aria-pressed="true"`) {
		t.Error("the Revoked segment should render pressed when the cookie holds it")
	}
	if strings.Contains(body, `data-status="all" aria-pressed="true"`) {
		t.Error("only the persisted segment should render pressed")
	}
}

func TestIndexPageHandler_StatsDisplayed(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	now := time.Now()
	in15Days := now.AddDate(0, 0, 15).Format("2006-01-02 15:04:05")
	in90Days := now.AddDate(0, 0, 90).Format("2006-01-02 15:04:05")

	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", Connections: 2, ExpirationDate: in90Days},
		{Identity: "user2", AccountStatus: "Active", Connections: 1, ExpirationDate: in15Days},
		{Identity: "user3", AccountStatus: "Revoked", Connections: 0, ExpirationDate: in90Days},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Verify stat cards are present
	if !strings.Contains(body, "Total users") {
		t.Error("Response should contain 'Total users' stat")
	}
	if !strings.Contains(body, "Connections") {
		t.Error("Response should contain 'Connections' stat")
	}
	if !strings.Contains(body, "Revoked") {
		t.Error("Response should contain 'Revoked' stat")
	}
	if !strings.Contains(body, "Expiring soon") {
		t.Error("Response should contain 'Expiring soon' stat")
	}
}

func TestModalCreateHandler(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/modal/create", nil)
	w := httptest.NewRecorder()

	oAdmin.modalCreateHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	// Verify modal elements
	if !strings.Contains(body, "Add New User") {
		t.Error("Create modal should contain 'Add New User' title")
	}
	if !strings.Contains(body, "modal-backdrop-custom") {
		t.Error("Create modal should have backdrop")
	}
	if !strings.Contains(body, "username") {
		t.Error("Create modal should have username field")
	}
	if !strings.Contains(body, "Create User") {
		t.Error("Create modal should have 'Create User' button")
	}
}

func TestModalCreateHandler_WithPasswordAuth(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.modules = []string{"core", "passwdAuth"}

	req := httptest.NewRequest(http.MethodGet, "/modal/create", nil)
	w := httptest.NewRecorder()

	oAdmin.modalCreateHandler(w, req)

	body := w.Body.String()

	// With passwdAuth module, password field should be present
	if !strings.Contains(body, "password") {
		t.Error("Create modal with passwdAuth should have password field")
	}
}

func TestModalDeleteHandler(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()

	// We need to set up routing context - use a simple workaround
	// by directly testing the template output
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_delete", map[string]interface{}{
		"Username": "testuser",
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "Delete User") {
		t.Error("Delete modal should contain 'Delete User' title")
	}
	if !strings.Contains(body, "testuser") {
		t.Error("Delete modal should contain username")
	}
	if !strings.Contains(body, "cannot be undone") {
		t.Error("Delete modal should contain warning message")
	}
}

func TestModalPasswordHandler(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_password", map[string]interface{}{
		"Username": "testuser",
		"Modules":  oAdmin.modules,
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "Change Password") {
		t.Error("Password modal should contain 'Change Password' title")
	}
	if !strings.Contains(body, "testuser") {
		t.Error("Password modal should contain username")
	}
	if !strings.Contains(body, "New Password") {
		t.Error("Password modal should have 'New Password' field")
	}
}

func TestModalRotateHandler(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.modules = []string{"core", "passwdAuth"}

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_rotate", map[string]interface{}{
		"Username": "testuser",
		"Modules":  oAdmin.modules,
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "Rotate Certificates") {
		t.Error("Rotate modal should contain 'Rotate Certificates' title")
	}
	if !strings.Contains(body, "testuser") {
		t.Error("Rotate modal should contain username")
	}
}

// =============================================================================
// Template Rendering Tests
// =============================================================================

func TestUserRowsTemplate_ActiveUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{
				Identity:         "activeuser",
				AccountStatus:    "Active",
				ConnectionStatus: "Connected",
				Connections:      2,
				ExpirationDate:   "2099-12-31 23:59:59",
			},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "activeuser") {
		t.Error("User rows should contain username")
	}
	if !strings.Contains(body, "connected-user") {
		t.Error("Connected user should have 'connected-user' class")
	}
	if !strings.Contains(body, "status-active") {
		t.Error("Active user should have 'status-active' badge")
	}
	if !strings.Contains(body, "bi-download") {
		t.Error("Active user should have download button")
	}
}

func TestUserRowsTemplate_RevokedUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{
				Identity:       "revokeduser",
				AccountStatus:  "Revoked",
				Connections:    0,
				RevocationDate: "2025-01-01 00:00:00",
			},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "revokeduser") {
		t.Error("User rows should contain username")
	}
	if !strings.Contains(body, "revoked-user") {
		t.Error("Revoked user should have 'revoked-user' class")
	}
	if !strings.Contains(body, "status-revoked") {
		t.Error("Revoked user should have 'status-revoked' badge")
	}
}

func TestUserRowsTemplate_ExpiredUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{
				Identity:       "expireduser",
				AccountStatus:  "Expired",
				Connections:    0,
				ExpirationDate: "2024-01-01 00:00:00",
			},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "expireduser") {
		t.Error("User rows should contain username")
	}
	if !strings.Contains(body, "expired-user") {
		t.Error("Expired user should have 'expired-user' class")
	}
	if !strings.Contains(body, "status-expired") {
		t.Error("Expired user should have 'status-expired' badge")
	}
}

func TestUserRowsTemplate_EmptyList(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// No users and no filter: offer the way to create the first one. The copy used to
	// blame a search that was not running.
	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users":      []OpenvpnClient{},
		"ServerRole": "master",
		"Modules":    []string{"core"},
		"Filtered":   false,
	})
	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "No users yet") {
		t.Error("An unfiltered empty list should say there are no users yet")
	}
	if !strings.Contains(body, "Add User") {
		t.Error("An unfiltered empty list should offer the Add User action")
	}
	if strings.Contains(body, "search") {
		t.Error("An unfiltered empty list must not blame a search that is not active")
	}
}

func TestUserRowsTemplate_EmptyListWhileFiltered(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users":      []OpenvpnClient{},
		"ServerRole": "master",
		"Modules":    []string{"core"},
		"Filtered":   true,
	})
	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "No matching users") {
		t.Error("A filtered empty list should say nothing matches")
	}
	if !strings.Contains(body, "clearFilters()") {
		t.Error("A filtered empty list should offer a way back to the full list")
	}
	if strings.Contains(body, "Add User") {
		t.Error("Add User is misleading here: users may exist but be filtered out")
	}
}

func TestUserActionsTemplate_MasterActiveUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.modules = []string{"core", "passwdAuth", "ccd"}

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_actions", map[string]interface{}{
		"User": OpenvpnClient{
			Identity:      "testuser",
			AccountStatus: "Active",
		},
		"ServerRole": "master",
		"Modules":    oAdmin.modules,
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	// Master should have all action buttons for active user
	if !strings.Contains(body, "bi-download") {
		t.Error("Should have download button")
	}
	if !strings.Contains(body, "bi-key") {
		t.Error("Should have password button (passwdAuth enabled)")
	}
	if !strings.Contains(body, "bi-diagram-3") {
		t.Error("Should have routes button (ccd enabled)")
	}
	if !strings.Contains(body, "bi-shield-x") {
		t.Error("Should have revoke button")
	}
}

func TestUserActionsTemplate_SlaveActiveUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.modules = []string{"core", "passwdAuth", "ccd"}

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_actions", map[string]interface{}{
		"User": OpenvpnClient{
			Identity:      "testuser",
			AccountStatus: "Active",
		},
		"ServerRole": "slave",
		"Modules":    oAdmin.modules,
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	// Slave should only have download and view routes
	if !strings.Contains(body, "bi-download") {
		t.Error("Should have download button")
	}
	if !strings.Contains(body, "bi-diagram-3") {
		t.Error("Should have view routes button (ccd enabled)")
	}
	// Slave should NOT have password or revoke buttons
	if strings.Contains(body, "bi-key") {
		t.Error("Slave should NOT have password button")
	}
	if strings.Contains(body, "bi-shield-x") {
		t.Error("Slave should NOT have revoke button")
	}
}

func TestUserActionsTemplate_RevokedUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_actions", map[string]interface{}{
		"User": OpenvpnClient{
			Identity:      "testuser",
			AccountStatus: "Revoked",
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	// Revoked user should have unrevoke, rotate, delete buttons
	if !strings.Contains(body, "bi-arrow-counterclockwise") {
		t.Error("Should have unrevoke button")
	}
	if !strings.Contains(body, "bi-arrow-repeat") {
		t.Error("Should have rotate button")
	}
	if !strings.Contains(body, "bi-trash") {
		t.Error("Should have delete button")
	}
}

func TestModalCcdTemplate(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_ccd", map[string]interface{}{
		"Ccd": Ccd{
			User:          "testuser",
			ClientAddress: "10.8.0.100",
			CustomRoutes: []ccdRoute{
				{Address: "192.168.1.0", Mask: "255.255.255.0", Description: "LAN"},
			},
		},
		"ServerRole": "master",
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "Client Routes") {
		t.Error("CCD modal should contain 'Client Routes' title")
	}
	if !strings.Contains(body, "10.8.0.100") {
		t.Error("CCD modal should show client address")
	}
	if !strings.Contains(body, "192.168.1.0") {
		t.Error("CCD modal should show route address")
	}
	if !strings.Contains(body, "Save Routes") {
		t.Error("Master should have 'Save Routes' button")
	}
}

func TestModalConfigTemplate(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "modal_config", map[string]interface{}{
		"Username": "testuser",
		"Config":   "client\ndev tun\nremote vpn.example.com 1194\n",
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "OpenVPN Configuration") {
		t.Error("Config modal should contain title")
	}
	if !strings.Contains(body, "testuser") {
		t.Error("Config modal should show username")
	}
	if !strings.Contains(body, "config-display") {
		t.Error("Config modal should have config display area")
	}
	if !strings.Contains(body, "Copy") {
		t.Error("Config modal should have Copy button")
	}
	if !strings.Contains(body, "Download") {
		t.Error("Config modal should have Download button")
	}
}

// =============================================================================
// CSS Class Tests (verify templates use correct CSS classes)
// =============================================================================

func TestCSSClassesInTemplates(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// Test index template has required CSS classes
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)
	body := w.Body.String()

	requiredClasses := []string{
		"app-header",
		"header-brand",
		"brand-mark",
		"stats-grid",
		"stat-card",
		"stat-value",
		"stat-label",
		"panel",
		"panel-header",
		"panel-title",
		"panel-toolbar",
		"search-wrapper",
		"search-input",
	}

	for _, class := range requiredClasses {
		if !strings.Contains(body, class) {
			t.Errorf("Index page should contain CSS class '%s'", class)
		}
	}
}

func TestBootstrapIconsInTemplates(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// Test that Bootstrap Icons are being used
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)
	body := w.Body.String()

	// Verify icon library is included
	if !strings.Contains(body, "bootstrap-icons") {
		t.Error("Bootstrap Icons CSS should be included")
	}

	// Verify some key icons are present. The summary strip carries no icons by
	// design: four figures with labels need no pictograms.
	icons := []string{
		"bi-shield-lock-fill", // Header icon
		"bi-person-badge",     // Panel title icon
		"bi-search",           // Search icon
	}

	for _, icon := range icons {
		if !strings.Contains(body, icon) {
			t.Errorf("Index page should contain icon '%s'", icon)
		}
	}
}

// =============================================================================
// DashboardStats Struct Tests
// =============================================================================

func TestDashboardStatsStruct(t *testing.T) {
	stats := DashboardStats{
		TotalUsers:        10,
		ActiveConnections: 5,
		RevokedUsers:      2,
		ExpiringSoon:      3,
	}

	if stats.TotalUsers != 10 {
		t.Errorf("Expected TotalUsers=10, got %d", stats.TotalUsers)
	}
	if stats.ActiveConnections != 5 {
		t.Errorf("Expected ActiveConnections=5, got %d", stats.ActiveConnections)
	}
	if stats.RevokedUsers != 2 {
		t.Errorf("Expected RevokedUsers=2, got %d", stats.RevokedUsers)
	}
	if stats.ExpiringSoon != 3 {
		t.Errorf("Expected ExpiringSoon=3, got %d", stats.ExpiringSoon)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestCalculateStats_InvalidExpirationDate(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", ExpirationDate: "invalid-date"},
		{Identity: "user2", AccountStatus: "Active", ExpirationDate: ""},
		{Identity: "user3", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
	}

	// Should not panic on invalid dates
	stats := oAdmin.calculateStats()

	if stats.TotalUsers != 3 {
		t.Errorf("Expected TotalUsers=3, got %d", stats.TotalUsers)
	}
	// Invalid dates should not count as expiring soon
	if stats.ExpiringSoon != 0 {
		t.Errorf("Expected ExpiringSoon=0 (invalid dates), got %d", stats.ExpiringSoon)
	}
}

func TestCalculateStats_HighConnectionCount(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", Connections: 100},
		{Identity: "user2", AccountStatus: "Active", Connections: 50},
	}

	stats := oAdmin.calculateStats()

	if stats.ActiveConnections != 150 {
		t.Errorf("Expected ActiveConnections=150, got %d", stats.ActiveConnections)
	}
}

// =============================================================================
// Stats Handler Tests
// =============================================================================

func TestStatsHandler(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	now := time.Now()
	in15Days := now.AddDate(0, 0, 15).Format("2006-01-02 15:04:05")
	in90Days := now.AddDate(0, 0, 90).Format("2006-01-02 15:04:05")

	oAdmin.clients = []OpenvpnClient{
		{Identity: "user1", AccountStatus: "Active", Connections: 2, ExpirationDate: in90Days},
		{Identity: "user2", AccountStatus: "Active", Connections: 1, ExpirationDate: in15Days},
		{Identity: "user3", AccountStatus: "Revoked", Connections: 0, ExpirationDate: in90Days},
	}

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()

	oAdmin.statsHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	// Verify stats cards content
	if !strings.Contains(body, "stat-card") {
		t.Error("Stats response should contain stat cards")
	}
	if !strings.Contains(body, "Total users") {
		t.Error("Stats response should contain 'Total users'")
	}
	if !strings.Contains(body, "Connections") {
		t.Error("Stats response should contain 'Connections'")
	}
}

func TestStatsCardsTemplate(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "stats_cards", map[string]interface{}{
		"Stats": DashboardStats{
			TotalUsers:        10,
			ActiveConnections: 5,
			RevokedUsers:      2,
			ExpiringSoon:      3,
		},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "stat-card") {
		t.Error("Stats cards should contain stat-card class")
	}
	if !strings.Contains(body, "warning") {
		t.Error("Stats cards should have warning class when ExpiringSoon > 0")
	}
	if !strings.Contains(body, "within 30 days") {
		t.Error("Stats cards should show 'within 30 days' text when ExpiringSoon > 0")
	}
}

// =============================================================================
// User List Handler Tests
// =============================================================================

func TestUserListHandler(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "testuser1", AccountStatus: "Active", Connections: 1, ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "testuser2", AccountStatus: "Revoked", Connections: 0, RevocationDate: "2025-01-01 00:00:00"},
	}

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	w := httptest.NewRecorder()

	oAdmin.userListHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	if !strings.Contains(body, "testuser1") {
		t.Error("User list should contain testuser1")
	}
	if !strings.Contains(body, "testuser2") {
		t.Error("User list should contain testuser2")
	}
}

func TestUserListHandler_StatusFilter(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "activeuser", AccountStatus: "Active", Connections: 1, ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "revokeduser", AccountStatus: "Revoked", Connections: 0, RevocationDate: "2025-01-01 00:00:00"},
	}

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "statusFilter", Value: "active"})
	w := httptest.NewRecorder()

	oAdmin.userListHandler(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "activeuser") {
		t.Error("User list should contain activeuser")
	}
	if strings.Contains(body, "revokeduser") {
		t.Error("User list should NOT contain revokeduser when the filter is Active")
	}
}

func TestUserListHandler_Search(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "alice", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "bob", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "charlie", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
	}

	req := httptest.NewRequest(http.MethodGet, "/users?search=ali", nil)
	w := httptest.NewRecorder()

	oAdmin.userListHandler(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "alice") {
		t.Error("Search for 'ali' should return alice")
	}
	if strings.Contains(body, "bob") {
		t.Error("Search for 'ali' should NOT return bob: no subsequence matches")
	}
	// The search is fuzzy: ch-a-r-l-i-e carries a, l, i in order, so charlie is a
	// legitimate (weaker) match and must rank below alice's prefix match.
	if !strings.Contains(body, "charlie") {
		t.Error("Fuzzy search for 'ali' should also return charlie (a-l-i as a subsequence)")
	}
	if strings.Index(body, "alice") > strings.Index(body, "charlie") {
		t.Error("alice's prefix match should rank above charlie's scattered subsequence")
	}
}

// =============================================================================
// ExpiringSoon Field Tests
// =============================================================================

func TestUserRowsTemplate_ExpiringSoonUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{
				Identity:       "expiringuser",
				AccountStatus:  "Active",
				Connections:    0,
				ExpirationDate: "2025-02-01 00:00:00",
				ExpiringSoon:   true,
			},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "expiring-soon-user") {
		t.Error("Expiring soon user should have 'expiring-soon-user' class")
	}
	if !strings.Contains(body, "expiring-badge") {
		t.Error("Expiring soon user should have expiring badge")
	}
}

// =============================================================================
// Dark Mode and Theme Tests
// =============================================================================

func TestDarkModeSupport(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Verify theme toggle button exists
	if !strings.Contains(body, "theme-toggle") {
		t.Error("Page should contain theme toggle button")
	}
	if !strings.Contains(body, "bi-sun-fill") {
		t.Error("Page should contain sun icon for light mode")
	}
	if !strings.Contains(body, "bi-moon-fill") {
		t.Error("Page should contain moon icon for dark mode")
	}
	// Verify data-theme attribute
	if !strings.Contains(body, "data-theme") {
		t.Error("HTML should have data-theme attribute")
	}
}

// =============================================================================
// Keyboard Shortcuts Tests
// =============================================================================

func TestKeyboardShortcutsModal(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Verify shortcuts modal exists
	if !strings.Contains(body, "shortcuts-modal") {
		t.Error("Page should contain keyboard shortcuts modal")
	}
	if !strings.Contains(body, "Keyboard Shortcuts") {
		t.Error("Page should contain 'Keyboard Shortcuts' text")
	}
	// Verify some shortcuts are documented
	if !strings.Contains(body, "<kbd>") {
		t.Error("Page should contain kbd elements for shortcuts")
	}
}

// =============================================================================
// Bulk Actions Tests
// =============================================================================

func TestBulkActionsBar(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "master"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Verify bulk actions bar exists for master
	if !strings.Contains(body, "bulk-actions-bar") {
		t.Error("Master should have bulk actions bar")
	}
	if !strings.Contains(body, "Revoke Selected") {
		t.Error("Bulk actions should have 'Revoke Selected' button")
	}
	if !strings.Contains(body, "select-all-checkbox") {
		t.Error("Master should have select all checkbox")
	}
}

func TestBulkActionsBar_SlaveHidden(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "slave"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// Slave should NOT have bulk actions div (check for the actual div, not comment)
	if strings.Contains(body, `id="bulk-actions-bar"`) {
		t.Error("Slave should NOT have bulk actions bar")
	}
	// Slave should NOT have Revoke Selected button
	if strings.Contains(body, "Revoke Selected") {
		t.Error("Slave should NOT have 'Revoke Selected' button")
	}
}

func TestUserRowsTemplate_CheckboxForMaster(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{Identity: "testuser", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "user-checkbox") {
		t.Error("Master role should have user checkboxes for selection")
	}
}

func TestUserRowsTemplate_NoCheckboxForSlave(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{Identity: "testuser", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
		},
		"ServerRole": "slave",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if strings.Contains(body, "user-checkbox") {
		t.Error("Slave role should NOT have user checkboxes")
	}
}

// =============================================================================
// Live Status Indicator Tests
// =============================================================================

func TestNoAutoRefresh(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)
	body := w.Body.String()

	// The background reload fought the search box, the row selection and open modals, so
	// it was removed along with the header indicator that toggled it.
	for _, gone := range []string{
		"setInterval",
		"autoRefreshInterval",
		"AUTO_REFRESH_MS",
		"startAutoRefresh",
		"toggleAutoRefresh",
		"visibilitychange",
		"live-indicator",
		"live-dot",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("auto-refresh residue still served to the browser: %q", gone)
		}
	}

	// Refreshing is still available, just only when asked for.
	if !strings.Contains(body, "function refreshUsers()") {
		t.Error("an explicit refresh helper should remain")
	}
	if !strings.Contains(body, "onclick=\"refreshUsers()\"") {
		t.Error("the toolbar Refresh button should call refreshUsers()")
	}
}

// =============================================================================
// HTMX Attributes Tests
// =============================================================================

func TestHTMXAttributesInUserRows(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{Identity: "testuser", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	// Verify correct HTMX targets
	if !strings.Contains(body, `hx-target="#user-table-body"`) {
		t.Error("Revoke button should target #user-table-body")
	}
	if !strings.Contains(body, `hx-swap="innerHTML"`) {
		t.Error("Actions should use innerHTML swap")
	}
}

func TestHTMXAttributesInModals(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// Test create modal
	w := httptest.NewRecorder()
	oAdmin.modalCreateHandler(w, httptest.NewRequest(http.MethodGet, "/modal/create", nil))
	body := w.Body.String()

	if !strings.Contains(body, `hx-post="/users"`) {
		t.Error("Create modal should POST to /users")
	}
	if !strings.Contains(body, `hx-target="#user-table-body"`) {
		t.Error("Create modal should target #user-table-body")
	}
}

// =============================================================================
// Form Validation Tests
// =============================================================================

func TestUsernamePatternInCreateModal(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	oAdmin.modalCreateHandler(w, httptest.NewRequest(http.MethodGet, "/modal/create", nil))
	body := w.Body.String()

	// Verify the fixed regex pattern (hyphen at start of character class)
	if !strings.Contains(body, `pattern="^[-a-zA-Z0-9_.@]+$"`) {
		t.Error("Username field should have correct regex pattern with hyphen at start")
	}
}

// =============================================================================
// Username Extraction Tests
// =============================================================================

func TestExtractUsername(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"user action", "/users/john/password", "john"},
		{"user delete", "/users/john", "john"},
		{"modal password", "/modal/password/john", "john"},
		{"modal rotate", "/modal/rotate/john", "john"},
		{"modal delete", "/modal/delete/john", "john"},
		{"modal ccd", "/modal/ccd/john", "john"},
		{"dotted username", "/modal/password/john.doe@example.com", "john.doe@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if got := oAdmin.extractUsername(r); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// Modal partials are fetched from /modal/{type}/{username}, so the rendered form
// must target that user. An empty username produces "/users//password", which the
// mux redirects to "/users/password" and answers 404.
func TestModalHandlers_RenderUserScopedFormAction(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		handler func(*OvpnAdmin) http.HandlerFunc
		want    string
	}{
		{"password", "/modal/password/john", func(o *OvpnAdmin) http.HandlerFunc { return o.modalPasswordHandler }, `hx-post="/users/john/password"`},
		{"rotate", "/modal/rotate/john", func(o *OvpnAdmin) http.HandlerFunc { return o.modalRotateHandler }, `hx-post="/users/john/rotate"`},
		{"delete", "/modal/delete/john", func(o *OvpnAdmin) http.HandlerFunc { return o.modalDeleteHandler }, `hx-delete="/users/john"`},
		{"ccd", "/modal/ccd/john", func(o *OvpnAdmin) http.HandlerFunc { return o.userShowCcdHandler }, `hx-post="/users/john/ccd"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oAdmin := newTestOvpnAdmin()
			w := httptest.NewRecorder()
			tt.handler(oAdmin)(w, httptest.NewRequest(http.MethodGet, tt.path, nil))

			body := w.Body.String()
			if strings.Contains(body, "/users//") {
				t.Errorf("%s modal rendered an empty username: form action contains \"/users//\"", tt.name)
			}
			if !strings.Contains(body, tt.want) {
				t.Errorf("%s modal should target %s", tt.name, tt.want)
			}
		})
	}
}

// =============================================================================
// Shell Injection Regression Tests
// =============================================================================

// Every value below reached "bash -c" via fmt.Sprintf before commands were switched
// to exec.Command with argument slices. Each payload creates a marker file if the
// argument is ever re-interpreted as shell syntax.
func TestRunCmd_DoesNotInterpretArgumentsAsShell(t *testing.T) {
	dir := t.TempDir()

	payloads := []struct {
		name string
		arg  string
	}{
		{"command substitution", "aaaaaa$(touch " + dir + "/pwned_subst)"},
		{"backticks", "aaaaaa`touch " + dir + "/pwned_tick`"},
		{"semicolon", "aaaaaa; touch " + dir + "/pwned_semi"},
		{"quote break", "'; touch " + dir + "/pwned_quote; echo '"},
		{"pipe", "aaaaaa | touch " + dir + "/pwned_pipe"},
		{"ampersand", "aaaaaa && touch " + dir + "/pwned_amp"},
		{"newline", "aaaaaa\ntouch " + dir + "/pwned_nl"},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			// echo is a stand-in for openvpn-user/easyrsa: it must receive the
			// payload as one inert argument.
			out, err := runCmd("echo", p.arg)
			if err != nil {
				t.Fatalf("runCmd returned error: %v", err)
			}
			if strings.TrimRight(out, "\n") != p.arg {
				t.Errorf("argument was altered in transit:\n got %q\nwant %q", strings.TrimRight(out, "\n"), p.arg)
			}
		})
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pwned_") {
			t.Errorf("SHELL INJECTION: payload executed and created %s", e.Name())
		}
	}
}

// checkStaticAddressIsFree runs before validateCcd has confirmed the address is a
// valid IP, so it must not hand the raw value to a shell.
func TestCheckStaticAddressIsFree_InjectionSafe(t *testing.T) {
	dir := t.TempDir()
	marker := dir + "/pwned_ccd"

	origCcd, origBackend := *ccdDir, *storageBackend
	*ccdDir, *storageBackend = dir, "filesystem"
	defer func() { *ccdDir, *storageBackend = origCcd, origBackend }()

	if err := os.WriteFile(dir+"/existing", []byte("ifconfig-push 172.16.100.5 255.255.255.0\n"), 0644); err != nil {
		t.Fatalf("seed ccd: %v", err)
	}

	checkStaticAddressIsFree("'; touch "+marker+"; echo '", "someuser")

	if _, err := os.Stat(marker); err == nil {
		t.Error("SHELL INJECTION: clientAddress payload executed via checkStaticAddressIsFree")
	}
}

// The Go reimplementation must keep the semantics of the grep pipeline it replaced.
func TestCheckStaticAddressIsFree_Semantics(t *testing.T) {
	dir := t.TempDir()
	origCcd, origBackend := *ccdDir, *storageBackend
	*ccdDir, *storageBackend = dir, "filesystem"
	defer func() { *ccdDir, *storageBackend = origCcd, origBackend }()

	if err := os.WriteFile(dir+"/alice", []byte("ifconfig-push 172.16.100.5 255.255.255.0\n"), 0644); err != nil {
		t.Fatalf("seed ccd: %v", err)
	}

	if checkStaticAddressIsFree("172.16.100.5", "bob") {
		t.Error("address held by alice should not be free for bob")
	}
	if !checkStaticAddressIsFree("172.16.100.5", "alice") {
		t.Error("a user's own address should be free for itself")
	}
	if !checkStaticAddressIsFree("172.16.100.99", "bob") {
		t.Error("unused address should be free")
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestHttpStatusFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"validation failure", userInputError{"password too short"}, http.StatusUnprocessableEntity},
		{"missing user", notFoundError{"ghost"}, http.StatusNotFound},
		{"wrapped validation", fmt.Errorf("create: %w", userInputError{"bad name"}), http.StatusUnprocessableEntity},
		{"wrapped not found", fmt.Errorf("delete: %w", notFoundError{"ghost"}), http.StatusNotFound},
		{"command failure", errors.New("easyrsa: exit status 1"), http.StatusInternalServerError},
		{"nil", nil, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpStatusFor(tt.err); got != tt.want {
				t.Errorf("httpStatusFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestValidators_ReturnUserInputError(t *testing.T) {
	var target userInputError

	if err := validateUsername("bad;rm -rf /"); !errors.As(err, &target) {
		t.Errorf("validateUsername should return userInputError, got %T", err)
	}
	if err := validatePassword("x"); !errors.As(err, &target) {
		t.Errorf("validatePassword should return userInputError, got %T", err)
	}
	if err := validateUsername("good.name"); err != nil {
		t.Errorf("valid username rejected: %v", err)
	}
	if err := validatePassword("longenough"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
}

// fWrite used to call log.Fatal (exiting the daemon) and always return nil, which made
// every "if err != nil" around it dead code.
func TestFWrite_ReturnsErrorInsteadOfExiting(t *testing.T) {
	err := fWrite(filepath.Join(t.TempDir(), "no-such-dir", "index.txt"), "data")
	if err == nil {
		t.Fatal("fWrite should return an error for an unwritable path")
	}
}

// A failed write must not clobber the previous contents: index.txt is the only record
// of which users exist.
func TestFWrite_IsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.txt")

	if err := fWrite(path, "original\n"); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if err := fWrite(path, "replacement\n"); err != nil {
		t.Fatalf("replacement write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "replacement\n" {
		t.Errorf("content = %q, want %q", got, "replacement\n")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestFirstLine(t *testing.T) {
	boom := errors.New("exit status 1")

	if got := firstLine("\n\n  easyrsa: cannot read index.txt\nmore\n", boom); got != "easyrsa: cannot read index.txt" {
		t.Errorf("firstLine picked %q", got)
	}
	if got := firstLine("", boom); got != "exit status 1" {
		t.Errorf("firstLine with empty output = %q, want the error", got)
	}
	if got := firstLine("", nil); got != "unknown error" {
		t.Errorf("firstLine with nothing = %q", got)
	}
}

// =============================================================================
// Toast Payload Escaping Tests
// =============================================================================

// HX-Trigger used to be built by string concatenation, so a username containing a
// quote broke out of the JSON string and could inject arbitrary trigger payloads.
func TestHxToast_EncodesHostileMessages(t *testing.T) {
	hostile := []string{
		`a"b`,
		`", "type": "success"}, "evil": {"x": "`,
		`back\slash`,
		"line\nbreak",
		`<img src=x onerror=alert(1)>`,
		"tab\there",
	}

	for _, msg := range hostile {
		t.Run(msg, func(t *testing.T) {
			header := hxToast("User "+msg+" deleted", "success")

			var decoded struct {
				ShowToast struct {
					Message string `json:"message"`
					Type    string `json:"type"`
				} `json:"showToast"`
			}
			if err := json.Unmarshal([]byte(header), &decoded); err != nil {
				t.Fatalf("header is not valid JSON (%q): %v", header, err)
			}

			want := "User " + msg + " deleted"
			if decoded.ShowToast.Message != want {
				t.Errorf("message round-tripped as %q, want %q", decoded.ShowToast.Message, want)
			}
			if decoded.ShowToast.Type != "success" {
				t.Errorf("type was altered to %q -- payload injection", decoded.ShowToast.Type)
			}
			// A raw newline in a header value would be rejected or truncated by net/http.
			if strings.ContainsAny(header, "\n\r") {
				t.Errorf("header contains a raw newline: %q", header)
			}
		})
	}
}

// The toast message must be assigned with textContent. Rendering it as HTML turns every
// error response into an XSS vector, since responseText is passed straight through.
func TestBaseTemplate_ToastDoesNotRenderMessageAsHtml(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	body := w.Body.String()

	if !strings.Contains(body, "label.textContent = text") {
		t.Error("showToast should assign the message via textContent")
	}
	if strings.Contains(body, "insertAdjacentHTML") {
		t.Error("showToast should not build the toast with insertAdjacentHTML")
	}
}

// =============================================================================
// Create-path Validation Tests
// =============================================================================

// exec.Command prevents shell injection but passes arguments through verbatim, so a
// username beginning with "-" still reaches easyrsa and openvpn-user as a flag.
func TestValidateUsername_RejectsArgumentInjection(t *testing.T) {
	for _, name := range []string{"-h", "--help", "--batch", "--db.path", "-", "--user"} {
		t.Run(name, func(t *testing.T) {
			if err := validateUsername(name); err == nil {
				t.Errorf("username %q should be rejected: it would be parsed as a flag", name)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		valid    bool
	}{
		{"plain", "alice", true},
		{"dots and dashes", "alice.smith-1", true},
		{"email style", "alice@example.com", true},
		{"underscore", "alice_smith", true},
		{"internal dash", "a-b", true},
		{"at max length", strings.Repeat("a", usernameMaxLength), true},

		{"empty", "", false},
		{"over max length", strings.Repeat("a", usernameMaxLength+1), false},
		{"space", "alice smith", false},
		{"slash", "alice/../etc", false},
		{"shell metacharacter", "alice;rm -rf /", false},
		{"single dot", ".", false},
		{"double dot", "..", false},
		{"reserved server", "server", false},
		{"contains REVOKED", "REVOKED-alice", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)
			if tt.valid && err != nil {
				t.Errorf("validateUsername(%q) rejected a valid name: %v", tt.username, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("validateUsername(%q) accepted an invalid name", tt.username)
			}
		})
	}
}

func TestValidatePassword_Bounds(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{"at minimum", strings.Repeat("x", passwordMinLength), true},
		{"below minimum", strings.Repeat("x", passwordMinLength-1), false},
		{"at maximum", strings.Repeat("x", passwordMaxLength), true},
		{"above maximum", strings.Repeat("x", passwordMaxLength+1), false},
		{"symbols are allowed", `P@ssw0rd!#$%^&*()`, true},
		{"spaces are allowed", "correct horse battery", true},
		{"unicode counted as runes", strings.Repeat("é", passwordMinLength), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)
			if tt.valid && err != nil {
				t.Errorf("validatePassword(len %d) rejected: %v", len(tt.password), err)
			}
			if !tt.valid && err == nil {
				t.Errorf("validatePassword(len %d) accepted", len(tt.password))
			}
		})
	}
}

// =============================================================================
// Bulk selection and delete Tests
// =============================================================================

func TestUserRowsTemplate_CheckboxForEveryStatus(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{Identity: "activeuser", AccountStatus: "Active", ExpirationDate: "2099-12-31 23:59:59"},
			{Identity: "revokeduser", AccountStatus: "Revoked", RevocationDate: "2025-01-01 00:00:00"},
			{Identity: "expireduser", AccountStatus: "Expired", ExpirationDate: "2020-01-01 00:00:00"},
		},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})
	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	// A revoked or expired user has to be selectable, otherwise it cannot be reached by
	// the bulk delete action at all.
	for _, status := range []string{"Active", "Revoked", "Expired"} {
		if !strings.Contains(body, `data-status="`+status+`"`) {
			t.Errorf("Expected a checkbox carrying data-status=%q", status)
		}
	}
	if got := strings.Count(body, "user-checkbox"); got != 3 {
		t.Errorf("Expected a checkbox on all 3 rows, got %d", got)
	}
}

func TestBulkActionsBar_HasDeleteSelected(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "master"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "Delete Selected") {
		t.Error("Bulk actions should offer a 'Delete Selected' button")
	}
	if !strings.Contains(body, `id="bulk-delete-btn"`) {
		t.Error("Bulk delete button needs the id the enable/disable logic looks up")
	}
	if !strings.Contains(body, `id="bulk-revoke-btn"`) {
		t.Error("Bulk revoke button needs the id the enable/disable logic looks up")
	}
}

func TestBulkActionsBar_DeleteHiddenForSlave(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "slave"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)

	if strings.Contains(w.Body.String(), "Delete Selected") {
		t.Error("Slave should NOT offer a 'Delete Selected' button")
	}
}

// =============================================================================
// visibleUsers Tests
// =============================================================================

func TestVisibleUsers_StatusFilterNarrowsToOneState(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "activeuser", AccountStatus: "Active"},
		{Identity: "revokeduser", AccountStatus: "Revoked"},
		{Identity: "expireduser", AccountStatus: "Expired"},
	}

	cases := []struct {
		filter string
		want   []string
	}{
		{"all", []string{"activeuser", "expireduser", "revokeduser"}},
		{"active", []string{"activeuser"}},
		{"revoked", []string{"revokeduser"}},
		{"expired", []string{"expireduser"}},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.AddCookie(&http.Cookie{Name: "statusFilter", Value: tc.filter})

		var got []string
		for _, user := range oAdmin.visibleUsers(req) {
			got = append(got, user.Identity)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("filter %q: expected %v, got %v", tc.filter, tc.want, got)
		}
	}

	// An explicit parameter wins over the persisted cookie.
	req := httptest.NewRequest(http.MethodGet, "/users?status=revoked", nil)
	req.AddCookie(&http.Cookie{Name: "statusFilter", Value: "active"})
	users := oAdmin.visibleUsers(req)
	if len(users) != 1 || users[0].Identity != "revokeduser" {
		t.Errorf("the status parameter should override the cookie, got %v", users)
	}
}

func TestVisibleUsers_SearchSurvivesMutation(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "alice", AccountStatus: "Active"},
		{Identity: "bob", AccountStatus: "Active"},
	}

	// A revoke posted while the search box holds "ali" carries the term back via
	// hx-include, so the re-rendered rows must stay filtered.
	req := httptest.NewRequest(http.MethodPost, "/users/alice/revoke", strings.NewReader("search=ali"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm failed: %v", err)
	}

	users := oAdmin.visibleUsers(req)
	if len(users) != 1 || users[0].Identity != "alice" {
		t.Errorf("Expected the search to still match only alice, got %v", users)
	}
}

func TestFuzzyMatch_RanksPrefixOverSubstringOverSubsequence(t *testing.T) {
	prefix, _, ok := fuzzyMatch("ali", "alice")
	if !ok {
		t.Fatal("prefix should match")
	}
	substring, _, ok := fuzzyMatch("ali", "malice")
	if !ok {
		t.Fatal("substring should match")
	}
	subsequence, positions, ok := fuzzyMatch("ale", "alice")
	if !ok {
		t.Fatal("subsequence should match: a-l-e appear in order in alice")
	}
	if prefix <= substring || substring <= subsequence {
		t.Errorf("expected prefix (%d) > substring (%d) > subsequence (%d)", prefix, substring, subsequence)
	}
	if len(positions) != 3 || positions[0] != 0 || positions[1] != 1 || positions[2] != 4 {
		t.Errorf("subsequence positions should be the matched runes, got %v", positions)
	}

	if _, _, ok := fuzzyMatch("xyz", "alice"); ok {
		t.Error("characters out of order or absent must not match")
	}
	if _, _, ok := fuzzyMatch("ecila", "alice"); ok {
		t.Error("fuzzy matching is ordered: reversed input must not match")
	}
	if _, _, ok := fuzzyMatch("ALICE", "alice"); !ok {
		t.Error("matching should be case-insensitive")
	}
}

func TestHighlightIdentity_WrapsMatchesAndEscapes(t *testing.T) {
	got := string(highlightIdentity("a<b", []int{0, 2}))
	want := "<mark>a</mark>&lt;<mark>b</mark>"
	if got != want {
		t.Errorf("highlightIdentity = %q, want %q - every non-mark character must be escaped", got, want)
	}

	// Adjacent positions merge into one mark, so the markup stays minimal.
	got = string(highlightIdentity("alice", []int{0, 1, 2}))
	want = "<mark>ali</mark>ce"
	if got != want {
		t.Errorf("highlightIdentity = %q, want %q", got, want)
	}
}

func TestVisibleUsers_FuzzySearchRanksAndHighlights(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.setClients([]OpenvpnClient{
		{Identity: "malice"},
		{Identity: "bob"},
		{Identity: "alice"},
		{Identity: "a-team"},
	})

	req := httptest.NewRequest(http.MethodGet, "/users?search=ali", nil)
	users := oAdmin.visibleUsers(req)

	if len(users) != 2 {
		t.Fatalf("expected alice and malice to match 'ali', got %v", users)
	}
	// alice is a prefix match and must outrank malice's mid-word substring,
	// even though malice comes first in the stored order.
	if users[0].Identity != "alice" || users[1].Identity != "malice" {
		t.Errorf("expected best match first [alice malice], got [%s %s]", users[0].Identity, users[1].Identity)
	}
	if string(users[0].IdentityHTML) != "<mark>ali</mark>ce" {
		t.Errorf("matched characters should be marked, got %q", users[0].IdentityHTML)
	}

	// A scattered subsequence still matches: 'atm' hits a-team.
	req = httptest.NewRequest(http.MethodGet, "/users?search=atm", nil)
	users = oAdmin.visibleUsers(req)
	if len(users) != 1 || users[0].Identity != "a-team" {
		t.Fatalf("expected the subsequence 'atm' to match only a-team, got %v", users)
	}

	// Without a search the names must render through Identity, not IdentityHTML.
	req = httptest.NewRequest(http.MethodGet, "/users", nil)
	for _, user := range oAdmin.visibleUsers(req) {
		if user.IdentityHTML != "" {
			t.Errorf("IdentityHTML should only be set while searching, got %q for %s", user.IdentityHTML, user.Identity)
		}
	}
}

func TestRenderUserRows_KeepsSearchAfterAction(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	dir := t.TempDir()
	origIndex, origBackend := *indexTxtPath, *storageBackend
	*indexTxtPath, *storageBackend = filepath.Join(dir, "index.txt"), "filesystem"
	defer func() { *indexTxtPath, *storageBackend = origIndex, origBackend }()

	if err := os.WriteFile(*indexTxtPath, []byte("V\t400101000000Z\t\t01\tunknown\t/CN=alice\nV\t400101000000Z\t\t02\tunknown\t/CN=bob\n"), 0o600); err != nil {
		t.Fatalf("writing index.txt: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/users/alice/revoke?search=ali", nil)
	w := httptest.NewRecorder()
	oAdmin.renderUserRows(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "alice") {
		t.Error("Re-rendered rows should still contain the searched user")
	}
	if strings.Contains(body, "bob") {
		t.Error("Re-rendered rows dropped the search filter and listed every user")
	}
}

// =============================================================================
// userDelete guard Tests
// =============================================================================

func TestUserDelete_RefusesActiveCertificate(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	dir := t.TempDir()
	origIndex, origBackend := *indexTxtPath, *storageBackend
	*indexTxtPath, *storageBackend = filepath.Join(dir, "index.txt"), "filesystem"
	defer func() { *indexTxtPath, *storageBackend = origIndex, origBackend }()

	// Flag V with an expiry in 2040: an active certificate.
	index := "V\t400101000000Z\t\t01\tunknown\t/CN=activeuser\n"
	if err := os.WriteFile(*indexTxtPath, []byte(index), 0o600); err != nil {
		t.Fatalf("writing index.txt: %v", err)
	}

	msg, err := oAdmin.userDelete("activeuser")
	if err == nil {
		t.Fatal("Deleting an active user must be refused: the entry is only renamed, so the certificate would stay valid and never enter the CRL")
	}

	var inputErr userInputError
	if !errors.As(err, &inputErr) {
		t.Errorf("Expected a userInputError so the handler answers 4xx, got %T", err)
	}
	if httpStatusFor(err) != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422, got %d", httpStatusFor(err))
	}
	if !strings.Contains(msg, "revoke") {
		t.Errorf("Message should tell the operator to revoke first, got %q", msg)
	}

	// The refusal has to happen before anything is written.
	after, readErr := os.ReadFile(*indexTxtPath)
	if readErr != nil {
		t.Fatalf("reading index.txt: %v", readErr)
	}
	if string(after) != index {
		t.Errorf("index.txt was modified by a refused delete:\n%s", after)
	}
}

func TestUserDelete_UnknownUserStillNotFound(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	dir := t.TempDir()
	origIndex, origBackend := *indexTxtPath, *storageBackend
	*indexTxtPath, *storageBackend = filepath.Join(dir, "index.txt"), "filesystem"
	defer func() { *indexTxtPath, *storageBackend = origIndex, origBackend }()

	if err := os.WriteFile(*indexTxtPath, nil, 0o600); err != nil {
		t.Fatalf("writing index.txt: %v", err)
	}

	_, err := oAdmin.userDelete("ghost")
	var missing notFoundError
	if !errors.As(err, &missing) {
		t.Errorf("Expected notFoundError for an unknown user, got %T (%v)", err, err)
	}
}

func TestUserAccountStatus(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	dir := t.TempDir()
	origIndex, origBackend := *indexTxtPath, *storageBackend
	*indexTxtPath, *storageBackend = filepath.Join(dir, "index.txt"), "filesystem"
	defer func() { *indexTxtPath, *storageBackend = origIndex, origBackend }()

	index := "V\t400101000000Z\t\t01\tunknown\t/CN=activeuser\n" +
		"V\t200101000000Z\t\t02\tunknown\t/CN=expireduser\n" +
		"R\t400101000000Z\t250101000000Z\t03\tunknown\t/CN=revokeduser\n"
	if err := os.WriteFile(*indexTxtPath, []byte(index), 0o600); err != nil {
		t.Fatalf("writing index.txt: %v", err)
	}

	for username, want := range map[string]string{
		"activeuser":  "Active",
		"expireduser": "Expired",
		"revokeduser": "Revoked",
		"ghost":       "",
	} {
		if got := oAdmin.userAccountStatus(username); got != want {
			t.Errorf("userAccountStatus(%q) = %q, want %q", username, got, want)
		}
	}
}

// =============================================================================
// Management interface Tests
// =============================================================================

func TestMgmtConnectedUsersParser_TruncatedReplyDoesNotPanic(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// A reply cut off by the read deadline ends mid-line. Truncated lines in both
	// the client list and the routing table used to index past the end of the
	// split and panic - fatally, when parsing ran in the updateState goroutine.
	truncated := "OpenVPN CLIENT LIST\n" +
		"Updated,2026-09-02 10:00:00\n" +
		"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n" +
		"alice,1.2.3.4:5555,100,200,2026-09-02 09:00:00\n" +
		"bob,5.6.7.8:1194,300,400,2026-09-02 08:00:00\n" +
		"charlie,9.9.9"

	users := oAdmin.mgmtConnectedUsersParser(truncated, "server1")
	if len(users) != 2 {
		t.Fatalf("expected the two complete lines to parse and the truncated one to be skipped, got %d users", len(users))
	}
	if users[0].CommonName != "alice" || users[1].CommonName != "bob" {
		t.Errorf("parsed the wrong users: %+v", users)
	}

	withRoutes := "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n" +
		"alice,1.2.3.4:5555,100,200,2026-09-02 09:00:00\n" +
		"ROUTING TABLE\n" +
		"Virtual Address,Common Name,Real Address,Last Ref\n" +
		"10.8.0.2,alice,1.2.3.4:5555,2026-09-02 09:59:59\n" +
		"10.8.0.3,al"

	users = oAdmin.mgmtConnectedUsersParser(withRoutes, "server1")
	if len(users) != 1 {
		t.Fatalf("expected one user, got %d", len(users))
	}
	if users[0].VirtualAddress != "10.8.0.2" {
		t.Errorf("the complete route line should still be applied, got %q", users[0].VirtualAddress)
	}
}

func TestMgmtRead_AssemblesReplyArrivingInChunks(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	client, server := net.Pipe()
	defer client.Close()

	reply := []string{
		"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n",
		"alice,1.2.3.4:5555,100,200,2026-09-02 09:00:00\n",
		"ROUTING TABLE\nGLOBAL STATS\nEND\n",
	}
	go func() {
		defer server.Close()
		for _, chunk := range reply {
			// The deadline must survive a reply that streams in slowly: it is
			// pushed forward on every read, so only an idle gap of
			// mgmtReadTimeout ends the read early.
			time.Sleep(20 * time.Millisecond)
			if _, err := server.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}()

	out := oAdmin.mgmtRead(client)
	if out != strings.Join(reply, "") {
		t.Errorf("mgmtRead should assemble the full reply, got %q", out)
	}
}

// =============================================================================
// Client state synchronization Tests
// =============================================================================

// TestClientsAccessors_ConcurrentUse hammers the accessors from concurrent
// goroutines the way handlers, hx refreshes and the updateState goroutine do.
// Run with -race (needs cgo) to make it meaningful as a race detector target;
// without it, it still exercises the lock paths.
func TestClientsAccessors_ConcurrentUse(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				oAdmin.setClients([]OpenvpnClient{{Identity: "alice"}})
				oAdmin.setActiveClients([]clientStatus{{CommonName: "alice"}})
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				for range oAdmin.getClients() {
				}
				for range oAdmin.getActiveClients() {
				}
			}
		}()
	}
	wg.Wait()

	if clients := oAdmin.getClients(); len(clients) != 1 || clients[0].Identity != "alice" {
		t.Errorf("unexpected final clients state: %+v", clients)
	}
}

// =============================================================================
// Dashboard Tests
// =============================================================================

func TestHumanBytes(t *testing.T) {
	for in, want := range map[string]string{
		"512":        "512 B",
		"2048":       "2.0 KB",
		"1572864":    "1.5 MB",
		"5368709120": "5.0 GB",
		"":           "",
		"garbage":    "garbage",
	} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDashboardPage_ShowsConnectionsAndRecentLogins(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.modules = []string{"core", "passwdAuth"}
	oAdmin.setActiveClients([]clientStatus{{
		CommonName:     "alice",
		RealAddress:    "203.0.113.7:51820",
		VirtualAddress: "192.168.100.2",
		BytesReceived:  "1572864",
		BytesSent:      "2048",
		ConnectedSince: "2026-09-02 08:00:00",
		ConnectedTo:    "main",
	}})
	writeAuthLog(t, "2026-09-02T08:00:01Z\tsuccess\talice\talice\t203.0.113.7:51820\n")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.dashboardPageHandler(w, req)

	body := w.Body.String()
	for _, want := range []string{
		"Connected Now", "alice", "203.0.113.7:51820", "192.168.100.2", "1.5 MB", "2.0 KB", "main",
		"Recent Logins", "stats-grid",
		`href="/users"`, // navigation to the management page
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard should contain %q", want)
		}
	}
	if strings.Contains(body, `id="user-table-body"`) {
		t.Error("the management table belongs to the Users page, not the dashboard")
	}
	if !strings.Contains(body, `aria-current="page"`) {
		t.Error("the active nav link should carry aria-current")
	}
}

func TestUsersPage_KeepsTableAndGainsNav(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "user-table-body") {
		t.Error("the Users page should keep the management table")
	}
	if !strings.Contains(body, `href="/"`) {
		t.Error("the Users page should link back to the dashboard")
	}
	if !strings.Contains(body, `hx-get="/partials/users"`) {
		t.Error("the row list should load from /partials/users now that GET /users is a page")
	}
}

func TestConnectionsHandler_EmptyState(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.mgmtInterfaces = map[string]string{}

	req := httptest.NewRequest(http.MethodGet, "/partials/connections", nil)
	w := httptest.NewRecorder()
	oAdmin.connectionsHandler(w, req)

	if !strings.Contains(w.Body.String(), "No active connections") {
		t.Error("an empty sweep should render the empty state")
	}
}

// =============================================================================
// Login activity Tests
// =============================================================================

// writeAuthLog points authLogPath at a temp file holding the given lines, in the
// exact format setup/auth.sh appends.
func writeAuthLog(t *testing.T, lines string) {
	t.Helper()
	dir := t.TempDir()
	orig := *authLogPath
	*authLogPath = filepath.Join(dir, "auth.log")
	t.Cleanup(func() { *authLogPath = orig })
	if err := os.WriteFile(*authLogPath, []byte(lines), 0o600); err != nil {
		t.Fatalf("writing auth log: %v", err)
	}
}

func TestParseAuthLog_NewestFirstSkippingMalformedLines(t *testing.T) {
	writeAuthLog(t,
		"2026-09-01T10:00:00Z\tsuccess\talice\talice\t10.1.2.3:51820\n"+
			"not a log line\n"+
			"2026-09-01T11:00:00Z\tbad-password\talice\talice\t10.1.2.3:51821\n")

	attempts := parseAuthLog(*authLogPath, 100)
	if len(attempts) != 2 {
		t.Fatalf("expected 2 parsed attempts with the malformed line skipped, got %d", len(attempts))
	}
	if attempts[0].Outcome != "bad-password" || attempts[1].Outcome != "success" {
		t.Errorf("attempts should come back newest first, got %+v", attempts)
	}
	if attempts[0].Source != "10.1.2.3:51821" {
		t.Errorf("source should carry the ip:port, got %q", attempts[0].Source)
	}

	if got := parseAuthLog(*authLogPath, 1); len(got) != 1 || got[0].Outcome != "bad-password" {
		t.Errorf("the limit should keep the newest entries, got %+v", got)
	}
	if parseAuthLog(filepath.Join(t.TempDir(), "absent.log"), 10) != nil {
		t.Error("a missing log is the normal no-password-auth state, not an error")
	}
}

func TestParseAuthLog_IncludesRotatedGeneration(t *testing.T) {
	writeAuthLog(t, "2026-09-02T10:00:00Z\tsuccess\talice\talice\t10.1.2.3:2\n")
	rotated := "2026-09-01T10:00:00Z\tsuccess\tbob\tbob\t10.1.2.4:1\n"
	if err := os.WriteFile(*authLogPath+".1", []byte(rotated), 0o600); err != nil {
		t.Fatalf("writing rotated log: %v", err)
	}

	attempts := parseAuthLog(*authLogPath, 100)
	if len(attempts) != 2 {
		t.Fatalf("expected the rotated generation to be read too, got %d attempts", len(attempts))
	}
	// Newest first across both generations: current file, then rotated.
	if attempts[0].Username != "alice" || attempts[1].Username != "bob" {
		t.Errorf("expected [alice bob] newest first across generations, got [%s %s]", attempts[0].Username, attempts[1].Username)
	}
}

func TestAuthLoginStats_FailuresResetOnSuccess(t *testing.T) {
	writeAuthLog(t,
		"2026-09-01T10:00:00Z\tbad-password\talice\talice\t10.1.2.3:1\n"+
			"2026-09-01T11:00:00Z\tsuccess\talice\talice\t10.1.2.3:2\n"+
			"2026-09-01T12:00:00Z\tbad-password\talice\talice\t10.1.2.3:3\n"+
			"2026-09-01T13:00:00Z\tbad-password\talice\talice\t10.1.2.3:4\n"+
			// A cn-mismatch counts against the certificate that was used, not
			// against the username the attacker typed.
			"2026-09-01T14:00:00Z\tcn-mismatch\tbob\talice\t9.9.9.9:5\n")

	stats := authLoginStats(*authLogPath)
	alice := stats["alice"]
	if alice.LastLogin != "2026-09-01T11:00:00Z" {
		t.Errorf("LastLogin should be the last success, got %q", alice.LastLogin)
	}
	if alice.FailedLogins != 3 {
		t.Errorf("expected 3 failures since the last success (2 bad passwords + 1 cn-mismatch on alice's cert), got %d", alice.FailedLogins)
	}
	if _, tracked := stats["bob"]; tracked {
		t.Error("the typed username of a cn-mismatch must not be charged: the attempt used alice's certificate")
	}
}

func TestUsersList_CarriesLoginActivity(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	dir := t.TempDir()
	origIndex, origBackend := *indexTxtPath, *storageBackend
	*indexTxtPath, *storageBackend = filepath.Join(dir, "index.txt"), "filesystem"
	defer func() { *indexTxtPath, *storageBackend = origIndex, origBackend }()
	index := "V\t400101000000Z\t\t01\tunknown\t/CN=alice\nV\t400101000000Z\t\t02\tunknown\t/CN=bob\n"
	if err := os.WriteFile(*indexTxtPath, []byte(index), 0o600); err != nil {
		t.Fatalf("writing index.txt: %v", err)
	}
	writeAuthLog(t,
		"2026-09-01T10:00:00Z\tsuccess\talice\talice\t10.1.2.3:1\n"+
			"2026-09-01T11:00:00Z\tbad-password\talice\talice\t10.1.2.3:2\n")

	for _, user := range oAdmin.usersList() {
		switch user.Identity {
		case "alice":
			if user.LastLogin != "2026-09-01T10:00:00Z" || user.FailedLogins != 1 {
				t.Errorf("alice should carry her login stats, got LastLogin=%q FailedLogins=%d", user.LastLogin, user.FailedLogins)
			}
		case "bob":
			if user.LastLogin != "" || user.FailedLogins != 0 {
				t.Errorf("bob has no recorded attempts and should carry none, got %+v", user)
			}
		}
	}
}

func TestModalActivityHandler_RendersAttempts(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	writeAuthLog(t,
		"2026-09-01T10:00:00Z\tsuccess\talice\talice\t10.1.2.3:51820\n"+
			"2026-09-01T11:00:00Z\tcn-mismatch\tbob\talice\t9.9.9.9:1\n")

	req := httptest.NewRequest(http.MethodGet, "/modal/activity", nil)
	w := httptest.NewRecorder()
	oAdmin.modalActivityHandler(w, req)

	body := w.Body.String()
	for _, want := range []string{"Login Activity", "Success", "CN mismatch", "10.1.2.3:51820", "cert: alice"} {
		if !strings.Contains(body, want) {
			t.Errorf("activity modal should contain %q", want)
		}
	}

	// And the empty state when nothing was ever recorded.
	orig := *authLogPath
	*authLogPath = filepath.Join(t.TempDir(), "absent.log")
	defer func() { *authLogPath = orig }()
	w = httptest.NewRecorder()
	oAdmin.modalActivityHandler(w, req)
	if !strings.Contains(w.Body.String(), "No login attempts recorded") {
		t.Error("an absent log should render the empty state, not an error")
	}
}

func TestModalActivityHandler_FiltersToOneUser(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	writeAuthLog(t,
		"2026-09-01T10:00:00Z\tsuccess\talice\talice\t10.1.2.3:1\n"+
			"2026-09-01T11:00:00Z\tsuccess\tbob\tbob\t10.1.2.4:2\n"+
			// eve typed her own name but presented alice's certificate: this
			// belongs to alice's history, not just eve's.
			"2026-09-01T12:00:00Z\tcn-mismatch\teve\talice\t9.9.9.9:3\n")

	req := httptest.NewRequest(http.MethodGet, "/modal/activity?user=alice", nil)
	w := httptest.NewRecorder()
	oAdmin.modalActivityHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Login History") || !strings.Contains(body, ">alice</span>") {
		t.Error("a filtered modal should be titled with the username")
	}
	if !strings.Contains(body, "10.1.2.3:1") {
		t.Error("alice's own successful login should be listed")
	}
	if !strings.Contains(body, "9.9.9.9:3") {
		t.Error("an attempt using alice's certificate under another name belongs in her history")
	}
	if strings.Contains(body, "10.1.2.4:2") {
		t.Error("bob's attempts must not appear in alice's history")
	}

	// A user with no attempts gets a scoped empty state, not an error.
	req = httptest.NewRequest(http.MethodGet, "/modal/activity?user=carol", nil)
	w = httptest.NewRecorder()
	oAdmin.modalActivityHandler(w, req)
	if !strings.Contains(w.Body.String(), "No login attempts recorded for carol") {
		t.Error("expected the per-user empty state")
	}
}

func TestUserActions_HistoryButtonNeedsPasswdAuth(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	render := func(modules []string, status string) string {
		w := httptest.NewRecorder()
		err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
			"Users":      []OpenvpnClient{{Identity: "alice", AccountStatus: status}},
			"ServerRole": "master",
			"Modules":    modules,
		})
		if err != nil {
			t.Fatalf("rendering user_rows: %v", err)
		}
		return w.Body.String()
	}

	// With password auth the button appears for every status: revoked and
	// expired accounts can still be probed.
	for _, status := range []string{"Active", "Revoked", "Expired"} {
		if !strings.Contains(render([]string{"core", "passwdAuth"}, status), "/modal/activity?user=alice") {
			t.Errorf("history button should render for a %s user when passwdAuth is on", status)
		}
	}
	if strings.Contains(render([]string{"core"}, "Active"), "/modal/activity") {
		t.Error("without passwdAuth there is no attempt log, so no history button")
	}
}

func TestUserRows_ShowFailedLoginsAndLastLogin(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users": []OpenvpnClient{
			{Identity: "alice", AccountStatus: "Active", LastLogin: "2026-09-01T10:00:00Z", FailedLogins: 3},
			{Identity: "bob", AccountStatus: "Active"},
		},
		"ServerRole": "master",
	})
	if err != nil {
		t.Fatalf("rendering user_rows: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "3 failed") {
		t.Error("a user with failures since their last login should carry a failed badge")
	}
	if !strings.Contains(body, "last login 2026-09-01T10:00:00Z") {
		t.Error("the last successful login should be shown under the username")
	}
	if strings.Count(body, "failed-badge") != 1 || strings.Count(body, "last-login") != 1 {
		t.Error("users without recorded activity must not render activity markup")
	}
}

// =============================================================================
// PKI file archiving Tests
// =============================================================================

// writePkiFile creates path with its parent directories.
func writePkiFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// setupPkiTestDirs points easyrsaDirPath, indexTxtPath and storageBackend at a
// temp directory and installs a stub easyrsa binary there. The stub mimics the
// real one where these tests need it to: build-client-full refuses a name whose
// request file exists (the behaviour under test), otherwise writes the crt/key/req
// files and appends an index entry with serial 99; every other subcommand
// (gen-crl) succeeds silently.
func setupPkiTestDirs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	origDir, origIndex, origBin, origBackend := *easyrsaDirPath, *indexTxtPath, *easyrsaBinPath, *storageBackend
	*easyrsaDirPath = dir
	*indexTxtPath = filepath.Join(dir, "pki", "index.txt")
	*easyrsaBinPath = filepath.Join(dir, "easyrsa")
	*storageBackend = "filesystem"
	t.Cleanup(func() {
		*easyrsaDirPath, *indexTxtPath, *easyrsaBinPath, *storageBackend = origDir, origIndex, origBin, origBackend
	})

	script := `#!/bin/sh
if [ "$2" = "build-client-full" ]; then
  if [ "$3" = "failuser" ]; then
    echo "stub: refusing to issue for failuser" >&2
    exit 1
  fi
  if [ -e "pki/reqs/$3.req" ]; then
    echo "Request file already exists. Aborting build to avoid overwriting this file." >&2
    exit 1
  fi
  mkdir -p pki/issued pki/private pki/reqs
  echo crt > "pki/issued/$3.crt"
  echo key > "pki/private/$3.key"
  echo req > "pki/reqs/$3.req"
  printf 'V\t400101000000Z\t\t99\tunknown\t/CN=%s\n' "$3" >> pki/index.txt
fi
exit 0
`
	if err := os.WriteFile(*easyrsaBinPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write easyrsa stub: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	return dir
}

func TestArchiveUserPkiFiles_MovesLeftoverFilesAside(t *testing.T) {
	dir := setupPkiTestDirs(t)

	for _, f := range []string{"pki/issued/u1.crt", "pki/private/u1.key", "pki/reqs/u1.req"} {
		writePkiFile(t, filepath.Join(dir, f), "x")
	}

	archiveUserPkiFiles("u1", "0A")

	for _, f := range []string{"pki/issued/u1.crt", "pki/private/u1.key", "pki/reqs/u1.req"} {
		if fExist(filepath.Join(dir, f)) {
			t.Errorf("%s should have been moved aside", f)
		}
	}
	for _, f := range []string{"pki/revoked/certs_by_serial/0A.crt", "pki/revoked/private_by_serial/0A.key", "pki/revoked/reqs_by_serial/0A.req"} {
		if !fExist(filepath.Join(dir, f)) {
			t.Errorf("%s should exist after archiving", f)
		}
	}
}

func TestUserDelete_ExpiredUserFreesTheUsername(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	dir := setupPkiTestDirs(t)

	// An expired certificate: easyrsa revoke never ran for it, so its files are
	// still filed under the username.
	writePkiFile(t, *indexTxtPath, "V\t200101000000Z\t\t02\tunknown\t/CN=olduser\n")
	for _, f := range []string{"pki/issued/olduser.crt", "pki/private/olduser.key", "pki/reqs/olduser.req"} {
		writePkiFile(t, filepath.Join(dir, f), "x")
	}

	if msg, err := oAdmin.userDelete("olduser"); err != nil {
		t.Fatalf("deleting an expired user should succeed, got %v (%s)", err, msg)
	}
	if fExist(filepath.Join(dir, "pki/reqs/olduser.req")) {
		t.Error("delete left pki/reqs/olduser.req behind: easyrsa would refuse to ever issue for this name again")
	}
	if !fExist(filepath.Join(dir, "pki/revoked/reqs_by_serial/02.req")) {
		t.Error("the request file should be archived by serial, matching easyrsa revoke's own layout")
	}

	// The point of archiving: the same username can be created again.
	created, msg, err := oAdmin.userCreate("olduser", "")
	if !created {
		t.Fatalf("recreating a deleted user failed: %v (%s)", err, msg)
	}
}

func TestUserCreate_HealsUserStrandedByEarlierDelete(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	dir := setupPkiTestDirs(t)

	// The state a delete used to leave behind: the index entry renamed away, but
	// the certificate files still filed under the username. easyrsa would refuse
	// to ever issue for this name again.
	writePkiFile(t, *indexTxtPath, "V\t200101000000Z\t\t05\tunknown\t/CN=REVOKED-ghost-cafe0123\n")
	for _, f := range []string{"pki/issued/ghost.crt", "pki/private/ghost.key", "pki/reqs/ghost.req"} {
		writePkiFile(t, filepath.Join(dir, f), "stranded")
	}

	created, msg, err := oAdmin.userCreate("ghost", "")
	if !created {
		t.Fatalf("creating a user stranded by an old delete should succeed, got %v (%s)", err, msg)
	}

	// The leftovers moved under the serial recorded when the entry was renamed.
	for _, f := range []string{"pki/revoked/certs_by_serial/05.crt", "pki/revoked/private_by_serial/05.key", "pki/revoked/reqs_by_serial/05.req"} {
		if data := fRead(filepath.Join(dir, f)); strings.TrimSpace(data) != "stranded" {
			t.Errorf("%s should hold the stranded file, got %q", f, data)
		}
	}
	if data := fRead(filepath.Join(dir, "pki/issued/ghost.crt")); strings.TrimSpace(data) != "crt" {
		t.Errorf("pki/issued/ghost.crt should be the newly issued certificate, got %q", data)
	}
	if !strings.Contains(fRead(*indexTxtPath), "/CN=ghost") {
		t.Error("the index should list the recreated user")
	}
}

func TestUserRotate_ReplacesCertificateDespiteExistingFiles(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	dir := setupPkiTestDirs(t)

	// An active certificate holds its files under the username for as long as it
	// lives, so a rotate must move them aside before it can issue the replacement.
	writePkiFile(t, *indexTxtPath, "V\t400101000000Z\t\t01\tunknown\t/CN=vpnuser\n")
	for _, f := range []string{"pki/issued/vpnuser.crt", "pki/private/vpnuser.key", "pki/reqs/vpnuser.req"} {
		writePkiFile(t, filepath.Join(dir, f), "old")
	}

	if msg, err := oAdmin.userRotate("vpnuser", ""); err != nil {
		t.Fatalf("rotate failed: %v (%s)", err, msg)
	}

	index := fRead(*indexTxtPath)
	if !strings.Contains(index, "/CN=vpnuser") {
		t.Error("rotate should leave an entry under the original name")
	}
	if !strings.Contains(index, "/CN=REVOKED-vpnuser-") {
		t.Error("rotate should rename the old entry out of the way")
	}
	if !fExist(filepath.Join(dir, "pki/revoked/reqs_by_serial/01.req")) {
		t.Error("the old request file should be archived by its serial")
	}
	if data := fRead(filepath.Join(dir, "pki/issued/vpnuser.crt")); strings.TrimSpace(data) != "crt" {
		t.Errorf("pki/issued/vpnuser.crt should be the newly issued certificate, got %q", data)
	}
}

func TestUserRotate_RestoresOldFilesWhenCreateFails(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	dir := setupPkiTestDirs(t)

	// The stub easyrsa refuses to issue for this specific name, standing in for
	// any build-client-full failure mid-rotate.
	writePkiFile(t, *indexTxtPath, "V\t400101000000Z\t\t01\tunknown\t/CN=failuser\n")
	for _, f := range []string{"pki/issued/failuser.crt", "pki/private/failuser.key", "pki/reqs/failuser.req"} {
		writePkiFile(t, filepath.Join(dir, f), "old")
	}

	_, err := oAdmin.userRotate("failuser", "")
	if err == nil {
		t.Fatal("rotate should fail when the replacement certificate cannot be issued")
	}

	if !strings.Contains(fRead(*indexTxtPath), "/CN=failuser") {
		t.Error("a failed rotate should restore the original index entry")
	}
	for _, f := range []string{"pki/issued/failuser.crt", "pki/private/failuser.key", "pki/reqs/failuser.req"} {
		if data := fRead(filepath.Join(dir, f)); strings.TrimSpace(data) != "old" {
			t.Errorf("%s should hold the original certificate files after a failed rotate, got %q", f, data)
		}
	}
}

// =============================================================================
// Accessibility Tests
// =============================================================================

// readStylesheet returns static/style.css, which is served from the embedded FS.
func readStylesheet(t *testing.T) string {
	t.Helper()
	css, err := os.ReadFile(filepath.Join("static", "style.css"))
	if err != nil {
		t.Fatalf("reading stylesheet: %v", err)
	}
	return string(css)
}

func TestStylesheet_NoInvertingRampOnAlwaysDarkSurfaces(t *testing.T) {
	css := readStylesheet(t)

	// --gray-900 flips to near-white in the dark theme. The bulk bar and the config
	// block are dark in both themes, so using the ramp there rendered white text on a
	// near-white surface (1.05:1 and 1.18:1). They must use --surface-inverse.
	for _, block := range []string{".bulk-actions-bar {", ".config-display {"} {
		start := strings.Index(css, block)
		if start < 0 {
			t.Fatalf("could not find %s in the stylesheet", block)
		}
		body := css[start : start+strings.Index(css[start:], "}")]
		if strings.Contains(body, "var(--gray-900)") {
			t.Errorf("%s uses var(--gray-900), which inverts in dark mode", block)
		}
		if !strings.Contains(body, "var(--surface-inverse)") {
			t.Errorf("%s should paint itself with var(--surface-inverse)", block)
		}
	}
}

func TestStylesheet_StatusColoursUseTextSafeTones(t *testing.T) {
	css := readStylesheet(t)

	// Every one of these put a mid tone on its own 100-level tint, measuring between
	// 1.93:1 and 3.08:1 against a 4.5:1 requirement.
	forbidden := []string{
		".status-active { background: var(--success-light); color: var(--success); }",
		".status-expired { background: var(--warning-light); color: var(--warning); }",
		".btn-action-info { background: var(--info-light); color: var(--info); }",
		".btn-action-danger { background: var(--danger-light); color: var(--danger); }",
		".alert-warning { background: var(--warning-light); color: var(--warning); }",
	}
	for _, rule := range forbidden {
		if strings.Contains(css, rule) {
			t.Errorf("rule fails WCAG AA and should use a -deep tone: %s", rule)
		}
	}

	for _, token := range []string{"--success-deep", "--warning-deep", "--danger-deep", "--info-deep"} {
		if !strings.Contains(css, token+":") {
			t.Errorf("expected %s to be defined", token)
		}
	}
}

func TestStylesheet_BootstrapColourUtilitiesOverridden(t *testing.T) {
	css := readStylesheet(t)

	// Bootstrap's .text-warning (#ffc107) is used for the expiry warnings and measured
	// 1.46:1 on a warning stat card, making the most urgent copy the least readable.
	for _, rule := range []string{".text-warning {", ".text-danger {"} {
		if !strings.Contains(css, rule) {
			t.Errorf("expected %s to be overridden with a text-safe tone", rule)
		}
	}
}

func TestStylesheet_HasFocusAndReducedMotion(t *testing.T) {
	css := readStylesheet(t)

	if !strings.Contains(css, ":focus-visible") {
		t.Error("stylesheet defines no focus styling at all")
	}
	if !strings.Contains(css, "prefers-reduced-motion") {
		t.Error("stylesheet does not honour prefers-reduced-motion")
	}
	// The bar used to animate `bottom`, forcing layout every frame, and bottom:-80px
	// peeked back into view once the buttons wrapped.
	if strings.Contains(css, "bottom: -80px") {
		t.Error("bulk bar should be hidden by a transform, not a negative offset")
	}
	if strings.Contains(css, "transition: bottom") {
		t.Error("bulk bar should not transition a layout property")
	}
}

func TestStylesheet_NoDeadRules(t *testing.T) {
	css := readStylesheet(t)

	// These class names appear in no template. .empty-state-inline, which templates do
	// use, had no rules at all.
	for _, dead := range []string{".action-btn {", ".skeleton {", ".empty-state-icon {"} {
		if strings.Contains(css, dead) {
			t.Errorf("%s is not used by any template", dead)
		}
	}
	if !strings.Contains(css, ".empty-state-inline {") {
		t.Error(".empty-state-inline is rendered by user_rows.html and needs styling")
	}
}

func TestIndexPage_InteractiveElementsAreAccessible(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.role = "master"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)
	body := w.Body.String()

	// Select-all belonged in the column header it controls, which was an empty <th>.
	if !strings.Contains(body, `aria-label="Select all listed users"`) {
		t.Error("select-all checkbox needs an accessible name")
	}
	if strings.Contains(body, `<th scope="col" class="col-checkbox"></th>`) {
		t.Error("the checkbox column header should hold the select-all control")
	}

	// htmx row swaps were silent for assistive tech.
	if !strings.Contains(body, `aria-live="polite"`) {
		t.Error("row count should be a live region so list changes are announced")
	}
}

func TestModals_HaveDialogSemantics(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	modals := map[string]map[string]interface{}{
		"modal_create":   {"Modules": []string{"core"}},
		"modal_delete":   {"Username": "john"},
		"modal_rotate":   {"Username": "john", "Modules": []string{"core"}},
		"modal_password": {"Username": "john"},
	}

	for name, data := range modals {
		w := httptest.NewRecorder()
		if err := oAdmin.htmlTemplates.ExecuteTemplate(w, name, data); err != nil {
			t.Fatalf("%s: template execution failed: %v", name, err)
		}
		body := w.Body.String()

		for _, attr := range []string{`role="dialog"`, `aria-modal="true"`, `aria-labelledby="modal-title"`, `id="modal-title"`} {
			if !strings.Contains(body, attr) {
				t.Errorf("%s is missing %s, so it is not announced as a dialog", name, attr)
			}
		}
		if !strings.Contains(body, `aria-label="Close"`) {
			t.Errorf("%s close button is icon-only and needs an accessible name", name)
		}
	}
}

func TestUserRows_CheckboxHasHitArea(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users":      []OpenvpnClient{{Identity: "alice", AccountStatus: "Active"}},
		"ServerRole": "master",
		"Modules":    []string{"core"},
		"Filtered":   false,
	})
	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	// A bare 16px checkbox is the smallest target in the UI and the whole bulk flow
	// depends on it; the label supplies a 36px hit area.
	if !strings.Contains(w.Body.String(), `<label class="row-select">`) {
		t.Error("row checkbox should sit in a .row-select label for a usable hit area")
	}
}

func TestFiltersActive(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	plain := httptest.NewRequest(http.MethodGet, "/users", nil)
	if oAdmin.filtersActive(plain) {
		t.Error("a bare request has no filters active")
	}

	searched := httptest.NewRequest(http.MethodGet, "/users?search=ali", nil)
	if !oAdmin.filtersActive(searched) {
		t.Error("a search term counts as an active filter")
	}

	narrowed := httptest.NewRequest(http.MethodGet, "/users", nil)
	narrowed.AddCookie(&http.Cookie{Name: "statusFilter", Value: "revoked"})
	if !oAdmin.filtersActive(narrowed) {
		t.Error("a status filter counts as an active filter")
	}

	everyone := httptest.NewRequest(http.MethodGet, "/users", nil)
	everyone.AddCookie(&http.Cookie{Name: "statusFilter", Value: "all"})
	if oAdmin.filtersActive(everyone) {
		t.Error("statusFilter=all is not an active filter")
	}

	// Sorting reorders rows but hides none, so it must not flip the empty state
	// into claiming a filter is the reason the table is empty.
	sorted := httptest.NewRequest(http.MethodGet, "/users?sort=created&dir=desc", nil)
	if oAdmin.filtersActive(sorted) {
		t.Error("a sort is not a filter")
	}
}

func TestHxToast_AlsoSignalsRefresh(t *testing.T) {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(hxToast("User alice revoked", "warn")), &payload); err != nil {
		t.Fatalf("HX-Trigger payload is not valid JSON: %v", err)
	}

	toast, ok := payload["showToast"].(map[string]interface{})
	if !ok {
		t.Fatal("payload should still carry the toast")
	}
	if toast["message"] != "User alice revoked" || toast["type"] != "warn" {
		t.Errorf("unexpected toast contents: %v", toast)
	}

	// The summary cards are bound to `refreshStats from:body`. With the 15s poll removed
	// nothing else fires it, so a mutation that omits this leaves stale counts on screen.
	// It must NOT be the row list's `refresh`: that event bubbles up through the tbody
	// and fired a duplicate GET /users racing the mutation's own row response.
	if payload["refreshStats"] != true {
		t.Error("a successful mutation must also trigger refreshStats so the stat cards update")
	}
	if _, present := payload["refresh"]; present {
		t.Error("hxToast must not fire `refresh`: it bubbles through the tbody and double-fetches the rows")
	}
}

// =============================================================================
// Management interface Tests
// =============================================================================

func TestMgmtGetActiveClients_SkipsUnreachableServerAndKeepsGoing(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// A listener that answers like the OpenVPN management interface, counting how often
	// it actually gets dialled.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var mu sync.Mutex
	dials := 0

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			dials++
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("INFO: OpenVPN Management Interface, type 'help' for more info\r\n"))
				buf := make([]byte, 256)
				_, _ = c.Read(buf) // the "status 1" request
				_, _ = c.Write([]byte("TITLE\tOpenVPN\r\nEND\r\n"))
			}(conn)
		}
	}()

	// One reachable server, one with nothing listening. mgmtInterfaces is a map and Go
	// randomises iteration order, so the old `break` on a dial failure skipped the
	// reachable server roughly half the time - nondeterministically zeroing out its
	// clients. Repeat enough that ordering cannot hide it.
	oAdmin.mgmtInterfaces = map[string]string{
		"down": "127.0.0.1:1",
		"up":   listener.Addr().String(),
	}

	const rounds = 20
	for i := 0; i < rounds; i++ {
		done := make(chan struct{})
		go func() {
			oAdmin.mgmtGetActiveClients()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("mgmtGetActiveClients did not return: an unreachable server must not stall it")
		}
	}

	mu.Lock()
	got := dials
	mu.Unlock()
	if got != rounds {
		t.Errorf("reachable server was dialled %d/%d times; an unreachable peer must not "+
			"abort the loop", got, rounds)
	}
}

func TestMgmtRead_DoesNotBlockOnASilentSocket(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	// Accepts the connection and then says nothing recognisable. mgmtRead only stops on a
	// sentinel ("END", "SUCCESS:", ...), so without a read deadline it blocks for ever -
	// and it is now called while serving a mutation.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Hold the connection open without ever sending a sentinel.
		time.Sleep(30 * time.Second)
		conn.Close()
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), mgmtDialTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	done := make(chan string, 1)
	go func() { done <- oAdmin.mgmtRead(conn) }()

	select {
	case <-done:
	case <-time.After(mgmtReadTimeout + 5*time.Second):
		t.Fatal("mgmtRead blocked past its read deadline on a silent socket")
	}
}

func TestRenderUserRows_RefreshesConnectionData(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	dir := t.TempDir()
	origIndex, origBackend := *indexTxtPath, *storageBackend
	*indexTxtPath, *storageBackend = filepath.Join(dir, "index.txt"), "filesystem"
	defer func() { *indexTxtPath, *storageBackend = origIndex, origBackend }()

	if err := os.WriteFile(*indexTxtPath, []byte("V\t400101000000Z\t\t01\tunknown\t/CN=alice\n"), 0o600); err != nil {
		t.Fatalf("writing index.txt: %v", err)
	}

	// Stale connection data: alice looks online, but nothing is actually connected.
	oAdmin.activeClients = []clientStatus{{CommonName: "alice"}}
	// No reachable management interface, so a refresh must clear it rather than keep it.
	oAdmin.mgmtInterfaces = map[string]string{"main": "127.0.0.1:1"}

	req := httptest.NewRequest(http.MethodPost, "/users/alice/revoke", nil)
	w := httptest.NewRecorder()
	oAdmin.renderUserRows(w, req)

	// Certificate data comes from disk; connection data must be re-read at the same time,
	// or the row shows a fresh status next to a stale Online badge.
	if len(oAdmin.activeClients) != 0 {
		t.Errorf("expected connection data to be refreshed, still holding %v", oAdmin.activeClients)
	}
	if strings.Contains(w.Body.String(), "Online") {
		t.Error("row still shows the Online badge from the stale connection cache")
	}
}

// =============================================================================
// Audit regression tests (2026-09-02): unrevoke restore, slave sync hardening,
// sync-time race, server-cert gauge, config panics, mgmt startup sweep.
// =============================================================================

func TestUserUnrevoke_RestoresBothCertificateCopies(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	dir := setupPkiTestDirs(t)

	writePkiFile(t, *indexTxtPath, "R\t400101000000Z\t250101000000Z\t07\tunknown\t/CN=user1\n")
	writePkiFile(t, filepath.Join(dir, "pki/revoked/certs_by_serial/07.crt"), "crt")
	writePkiFile(t, filepath.Join(dir, "pki/revoked/private_by_serial/07.key"), "key")
	writePkiFile(t, filepath.Join(dir, "pki/revoked/reqs_by_serial/07.req"), "req")
	for _, d := range []string{"pki/issued", "pki/certs_by_serial", "pki/private", "pki/reqs"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	if msg, err := oAdmin.userUnrevoke("user1"); err != nil {
		t.Fatalf("unrevoke failed: %v (%s)", err, msg)
	}

	// revoke leaves one archived certificate; the restore has to put it back in
	// both places easyrsa keeps it. Moving it twice restored only the first.
	for path, want := range map[string]string{
		"pki/issued/user1.crt":       "crt",
		"pki/certs_by_serial/07.pem": "crt",
		"pki/private/user1.key":      "key",
		"pki/reqs/user1.req":         "req",
	} {
		if got := fRead(filepath.Join(dir, path)); got != want {
			t.Errorf("%s: got %q, want %q", path, got, want)
		}
	}
	if fExist(filepath.Join(dir, "pki/revoked/certs_by_serial/07.crt")) {
		t.Error("the archived certificate should be consumed by the restore")
	}
	if !strings.Contains(fRead(*indexTxtPath), "V\t400101000000Z\t\t07\tunknown\t/CN=user1") {
		t.Error("the index entry should be valid again")
	}
}

func TestFDownload_RejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := fDownload(path, srv.URL, false); err == nil {
		t.Fatal("a 403 must be an error, not a successful download of the error page")
	}
	if fExist(path) {
		t.Error("no file should be written for an error response")
	}
}

// writeTarGz builds a small tar.gz of regular-file entries at path.
func writeTarGz(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestExtractFromArchive_UnpacksRegularFiles(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "ok.tar.gz")
	writeTarGz(t, archive, map[string]string{"sub/file.txt": "hello"})

	target := filepath.Join(dir, "out")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := extractFromArchive(archive, target); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := fRead(filepath.Join(target, "sub", "file.txt")); got != "hello" {
		t.Errorf("extracted file holds %q, want %q", got, "hello")
	}
}

func TestExtractFromArchive_RejectsEscapingEntryNames(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tar.gz")
	writeTarGz(t, archive, map[string]string{"../escaped.txt": "boom"})

	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := extractFromArchive(archive, target); err == nil {
		t.Fatal("an entry addressing outside the target directory must be rejected")
	}
	if fExist(filepath.Join(dir, "escaped.txt")) {
		t.Error("the escaping entry must not be written")
	}
}

func TestExtractFromArchive_CorruptArchiveIsAnErrorNotFatal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "bad.tar.gz")
	// What a slave used to write to disk after downloading an error page.
	if err := os.WriteFile(archive, []byte(`{"status":"error"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractFromArchive(archive, dir); err == nil {
		t.Fatal("a non-gzip file must produce an error")
	}
}

func TestSyncTimesAccessors_ConcurrentUse(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				oAdmin.markSyncAttempt("2026-01-01 00:00:00", j%2 == 0)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = oAdmin.getSyncTimes()
			}
		}()
	}
	wg.Wait()

	lastTry, lastSuccessful := oAdmin.getSyncTimes()
	if lastTry == "" || lastSuccessful == "" {
		t.Error("sync times should be recorded")
	}
}

func TestUsersList_ServerCertExpireIgnoresRevokedLeftovers(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	setupPkiTestDirs(t)

	// The REVOKED-* rename a delete leaves behind falls into the same branch as
	// the server certificate; it must not overwrite the server-expiry gauge.
	writePkiFile(t, *indexTxtPath,
		"V\t400101000000Z\t\t01\tunknown\t/CN=server\n"+
			"V\t500101000000Z\t\t02\tunknown\t/CN=REVOKED-gone-cafe0123\n")

	oAdmin.usersList()

	want := float64((parseDateToUnix(indexTxtDateLayout, "400101000000Z") - time.Now().Unix()) / 3600 / 24)
	if got := testutil.ToFloat64(ovpnServerCertExpire); got != want {
		t.Errorf("server cert expiry gauge is %v, want %v (the server line, not the leftover)", got, want)
	}
}

func TestRenderClientConfig_SkipsMalformedServerValue(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	setupPkiTestDirs(t)
	writePkiFile(t, *indexTxtPath, "V\t400101000000Z\t\t01\tunknown\t/CN=u1\n")

	orig := *openvpnServer
	*openvpnServer = []string{"hostonly", "1.2.3.4:1194:udp"}
	t.Cleanup(func() { *openvpnServer = orig })

	conf := oAdmin.renderClientConfig("u1") // must not panic on the malformed value
	if !strings.Contains(conf, "1.2.3.4") {
		t.Error("the well-formed server value should still be rendered")
	}
}

func TestGetOvpnCaCertExpireDate_ToleratesMissingOrGarbledCaCert(t *testing.T) {
	dir := setupPkiTestDirs(t)

	_ = getOvpnCaCertExpireDate() // no ca.crt at all: must not panic

	writePkiFile(t, filepath.Join(dir, "pki", "ca.crt"), "not a pem certificate")
	_ = getOvpnCaCertExpireDate() // garbled ca.crt: must not panic
}

func TestMgmtSetTimeFormat_SkipsUnreachableServerAndKeepsGoing(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	origRetries, origSleep := mgmtConnectRetries, mgmtConnectRetrySleep
	mgmtConnectRetries, mgmtConnectRetrySleep = 1, 0
	t.Cleanup(func() { mgmtConnectRetries, mgmtConnectRetrySleep = origRetries, origSleep })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("INFO: OpenVPN Management Interface, type 'help' for more info\r\n"))
				buf := make([]byte, 256)
				_, _ = c.Read(buf) // the "version" request
				_, _ = c.Write([]byte("OpenVPN Version: OpenVPN 2.4.9 x86_64-pc-linux-gnu\r\nManagement Version: 1\r\nEND\r\n"))
			}(conn)
		}
	}()

	// One reachable 2.4 server, one dead address. The old `break` on a dial
	// failure abandoned version detection for a random subset of the map, so
	// the 2.4 time format was only picked up on lucky iteration orders.
	oAdmin.mgmtInterfaces = map[string]string{
		"down": "127.0.0.1:1",
		"up":   listener.Addr().String(),
	}

	for i := 0; i < 20; i++ {
		oAdmin.mgmtStatusTimeFormat = ""
		oAdmin.mgmtSetTimeFormat()
		if oAdmin.mgmtStatusTimeFormat != time.ANSIC {
			t.Fatalf("round %d: the reachable 2.4 server's version was not read (format %q); "+
				"a dead peer must not abort the sweep", i, oAdmin.mgmtStatusTimeFormat)
		}
	}
}

func TestBasePage_VersionsStaticAssets(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	oAdmin.dashboardPageHandler(w, req)

	// The stylesheet is served with a 30-day Cache-Control header, so a deploy
	// only reaches returning browsers if the URL changes with the build.
	if !strings.Contains(w.Body.String(), "/static/style.css?v="+version) {
		t.Error("the stylesheet link should carry the build version for cache busting")
	}
}

// =============================================================================
// Users page: status filter, column sort, creation date
// =============================================================================

// writeTestCert writes a self-signed certificate with the given NotBefore to
// path, standing in for what easyrsa issues.
func writeTestCert(t *testing.T, path string, notBefore time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode certificate: %v", err)
	}
	writePkiFile(t, path, buf.String())
}

func TestUsersList_CreationDateFromCertificate(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	dir := setupPkiTestDirs(t)

	writeTestCert(t, filepath.Join(dir, "pki/issued/alice.crt"), time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC))
	// bob's per-name file was moved aside by revoke; only the by-serial archive
	// still knows when his certificate was issued.
	writeTestCert(t, filepath.Join(dir, "pki/revoked/certs_by_serial/0B.crt"), time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC))

	writePkiFile(t, *indexTxtPath,
		"V\t400101000000Z\t\t0A\tunknown\t/CN=alice\n"+
			"R\t400101000000Z\t250801000000Z\t0B\tunknown\t/CN=bob\n")

	byName := map[string]OpenvpnClient{}
	for _, u := range oAdmin.usersList() {
		byName[u.Identity] = u
	}

	if got := byName["alice"].CreationDate; got != "2026-03-14 09:26:53" {
		t.Errorf("alice creation date %q, want the certificate's NotBefore", got)
	}
	if got := byName["bob"].CreationDate; got != "2025-07-01 12:00:00" {
		t.Errorf("bob creation date %q, want it read from the revoked by-serial archive", got)
	}
}

func TestVisibleUsers_DefaultSortIsUsernameAZ(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	// Index order is issue order, which means nothing to an operator.
	oAdmin.clients = []OpenvpnClient{
		{Identity: "charlie", AccountStatus: "Active"},
		{Identity: "alice", AccountStatus: "Active"},
		{Identity: "Bravo", AccountStatus: "Active"},
	}

	var got []string
	for _, u := range oAdmin.visibleUsers(httptest.NewRequest(http.MethodGet, "/users", nil)) {
		got = append(got, u.Identity)
	}
	if strings.Join(got, ",") != "alice,Bravo,charlie" {
		t.Errorf("default order should be username A-Z case-insensitively, got %v", got)
	}
}

func TestVisibleUsers_SortByColumnAndDirection(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "old", AccountStatus: "Revoked", createdUnix: 100, expirationUnix: 300},
		{Identity: "new", AccountStatus: "Active", createdUnix: 300, expirationUnix: 100},
		{Identity: "mid", AccountStatus: "Expired", createdUnix: 200, expirationUnix: 200},
	}

	cases := []struct {
		query string
		want  string
	}{
		{"sort=created", "old,mid,new"},
		{"sort=created&dir=desc", "new,mid,old"},
		{"sort=expires", "new,mid,old"},
		{"sort=status", "new,mid,old"}, // Active < Expired < Revoked
		{"sort=name&dir=desc", "old,new,mid"},
	}
	for _, tc := range cases {
		var got []string
		for _, u := range oAdmin.visibleUsers(httptest.NewRequest(http.MethodGet, "/users?"+tc.query, nil)) {
			got = append(got, u.Identity)
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%s: expected %s, got %v", tc.query, tc.want, got)
		}
	}

	// The toolbar persists the sort in cookies; a request without parameters
	// (a mutation re-render) must honour them.
	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "sortKey", Value: "created"})
	req.AddCookie(&http.Cookie{Name: "sortDir", Value: "desc"})
	var got []string
	for _, u := range oAdmin.visibleUsers(req) {
		got = append(got, u.Identity)
	}
	if strings.Join(got, ",") != "new,mid,old" {
		t.Errorf("cookie sort: expected new,mid,old, got %v", got)
	}
}

func TestVisibleUsers_SearchKeepsRelevanceUnlessSorted(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "az", AccountStatus: "Active"},
		{Identity: "za", AccountStatus: "Active"},
	}

	// "z" prefixes "za", so relevance puts it first even though "az" sorts first.
	var ranked []string
	for _, u := range oAdmin.visibleUsers(httptest.NewRequest(http.MethodGet, "/users?search=z", nil)) {
		ranked = append(ranked, u.Identity)
	}
	if strings.Join(ranked, ",") != "za,az" {
		t.Errorf("a search without an explicit sort keeps relevance order, got %v", ranked)
	}

	var sorted []string
	for _, u := range oAdmin.visibleUsers(httptest.NewRequest(http.MethodGet, "/users?search=z&sort=name", nil)) {
		sorted = append(sorted, u.Identity)
	}
	if strings.Join(sorted, ",") != "az,za" {
		t.Errorf("an explicit sort overrides the search ranking, got %v", sorted)
	}
}

func TestVisibleUsers_DoesNotReorderTheSharedSlice(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "charlie", AccountStatus: "Active"},
		{Identity: "alice", AccountStatus: "Active"},
	}

	oAdmin.visibleUsers(httptest.NewRequest(http.MethodGet, "/users", nil))

	// The slice handed out under RLock is shared state: sorting must work on a
	// copy, never reorder it in place under a concurrent reader.
	if got := oAdmin.getClients()[0].Identity; got != "charlie" {
		t.Errorf("visibleUsers reordered the shared client slice (first is now %q)", got)
	}
}

func TestUsersPage_StatusFilterAndSortableHeaders(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	w := httptest.NewRecorder()
	oAdmin.indexPageHandler(w, req)
	body := w.Body.String()

	if !strings.Contains(body, `id="status-filter"`) {
		t.Error("the toolbar should carry the status filter control")
	}
	for _, status := range []string{"all", "active", "revoked", "expired"} {
		if !strings.Contains(body, `data-status="`+status+`"`) {
			t.Errorf("the status filter should offer %q", status)
		}
	}
	for _, key := range []string{"name", "status", "created", "expires"} {
		if !strings.Contains(body, `data-sort-key="`+key+`"`) {
			t.Errorf("the %q column should be sortable", key)
		}
	}
	if !strings.Contains(body, "Created") {
		t.Error("the table should show the Created column")
	}
	// Default view: sorted by username ascending, announced via aria-sort.
	if !strings.Contains(body, `aria-sort="ascending"`) {
		t.Error("the default sort column should announce aria-sort=ascending")
	}
	if strings.Contains(body, "Hide Revoked") {
		t.Error("the Hide Revoked toggle is replaced by the status filter")
	}
}
