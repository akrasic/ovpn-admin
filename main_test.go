package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestIndexPageHandler_HideRevokedCookie(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "hideRevoked", Value: "true"})
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	// When hideRevoked is true, button should say "Show Revoked"
	if !strings.Contains(body, "Show Revoked") {
		t.Error("When hideRevoked=true, button should say 'Show Revoked'")
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
	if !strings.Contains(body, "Total Users") {
		t.Error("Response should contain 'Total Users' stat")
	}
	if !strings.Contains(body, "Active Connections") {
		t.Error("Response should contain 'Active Connections' stat")
	}
	if !strings.Contains(body, "Revoked") {
		t.Error("Response should contain 'Revoked' stat")
	}
	if !strings.Contains(body, "Expiring Soon") {
		t.Error("Response should contain 'Expiring Soon' stat")
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

	w := httptest.NewRecorder()
	err := oAdmin.htmlTemplates.ExecuteTemplate(w, "user_rows", map[string]interface{}{
		"Users":      []OpenvpnClient{},
		"ServerRole": "master",
		"Modules":    []string{"core"},
	})

	if err != nil {
		t.Fatalf("Template execution failed: %v", err)
	}

	body := w.Body.String()

	if !strings.Contains(body, "No users found") {
		t.Error("Empty user list should show 'No users found' message")
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
		"brand-icon",
		"stats-grid",
		"stat-card",
		"stat-icon",
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

	// Verify some key icons are present
	icons := []string{
		"bi-shield-lock-fill", // Header icon
		"bi-people-fill",      // Total users stat
		"bi-wifi",             // Active connections stat
		"bi-slash-circle",     // Revoked stat
		"bi-clock-history",    // Expiring soon stat
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
	if !strings.Contains(body, "Total Users") {
		t.Error("Stats response should contain 'Total Users'")
	}
	if !strings.Contains(body, "Active Connections") {
		t.Error("Stats response should contain 'Active Connections'")
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

func TestUserListHandler_HideRevoked(t *testing.T) {
	oAdmin := newTestOvpnAdmin()
	oAdmin.clients = []OpenvpnClient{
		{Identity: "activeuser", AccountStatus: "Active", Connections: 1, ExpirationDate: "2099-12-31 23:59:59"},
		{Identity: "revokeduser", AccountStatus: "Revoked", Connections: 0, RevocationDate: "2025-01-01 00:00:00"},
	}

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "hideRevoked", Value: "true"})
	w := httptest.NewRecorder()

	oAdmin.userListHandler(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "activeuser") {
		t.Error("User list should contain activeuser")
	}
	if strings.Contains(body, "revokeduser") {
		t.Error("User list should NOT contain revokeduser when hideRevoked=true")
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
		t.Error("Search for 'ali' should NOT return bob")
	}
	if strings.Contains(body, "charlie") {
		t.Error("Search for 'ali' should NOT return charlie")
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

func TestLiveStatusIndicator(t *testing.T) {
	oAdmin := newTestOvpnAdmin()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	oAdmin.indexPageHandler(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "live-indicator") {
		t.Error("Page should contain live status indicator")
	}
	if !strings.Contains(body, "live-dot") {
		t.Error("Page should contain live dot animation element")
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
