// API Base URL
const API_URL = '';

// Current location
let currentLocation = 'hktmb';
let currentUser = null;

// ============ Initialize ============
document.addEventListener('DOMContentLoaded', () => {
    // Load user info
    initUserInfo();

    // Load data
    loadCases();
    loadStats();
    loadFilters();
    loadResolverUsers();

    // Setup import file listener
    document.getElementById('importFile').addEventListener('change', importExcel);

    // Set default date to today for new cases
    document.getElementById('caseDate').valueAsDate = new Date();
});

// ============ User Info & Auth ============
function initUserInfo() {
    const userData = localStorage.getItem('user');
    if (userData) {
        currentUser = JSON.parse(userData);

        // Update UI
        document.getElementById('userName').textContent = currentUser.full_name || currentUser.eid;

        const roleEl = document.getElementById('userRole');
        roleEl.textContent = currentUser.role;
        if (currentUser.role === 'admin' || currentUser.role === 'superadmin') {
            roleEl.classList.add(currentUser.role);
            document.getElementById('adminLink').style.display = 'inline-block';
            // Show Delete All button only for admins
            const deleteAllBtn = document.getElementById('deleteAllBtn');
            if (deleteAllBtn) deleteAllBtn.style.display = 'inline-block';
            // Show Import button only for admins
            const importBtn = document.getElementById('importBtn');
            if (importBtn) importBtn.style.display = 'inline-block';
        } else {
            // Hide Delete All button for non-admins
            const deleteAllBtn = document.getElementById('deleteAllBtn');
            if (deleteAllBtn) deleteAllBtn.style.display = 'none';
            // Hide Import button for non-admins
            const importBtn = document.getElementById('importBtn');
            if (importBtn) importBtn.style.display = 'none';
        }

        // Load location selector
        loadLocationSelector();
    }
}

// Get auth headers for API calls
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
}

function loadLocationSelector() {
    const selector = document.getElementById('locationSelector');
    const locationName = document.getElementById('locationName');

    if (currentUser && currentUser.locations) {
        selector.innerHTML = '';
        currentUser.locations.forEach(loc => {
            const option = document.createElement('option');
            option.value = loc.code;
            option.textContent = loc.code.toUpperCase();
            selector.appendChild(option);
        });

        // Set first location as default
        if (currentUser.locations.length > 0) {
            currentLocation = currentUser.locations[0].code;
            selector.value = currentLocation;
            locationName.textContent = currentUser.locations[0].name;
        }
    }
}

function changeLocation() {
    const selector = document.getElementById('locationSelector');
    currentLocation = selector.value;

    // Update location name display
    if (currentUser && currentUser.locations) {
        const loc = currentUser.locations.find(l => l.code === currentLocation);
        if (loc) {
            document.getElementById('locationName').textContent = loc.name;
        }
    }

    // Reload data for new location
    loadCases();
    loadStats();
    loadResolverUsers();
}

// ============ Load Resolver Users ============
async function loadResolverUsers() {
    try {
        const container = document.getElementById('resolverChips');
        // Skip if resolver chips container doesn't exist (removed from UI)
        if (!container) return;

        const response = await fetch(`${API_URL}/api/users/by-location?location=${currentLocation}`);
        const result = await response.json();

        if (result.success && result.data.length > 0) {
            // Filter out superadmin users
            const visibleUsers = result.data.filter(user => user.role !== 'superadmin');

            if (visibleUsers.length > 0) {
                container.innerHTML = visibleUsers.map(user => `
                    <label class="chip-option">
                        <input type="checkbox" name="resolver" value="${user.eid}">
                        <span class="chip">${user.eid}</span>
                    </label>
                `).join('');
            } else {
                container.innerHTML = '<span class="loading-text">No users found</span>';
            }
        } else {
            container.innerHTML = '<span class="loading-text">No users found</span>';
        }
    } catch (error) {
        console.error('Failed to load resolver users:', error);
        const container = document.getElementById('resolverChips');
        if (container) container.innerHTML = '<span class="loading-text">Failed to load users</span>';
    }
}

async function logout() {
    try {
        await fetch(`${API_URL}/api/auth/logout`, { method: 'POST' });
    } catch (e) {
        // Ignore errors
    }

    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
}

// ============ Load Cases ============
async function loadCases(showAll = false) {
    const tbody = document.getElementById('caseTableBody');
    tbody.innerHTML = '<tr><td colspan="11" class="loading">Loading...</td></tr>';

    try {
        const params = new URLSearchParams();
        params.append('location', currentLocation);

        const status = document.getElementById('filterStatus').value;
        const department = document.getElementById('filterDepartment').value;
        const issues = document.getElementById('filterIssues').value;
        const fromDate = document.getElementById('filterFromDate').value;
        const toDate = document.getElementById('filterToDate').value;
        const search = document.getElementById('filterSearch').value;

        if (status) params.append('status', status);
        if (department) params.append('department', department);
        if (issues) params.append('issues', issues);
        if (fromDate) params.append('from_date', fromDate);
        if (toDate) params.append('to_date', toDate);
        if (search) params.append('search', search);

        // Limit to 10 by default, unless showAll is true or filters are active
        const hasFilters = status || department || issues || fromDate || toDate || search;
        if (!showAll && !hasFilters) {
            params.append('limit', '10');
        }

        const response = await fetch(`${API_URL}/api/cases?${params}`);
        const result = await response.json();

        if (result.success) {
            renderCases(result.data);

            // Show/hide See All button
            const seeAllContainer = document.getElementById('seeAllContainer');
            const totalCount = document.getElementById('totalCasesCount');

            if (!showAll && !hasFilters && result.total > result.data.length) {
                seeAllContainer.style.display = 'block';
                totalCount.textContent = result.total;
            } else {
                seeAllContainer.style.display = 'none';
            }

            // Update stats to reflect current filters
            loadStats();
        } else {
            showToast(result.error, 'error');
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="11" class="empty">Error loading data</td></tr>';
        showToast('Failed to load cases', 'error');
    }
}

// ============ Load All Cases ============
function loadAllCases() {
    loadCases(true);
}

// ============ Render Cases Table ============
function renderCases(cases) {
    const tbody = document.getElementById('caseTableBody');

    if (cases.length === 0) {
        tbody.innerHTML = '<tr><td colspan="11" class="empty">No cases found</td></tr>';
        return;
    }

    tbody.innerHTML = cases.map(c => `
        <tr>
            <td><strong>${escapeHtml(c.case_no || '-')}</strong></td>
            <td>${formatDate(c.case_date)}</td>
            <td><span class="issue-badge">${escapeHtml(c.issues || '-')}</span></td>
            <td title="${escapeHtml(c.description || '')}">${escapeHtml(truncate(c.description, 30))}</td>
            <td title="${escapeHtml(c.step_to_resolve || '')}">${escapeHtml(truncate(c.step_to_resolve, 30))}</td>
            <td>${escapeHtml(c.opened_by || '-')}</td>
            <td><span class="dept-badge">${escapeHtml(c.department || '-')}</span></td>
            <td><span class="status-badge status-${getStatusClass(c.status)}">${c.status || '-'}</span></td>
            <td>${escapeHtml(c.resolved_by || '-')}</td>
            <td>${escapeHtml(c.remark || '-')}</td>
            <td class="action-btns">
                <button class="btn btn-small btn-secondary" onclick="editCase(${c.id})">Edit</button>
                <button class="btn btn-small btn-danger" onclick="deleteCase(${c.id})">Del</button>
            </td>
        </tr>
    `).join('');
}

// ============ Load Stats ============
async function loadStats() {
    try {
        // Get current filter values
        const params = new URLSearchParams();
        params.append('location', currentLocation);

        const department = document.getElementById('filterDepartment').value;
        const issues = document.getElementById('filterIssues').value;
        const fromDate = document.getElementById('filterFromDate').value;
        const toDate = document.getElementById('filterToDate').value;
        const search = document.getElementById('filterSearch').value;

        if (department) params.append('department', department);
        if (issues) params.append('issues', issues);
        if (fromDate) params.append('from_date', fromDate);
        if (toDate) params.append('to_date', toDate);
        if (search) params.append('search', search);

        const response = await fetch(`${API_URL}/api/stats?${params}`);
        const result = await response.json();

        if (result.success) {
            document.getElementById('statTotal').textContent = result.data.total;
            document.getElementById('statProgress').textContent = result.data.in_progress;
            document.getElementById('statCompleted').textContent = result.data.completed;
            document.getElementById('statMonth').textContent = result.data.this_month;
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// ============ Load Filters ============
async function loadFilters() {
    try {
        // Load departments
        const deptResponse = await fetch(`${API_URL}/api/departments?location=${currentLocation}`);
        const deptResult = await deptResponse.json();
        if (deptResult.success) {
            const deptSelect = document.getElementById('filterDepartment');
            deptResult.data.forEach(dept => {
                const option = document.createElement('option');
                option.value = dept;
                option.textContent = dept;
                deptSelect.appendChild(option);
            });
        }

        // Load issues
        const issuesResponse = await fetch(`${API_URL}/api/issues?location=${currentLocation}`);
        const issuesResult = await issuesResponse.json();
        if (issuesResult.success) {
            const issuesSelect = document.getElementById('filterIssues');
            issuesResult.data.forEach(issue => {
                const option = document.createElement('option');
                option.value = issue;
                option.textContent = issue;
                issuesSelect.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Failed to load filters:', error);
    }
}

// ============ Modal Functions ============
function openModal(caseData = null) {
    const modal = document.getElementById('caseModal');
    const title = document.getElementById('modalTitle');
    const form = document.getElementById('caseForm');

    form.reset();
    document.getElementById('caseDate').valueAsDate = new Date();

    // Reset all resolver checkboxes
    document.querySelectorAll('input[name="resolver"]').forEach(cb => cb.checked = false);

    if (caseData) {
        title.textContent = 'Edit Case';
        document.getElementById('caseId').value = caseData.id;
        document.getElementById('caseNo').value = caseData.case_no || '';
        document.getElementById('caseDate').value = caseData.case_date ? caseData.case_date.split(' ')[0] : '';
        document.getElementById('caseIssues').value = caseData.issues || '';
        document.getElementById('caseDepartment').value = caseData.department || '';
        document.getElementById('caseDescription').value = caseData.description || '';
        document.getElementById('caseStepToResolve').value = caseData.step_to_resolve || '';
        document.getElementById('caseOpenedBy').value = caseData.opened_by || '';
        document.getElementById('caseStatus').value = caseData.status || '';
        document.getElementById('caseRemark').value = caseData.remark || '';

        // Set resolver checkboxes based on saved value (comma-separated)
        if (caseData.resolved_by) {
            const resolvers = caseData.resolved_by.split(',').map(r => r.trim());
            document.querySelectorAll('input[name="resolver"]').forEach(cb => {
                if (resolvers.includes(cb.value)) {
                    cb.checked = true;
                }
            });
        }
    } else {
        title.textContent = 'Add New Case';
        document.getElementById('caseId').value = '';
        // Auto-set opened_by from logged-in user
        if (currentUser) {
            document.getElementById('caseOpenedBy').value = currentUser.position || currentUser.eid;
        }
        // Auto-set case_no (will be calculated on save if empty)
        document.getElementById('caseNo').value = '';
    }

    modal.classList.add('active');
}

function closeModal() {
    document.getElementById('caseModal').classList.remove('active');
    document.getElementById('autoNo').checked = false;
    document.getElementById('caseNo').readOnly = false;
}

// ============ Toggle Auto No ============
async function toggleAutoNo() {
    const autoCheckbox = document.getElementById('autoNo');
    const caseNoInput = document.getElementById('caseNo');

    if (autoCheckbox.checked) {
        try {
            // Fetch max case number from API
            const response = await fetch(`${API_URL}/api/cases/max-no?location=${currentLocation}`);
            const result = await response.json();

            if (result.success) {
                // Ensure proper number addition (not string concatenation)
                const maxNo = parseInt(result.data.max_no, 10) || 0;
                const nextNo = maxNo + 1;
                caseNoInput.value = nextNo;
                caseNoInput.readOnly = true;
            }
        } catch (error) {
            console.error('Failed to get max case number:', error);
            autoCheckbox.checked = false;
        }
    } else {
        caseNoInput.readOnly = false;
        caseNoInput.value = '';
        caseNoInput.focus();
    }
}

// ============ Save Case ============
async function saveCase(event) {
    event.preventDefault();

    // Get selected resolvers from checkboxes
    const selectedResolvers = Array.from(document.querySelectorAll('input[name="resolver"]:checked'))
        .map(cb => cb.value);
    const resolvedBy = selectedResolvers.join(', ');

    const caseId = document.getElementById('caseId').value;
    const data = {
        case_no: document.getElementById('caseNo').value,
        case_date: document.getElementById('caseDate').value,
        issues: document.getElementById('caseIssues').value,
        department: document.getElementById('caseDepartment').value,
        description: document.getElementById('caseDescription').value,
        step_to_resolve: document.getElementById('caseStepToResolve').value,
        opened_by: document.getElementById('caseOpenedBy').value,
        status: document.getElementById('caseStatus').value,
        resolved_by: resolvedBy,
        remark: document.getElementById('caseRemark').value,
        location: currentLocation
    };

    try {
        const url = caseId ? `${API_URL}/api/cases/${caseId}` : `${API_URL}/api/cases`;
        const method = caseId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message, 'success');
            closeModal();
            loadCases();
            loadStats();
        } else {
            showToast(result.error, 'error');
        }
    } catch (error) {
        showToast('Failed to save case', 'error');
    }
}

// ============ Edit Case ============
async function editCase(id) {
    try {
        const response = await fetch(`${API_URL}/api/cases?location=${currentLocation}`);
        const result = await response.json();

        if (result.success) {
            const caseData = result.data.find(c => c.id === id);
            if (caseData) {
                openModal(caseData);
            }
        }
    } catch (error) {
        showToast('Failed to load case', 'error');
    }
}

// ============ Delete Case ============
async function deleteCase(id) {
    if (!confirm('Are you sure you want to delete this case?')) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/api/cases/${id}?location=${currentLocation}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message, 'success');
            loadCases();
            loadStats();
        } else {
            showToast(result.error, 'error');
        }
    } catch (error) {
        showToast('Failed to delete case', 'error');
    }
}

// ============ Export Excel ============
function exportExcel() {
    // Build query params from current filters
    const params = new URLSearchParams();
    params.append('location', currentLocation);

    const status = document.getElementById('filterStatus').value;
    const department = document.getElementById('filterDepartment').value;
    const issues = document.getElementById('filterIssues').value;
    const fromDate = document.getElementById('filterFromDate').value;
    const toDate = document.getElementById('filterToDate').value;
    const search = document.getElementById('filterSearch').value;

    if (status) params.append('status', status);
    if (department) params.append('department', department);
    if (issues) params.append('issues', issues);
    if (fromDate) params.append('from_date', fromDate);
    if (toDate) params.append('to_date', toDate);
    if (search) params.append('search', search);

    window.location.href = `${API_URL}/api/export?${params}`;
}

// ============ Import Excel ============
async function importExcel(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('location', currentLocation);

    try {
        showToast('Importing...', 'success');

        const response = await fetch(`${API_URL}/api/import`, {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message, 'success');
            loadCases();
            loadStats();
            // Reload page to refresh filter dropdowns
            setTimeout(() => location.reload(), 1000);
        } else {
            showToast(result.error, 'error');
        }
    } catch (error) {
        showToast('Failed to import file', 'error');
    }

    event.target.value = '';
}

// ============ Clear Filters ============
function clearFilters() {
    document.getElementById('filterSearch').value = '';
    document.getElementById('filterStatus').value = '';
    document.getElementById('filterDepartment').value = '';
    document.getElementById('filterIssues').value = '';
    document.getElementById('filterFromDate').value = '';
    document.getElementById('filterToDate').value = '';
    loadCases();
}

// ============ Delete All Cases ============
async function deleteAllCases() {
    // First confirmation
    const confirm1 = prompt('⚠️ WARNING: This will delete ALL cases!\n\nType "Yes" to continue:');
    if (confirm1 !== 'Yes') {
        showToast('Delete cancelled', 'error');
        return;
    }

    // Second confirmation
    const confirm2 = prompt('🚨 FINAL WARNING: This action cannot be undone!\n\nType "Yes i want to delete" to confirm:');
    if (confirm2 !== 'Yes i want to delete') {
        showToast('Delete cancelled', 'error');
        return;
    }

    try {
        showToast('Deleting all cases...', 'success');

        const response = await fetch(`${API_URL}/api/cases/all?location=${currentLocation}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            showToast(result.message, 'success');
            loadCases();
            loadStats();
        } else {
            showToast(result.error, 'error');
        }
    } catch (error) {
        showToast('Failed to delete cases', 'error');
    }
}

// ============ Utility Functions ============
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function truncate(text, length) {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    if (isNaN(date)) return dateStr;
    // Format as D-MMM-YY (e.g., 1-Dec-25)
    const day = date.getDate();
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[date.getMonth()];
    const year = String(date.getFullYear()).slice(-2);
    return `${day}-${month}-${year}`;
}

function getStatusClass(status) {
    if (!status) return 'pending';
    const s = status.toLowerCase();
    if (s === 'in progress') return 'progress';
    if (s === 'completed') return 'completed';
    return 'pending';
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast show ${type}`;

    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}
