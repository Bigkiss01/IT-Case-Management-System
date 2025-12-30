// Report Page JavaScript
const API_URL = '';
let mainChart = null;
let currentChartType = 'bar';
let reportData = null;
let currentLocation = 'hktmb';
let currentUser = null;

// ============ Initialize ============
document.addEventListener('DOMContentLoaded', () => {
    initUserInfo();
});

// ============ Load User Info & Locations ============
function initUserInfo() {
    const userData = localStorage.getItem('user');
    if (userData) {
        currentUser = JSON.parse(userData);
        loadUserLocations();
    } else {
        // No user data, redirect to login
        window.location.href = '/login';
    }
}

function loadUserLocations() {
    const selector = document.getElementById('reportLocation');
    if (!selector || !currentUser || !currentUser.locations) return;

    selector.innerHTML = '';
    currentUser.locations.forEach(loc => {
        const option = document.createElement('option');
        option.value = loc.code;
        option.textContent = loc.name;
        selector.appendChild(option);
    });

    if (currentUser.locations.length > 0) {
        currentLocation = currentUser.locations[0].code;
        selector.value = currentLocation;
    }

    // Now load departments and report
    loadDepartments();
    loadReport();
}

// ============ Load Departments ============
async function loadDepartments() {
    try {
        const response = await fetch(`${API_URL}/api/departments?location=${currentLocation}`);
        const result = await response.json();
        if (result.success) {
            const select = document.getElementById('reportDepartment');
            // Clear existing options except first
            select.innerHTML = '<option value="">All Departments</option>';
            result.data.forEach(dept => {
                const option = document.createElement('option');
                option.value = dept;
                option.textContent = dept;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Failed to load departments:', error);
    }
}

// ============ Load Report ============
async function loadReport() {
    try {
        // Get current location from selector
        const locationSelector = document.getElementById('reportLocation');
        if (locationSelector && locationSelector.value) {
            currentLocation = locationSelector.value;
        }

        // Fallback: if no location, try to get from user data
        if (!currentLocation && currentUser && currentUser.locations && currentUser.locations.length > 0) {
            currentLocation = currentUser.locations[0].code;
        }

        // Final fallback
        if (!currentLocation) {
            currentLocation = 'hktmb';
        }

        const fromDate = document.getElementById('reportFromDate')?.value || '';
        const toDate = document.getElementById('reportToDate')?.value || '';
        const department = document.getElementById('reportDepartment')?.value || '';

        const params = new URLSearchParams();
        params.append('location', currentLocation);
        if (fromDate) params.append('from_date', fromDate);
        if (toDate) params.append('to_date', toDate);
        if (department) params.append('department', department);

        console.log('Loading report with params:', params.toString());

        const response = await fetch(`${API_URL}/api/report?${params}`);
        const result = await response.json();

        console.log('Report API response:', result);

        if (result.success) {
            reportData = result.data;
            updateSummary(reportData.summary);
            updateChart();
            updateTopLists(reportData);
            updateTable();

            // Show message if no data
            if (reportData.summary.total === 0) {
                alert('No data found for the selected date range. Please adjust your filters.');
            }
        } else {
            console.error('Report API error:', result.error);
            alert('Error loading report: ' + result.error);
        }
    } catch (error) {
        console.error('Failed to load report:', error);
        alert('Failed to load report. Please check the console for details.');
    }
}

// ============ Update Summary Cards ============
function updateSummary(summary) {
    document.getElementById('summaryTotal').textContent = summary.total;
    document.getElementById('summaryCompleted').textContent = summary.completed;
    document.getElementById('summaryPending').textContent = summary.in_progress;

    const rate = summary.total > 0 ? Math.round((summary.completed / summary.total) * 100) : 0;
    document.getElementById('summaryRate').textContent = rate + '%';
}

// ============ Chart Functions ============
function updateChartType() {
    updateChart();
    updateTable();
}

function setChartType(type) {
    currentChartType = type;

    // Update toggle buttons
    document.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.type === type) {
            btn.classList.add('active');
        }
    });

    updateChart();
}

function updateChart() {
    if (!reportData) return;

    const view = document.getElementById('reportView').value;
    const ctx = document.getElementById('mainChart').getContext('2d');

    // Destroy existing chart
    if (mainChart) {
        mainChart.destroy();
    }

    let data, title;

    switch (view) {
        case 'issues':
            data = reportData.by_issues;
            title = 'Issues by Type';
            break;
        case 'department':
            data = reportData.by_department;
            title = 'Issues by Department';
            break;
        case 'resolver':
            data = reportData.by_resolver;
            title = 'Issues by Resolver';
            break;
        case 'trend':
            data = reportData.by_date;
            title = 'Daily Trend';
            currentChartType = 'line';
            break;
    }

    document.getElementById('chartTitle').textContent = title;

    const labels = data.map(d => d.name || d.date);
    const values = data.map(d => d.count);

    const colors = generateColors(labels.length);

    const chartConfig = {
        type: currentChartType === 'line' ? 'line' : currentChartType,
        data: {
            labels: labels,
            datasets: [{
                label: 'Cases',
                data: values,
                backgroundColor: currentChartType === 'bar' ? colors[0] : colors,
                borderColor: currentChartType === 'line' ? '#3498db' : colors,
                borderWidth: currentChartType === 'line' ? 3 : 1,
                fill: currentChartType === 'line' ? false : true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: currentChartType !== 'bar' && currentChartType !== 'line'
                }
            },
            scales: currentChartType === 'bar' || currentChartType === 'line' ? {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            } : {}
        }
    };

    mainChart = new Chart(ctx, chartConfig);
}

function generateColors(count) {
    const palette = [
        '#3498db', '#e74c3c', '#27ae60', '#f39c12', '#9b59b6',
        '#1abc9c', '#e67e22', '#2ecc71', '#34495e', '#16a085',
        '#d35400', '#8e44ad', '#2980b9', '#c0392b', '#27ae60'
    ];

    const colors = [];
    for (let i = 0; i < count; i++) {
        colors.push(palette[i % palette.length]);
    }
    return colors;
}

// ============ Update Top Lists ============
function updateTopLists(data) {
    // Top Issues
    const topIssues = document.getElementById('topIssues');
    topIssues.innerHTML = data.by_issues.slice(0, 5).map((item, index) => `
        <div class="ranking-item">
            <span class="rank rank-${index + 1}">${index + 1}</span>
            <span class="name">${escapeHtml(item.name)}</span>
            <span class="count">${item.count}</span>
        </div>
    `).join('') || '<div class="empty">No data</div>';

    // Top Departments
    const topDepts = document.getElementById('topDepartments');
    topDepts.innerHTML = data.by_department.slice(0, 5).map((item, index) => `
        <div class="ranking-item">
            <span class="rank rank-${index + 1}">${index + 1}</span>
            <span class="name">${escapeHtml(item.name)}</span>
            <span class="count">${item.count}</span>
        </div>
    `).join('') || '<div class="empty">No data</div>';

    // Top Resolvers
    const topResolvers = document.getElementById('topResolvers');
    topResolvers.innerHTML = data.by_resolver.slice(0, 5).map((item, index) => `
        <div class="ranking-item">
            <span class="rank rank-${index + 1}">${index + 1}</span>
            <span class="name">${escapeHtml(item.name)}</span>
            <span class="count">${item.count}</span>
        </div>
    `).join('') || '<div class="empty">No data</div>';
}

// ============ Update Table ============
function updateTable() {
    if (!reportData) return;

    const view = document.getElementById('reportView').value;
    let data;

    switch (view) {
        case 'issues':
            data = reportData.by_issues;
            break;
        case 'department':
            data = reportData.by_department;
            break;
        case 'resolver':
            data = reportData.by_resolver;
            break;
        case 'trend':
            data = reportData.by_date;
            break;
    }

    const total = data.reduce((sum, d) => sum + d.count, 0);

    const tbody = document.getElementById('reportTableBody');
    tbody.innerHTML = data.map((item, index) => {
        const percentage = total > 0 ? ((item.count / total) * 100).toFixed(1) : 0;
        const barWidth = total > 0 ? (item.count / data[0].count) * 100 : 0;

        return `
            <tr>
                <td><span class="table-rank rank-${index + 1}">${index + 1}</span></td>
                <td>${escapeHtml(item.name || item.date)}</td>
                <td><strong>${item.count}</strong></td>
                <td>${percentage}%</td>
                <td>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${barWidth}%"></div>
                    </div>
                </td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="5" class="empty">No data</td></tr>';
}

// ============ Export PDF ============
function exportReportPDF() {
    alert('PDF export feature - Use Print (Ctrl+P) and save as PDF');
    window.print();
}

// ============ Utility ============
function escapeHtml(text) {
    if (!text) return '-';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
