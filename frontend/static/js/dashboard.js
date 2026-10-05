/**
 * SOC Dashboard Interactive Engine
 * Handles real-time polling, Chart.js visualizations, and scenario triggers.
 */

let timelineChart = null;
let ratioChart = null;
let severityChart = null;
let alertTypesChart = null;
let protocolChart = null;

// Initialize charts on DOM Load
document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    loadDashboardData();
    // Poll every 3 seconds for near-real-time updates
    setInterval(loadDashboardData, 3000);
});

function initCharts() {
    const defaultFont = { family: "'Inter', sans-serif" };

    // 1. Traffic Timeline Chart (Packets & Bytes)
    const ctxTimeline = document.getElementById("trafficTimelineChart").getContext("2d");
    timelineChart = new Chart(ctxTimeline, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Packets",
                    data: [],
                    borderColor: "#06b6d4",
                    backgroundColor: "rgba(6, 182, 212, 0.15)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    yAxisID: "yPackets",
                },
                {
                    label: "Risk Score",
                    data: [],
                    borderColor: "#f43f5e",
                    borderWidth: 2,
                    borderDash: [4, 4],
                    tension: 0.2,
                    yAxisID: "yRisk",
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: {
                legend: { labels: { color: "#94a3b8", font: defaultFont } },
            },
            scales: {
                x: {
                    grid: { color: "#1e293b" },
                    ticks: { color: "#64748b", font: { size: 10 } },
                },
                yPackets: {
                    type: "linear",
                    position: "left",
                    grid: { color: "#1e293b" },
                    ticks: { color: "#94a3b8" },
                    title: { display: true, text: "Packets", color: "#64748b" },
                },
                yRisk: {
                    type: "linear",
                    position: "right",
                    min: 0,
                    max: 100,
                    grid: { drawOnChartArea: false },
                    ticks: { color: "#f43f5e" },
                    title: { display: true, text: "Risk (0-100)", color: "#f43f5e" },
                },
            },
        },
    });

    // 2. Normal vs Suspicious Donut
    const ctxRatio = document.getElementById("trafficRatioChart").getContext("2d");
    ratioChart = new Chart(ctxRatio, {
        type: "doughnut",
        data: {
            labels: ["Normal Flows", "Suspicious Flows"],
            datasets: [{
                data: [1, 0],
                backgroundColor: ["#10b981", "#f59e0b"],
                borderColor: "#111726",
                borderWidth: 3,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "bottom", labels: { color: "#94a3b8" } },
            },
            cutout: "70%",
        },
    });

    // 3. Alerts by Severity Bar
    const ctxSeverity = document.getElementById("severityChart").getContext("2d");
    severityChart = new Chart(ctxSeverity, {
        type: "bar",
        data: {
            labels: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ["#64748b", "#06b6d4", "#3b82f6", "#f59e0b", "#f43f5e"],
                borderRadius: 4,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                y: { ticks: { color: "#64748b", stepSize: 1 }, grid: { color: "#1e293b" } },
            },
        },
    });

    // 4. Top Alert Types Horizontal Bar
    const ctxAlertTypes = document.getElementById("alertTypesChart").getContext("2d");
    alertTypesChart = new Chart(ctxAlertTypes, {
        type: "bar",
        data: {
            labels: ["None"],
            datasets: [{
                data: [0],
                backgroundColor: "#8b5cf6",
                borderRadius: 4,
            }],
        },
        options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#64748b", stepSize: 1 }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } },
            },
        },
    });

    // 5. Protocol Pie Chart
    const ctxProto = document.getElementById("protocolChart").getContext("2d");
    protocolChart = new Chart(ctxProto, {
        type: "pie",
        data: {
            labels: ["TCP", "UDP", "ICMP"],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ["#0ea5e9", "#14b8a6", "#a855f7"],
                borderColor: "#111726",
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "bottom", labels: { color: "#94a3b8" } },
            },
        },
    });
}

async function loadDashboardData() {
    await Promise.all([loadStats(), loadTrafficTimeline(), loadAlerts()]);
}

async function loadStats() {
    try {
        const resp = await fetch("/api/dashboard/stats");
        if (!resp.ok) return;
        const data = await resp.json();

        document.getElementById("stat-total-flows").innerText = data.total_flows.toLocaleString();
        document.getElementById("stat-normal-flows").innerText = data.normal_flows.toLocaleString();
        document.getElementById("stat-suspicious-flows").innerText = data.suspicious_flows.toLocaleString();
        document.getElementById("stat-open-alerts").innerText = data.open_alerts.toLocaleString();
        document.getElementById("stat-critical-alerts").innerText = data.critical_alerts.toLocaleString();
        document.getElementById("stat-avg-risk").innerText = data.average_risk_score.toFixed(1);

        // Update Donut
        if (ratioChart) {
            ratioChart.data.datasets[0].data = [data.normal_flows, data.suspicious_flows];
            ratioChart.update();
        }

        // Update Severity Chart
        if (severityChart && data.severity_distribution) {
            const sevMap = data.severity_distribution;
            severityChart.data.datasets[0].data = [
                sevMap["INFO"] || 0,
                sevMap["LOW"] || 0,
                sevMap["MEDIUM"] || 0,
                sevMap["HIGH"] || 0,
                sevMap["CRITICAL"] || 0,
            ];
            severityChart.update();
        }

        // Update Top Alert Types
        if (alertTypesChart && data.top_alert_types && data.top_alert_types.length > 0) {
            alertTypesChart.data.labels = data.top_alert_types.map(t => t.alert_type.substring(0, 22));
            alertTypesChart.data.datasets[0].data = data.top_alert_types.map(t => t.cnt);
            alertTypesChart.update();
        }

        // Update Protocol Chart
        if (protocolChart && data.protocol_distribution) {
            const pMap = {};
            data.protocol_distribution.forEach(p => pMap[p.protocol] = p.cnt);
            protocolChart.data.datasets[0].data = [
                pMap["TCP"] || 0,
                pMap["UDP"] || 0,
                pMap["ICMP"] || 0,
            ];
            protocolChart.update();
        }
    } catch (e) {
        console.error("Error loading stats:", e);
    }
}

async function loadTrafficTimeline() {
    try {
        const resp = await fetch("/api/dashboard/traffic?limit=40");
        if (!resp.ok) return;
        const data = await resp.json();
        const rows = data.timeline || [];

        if (timelineChart && rows.length > 0) {
            const labels = rows.map(r => r.timestamp.split(" ")[1] || r.timestamp);
            const packets = rows.map(r => r.packet_count);
            const risks = rows.map(r => r.risk_score);

            timelineChart.data.labels = labels;
            timelineChart.data.datasets[0].data = packets;
            timelineChart.data.datasets[1].data = risks;
            timelineChart.update("none"); // update without full reset animation for smooth polling
        }
    } catch (e) {
        console.error("Error loading traffic timeline:", e);
    }
}

async function loadAlerts() {
    try {
        const sev = document.getElementById("filter-severity").value;
        const stat = document.getElementById("filter-status").value;

        let url = "/api/dashboard/alerts?limit=15";
        if (sev) url += `&severity=${sev}`;
        if (stat) url += `&status=${stat}`;

        const resp = await fetch(url);
        if (!resp.ok) return;
        const data = await resp.json();
        const alerts = data.alerts || [];

        const tbody = document.getElementById("alerts-table-body");
        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" class="text-center text-secondary py-3">No active alerts matching criteria.</td></tr>`;
            return;
        }

        tbody.innerHTML = "";
        alerts.forEach(a => {
            let sevBadge = "bg-secondary";
            if (a.severity === "CRITICAL") sevBadge = "bg-danger text-light";
            else if (a.severity === "HIGH") sevBadge = "bg-warning text-dark";
            else if (a.severity === "MEDIUM") sevBadge = "bg-primary text-light";
            else if (a.severity === "LOW") sevBadge = "bg-info text-dark";

            let statusBadge = "bg-secondary";
            if (a.status === "NEW") statusBadge = "bg-danger-subtle text-danger border border-danger-subtle";
            else if (a.status === "INVESTIGATING") statusBadge = "bg-warning-subtle text-warning border border-warning-subtle";
            else if (a.status === "RESOLVED") statusBadge = "bg-success-subtle text-success border border-success-subtle";
            else if (a.status === "FALSE_POSITIVE") statusBadge = "bg-secondary-subtle text-secondary";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="ps-3 text-secondary small">${a.created_at.split(" ")[1] || a.created_at}</td>
                <td class="fw-bold text-info">${a.alert_id}</td>
                <td><span class="badge bg-dark border border-secondary">${a.source_ip}</span></td>
                <td><span class="badge bg-dark border border-secondary">${a.destination_ip}:${a.destination_port}</span></td>
                <td><span class="text-secondary">${a.protocol}</span></td>
                <td><span class="text-light">${a.alert_type}</span></td>
                <td><span class="badge ${sevBadge}">${a.severity}</span></td>
                <td><span class="fw-bold ${a.risk_score > 60 ? 'text-danger' : 'text-warning'}">${a.risk_score}</span></td>
                <td><span class="badge ${statusBadge}">${a.status}</span></td>
                <td class="text-end pe-3">
                    <a href="/investigation?alert_id=${a.alert_id}" class="btn btn-sm btn-outline-info">
                        <i class="fa-solid fa-magnifying-glass me-1"></i> Triage
                    </a>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading alerts:", e);
    }
}

// On-Demand Scenario Trigger
async function triggerScenario(scenarioName) {
    try {
        const resp = await fetch("/api/simulation/trigger", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: scenarioName }),
        });
        const res = await resp.json();
        // Immediately reload data to show instant feedback
        loadDashboardData();
    } catch (e) {
        console.error("Error triggering scenario:", e);
    }
}
