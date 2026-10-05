/**
 * Event Investigation & Incident Management Client
 */

let currentAlertId = "";

document.addEventListener("DOMContentLoaded", () => {
    const urlParams = new URLSearchParams(window.location.search);
    const initialAlertId = urlParams.get("alert_id") || document.getElementById("input-alert-id").value;

    if (initialAlertId) {
        document.getElementById("input-alert-id").value = initialAlertId;
        fetchAlertDetails(initialAlertId);
    } else {
        // Auto-fetch latest alert if none provided
        fetchLatestAlert();
    }
});

async function fetchLatestAlert() {
    try {
        const resp = await fetch("/api/dashboard/alerts?limit=1");
        const data = await resp.json();
        if (data.alerts && data.alerts.length > 0) {
            const latestId = data.alerts[0].alert_id;
            document.getElementById("input-alert-id").value = latestId;
            fetchAlertDetails(latestId);
        }
    } catch (e) {
        console.error("Failed to load latest alert:", e);
    }
}

async function fetchAlertDetails(overrideId = null) {
    const alertId = overrideId || document.getElementById("input-alert-id").value.trim();
    if (!alertId) return;

    try {
        const resp = await fetch(`/api/alerts/${alertId}`);
        if (!resp.ok) {
            alert(`Alert '${alertId}' not found.`);
            return;
        }

        const data = await resp.json();
        currentAlertId = data.alert_id;

        // Populate basic headers
        document.getElementById("inv-alert-id").innerText = data.alert_id;
        document.getElementById("inv-alert-type").innerText = data.alert_type;
        document.getElementById("inv-description").innerText = data.description;
        document.getElementById("inv-status-badge").innerText = data.status;

        // Severity Badge Styling
        const sevBadge = document.getElementById("inv-severity-badge");
        sevBadge.innerText = data.severity;
        sevBadge.className = "badge";
        if (data.severity === "CRITICAL") sevBadge.classList.add("bg-danger");
        else if (data.severity === "HIGH") sevBadge.classList.add("bg-warning", "text-dark");
        else if (data.severity === "MEDIUM") sevBadge.classList.add("bg-primary");
        else sevBadge.classList.add("bg-info", "text-dark");

        // Telemetry details
        const flow = data.flow || {};
        document.getElementById("inv-src").innerText = `${data.source_ip || flow.source_ip || 'N/A'}:${flow.source_port || 'N/A'}`;
        document.getElementById("inv-dst").innerText = `${data.destination_ip || flow.destination_ip || 'N/A'}:${flow.destination_port || 'N/A'}`;
        document.getElementById("inv-proto").innerText = flow.protocol || data.protocol || "TCP";
        document.getElementById("inv-packets").innerText = (flow.packet_count || 0).toLocaleString();
        document.getElementById("inv-bytes").innerText = (flow.byte_count || 0).toLocaleString() + " B";
        document.getElementById("inv-duration").innerText = (flow.duration || 0).toFixed(2) + "s";

        // Multi-Layer Scores
        document.getElementById("inv-rule-id").innerText = data.rule_id || "IDS-001";
        document.getElementById("inv-anomaly-score").innerText = (flow.anomaly_score !== undefined ? flow.anomaly_score : 50.0).toFixed(1);
        document.getElementById("inv-ml-prob").innerText = `${((flow.ml_probability || 0.8) * 100).toFixed(1)}%`;
        document.getElementById("inv-risk-score").innerText = `${data.risk_score} / 100`;

        // Playbook steps
        const ul = document.getElementById("inv-playbook-steps");
        ul.innerHTML = "";
        const steps = data.recommended_steps || [
            "Review firewall connection logs for source IP.",
            "Verify host legitimacy against internal directory.",
            "Assess potential impact on affected target port.",
        ];
        steps.forEach(st => {
            const li = document.createElement("li");
            li.className = "mb-1";
            li.innerText = st;
            ul.appendChild(li);
        });

        // Notes timeline
        renderNotes(data.notes || []);

    } catch (e) {
        console.error("Error loading alert details:", e);
    }
}

function renderNotes(notes) {
    const container = document.getElementById("notes-timeline");
    if (!notes || notes.length === 0) {
        container.innerHTML = `<div class="text-center text-secondary py-3 small font-monospace">No notes recorded yet.</div>`;
        return;
    }

    container.innerHTML = "";
    notes.forEach(n => {
        const item = document.createElement("div");
        item.className = "p-2 mb-2 rounded bg-dark border border-secondary font-monospace";
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="fw-bold text-info" style="font-size: 0.8rem;">${n.author}</span>
                <span class="text-secondary" style="font-size: 0.7rem;">${n.created_at}</span>
            </div>
            <div class="text-light small">${n.note}</div>
        `;
        container.appendChild(item);
    });
}

async function updateStatus(newStatus) {
    if (!currentAlertId) return;

    try {
        const resp = await fetch(`/api/alerts/${currentAlertId}/status`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                status: newStatus,
                note: `Analyst toggled status to ${newStatus}`,
                author: document.getElementById("input-analyst-name").value || "SOC Analyst",
            }),
        });

        if (resp.ok) {
            fetchAlertDetails(currentAlertId);
        } else {
            alert("Failed to update alert status.");
        }
    } catch (e) {
        console.error("Error updating status:", e);
    }
}

async function submitAnalystNote() {
    if (!currentAlertId) return;

    const noteText = document.getElementById("input-analyst-note").value.trim();
    const author = document.getElementById("input-analyst-name").value.trim();

    if (!noteText) {
        alert("Please enter a note before posting.");
        return;
    }

    try {
        const resp = await fetch(`/api/alerts/${currentAlertId}/notes`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ note: noteText, author: author }),
        });

        if (resp.ok) {
            document.getElementById("input-analyst-note").value = "";
            fetchAlertDetails(currentAlertId);
        } else {
            alert("Failed to save note.");
        }
    } catch (e) {
        console.error("Error posting note:", e);
    }
}
