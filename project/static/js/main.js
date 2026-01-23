/**
 * IoT-Guardian - Main JavaScript
 * Expert System for IoT Security
 */

// Global socket connection
let socket = null;

/**
 * Initialize WebSocket connection
 */
function initializeSocket() {
    try {
        socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to IoT-Guardian server');
            updateSystemStatus('System Online', 'online');
        });

        socket.on('disconnect', function() {
            console.log('Disconnected from server');
            updateSystemStatus('Disconnected', 'offline');
        });

        socket.on('connected', function(data) {
            console.log('Server response:', data);
        });

        socket.on('inference_update', function(data) {
            addInferenceLog(data.timestamp, data.message);
        });

        socket.on('new_alert', function(data) {
            displayNewAlert(data);
            updateAlertCount();
        });

        socket.on('new_defense', function(data) {
            displayNewDefense(data);
            updateDefenseCount();
        });

        socket.on('status_update', function(data) {
            updateDashboardStats(data);
        });

    } catch (error) {
        console.error('Socket initialization error:', error);
    }
}

/**
 * Update system status indicator
 */
function updateSystemStatus(text, status) {
    const statusText = document.getElementById('system-status');
    const statusIndicator = document.querySelector('.status-indicator');
    
    if (statusText) {
        statusText.textContent = text;
    }
    
    if (statusIndicator) {
        statusIndicator.className = 'status-indicator ' + status;
    }
}

/**
 * Load system status from API
 */
function loadStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            updateDashboardStats(data);
        })
        .catch(error => {
            console.error('Error loading status:', error);
        });
}

/**
 * Update dashboard statistics
 */
function updateDashboardStats(data) {
    const attackCount = document.getElementById('attack-count');
    const alertCount = document.getElementById('alert-count');
    const defenseCount = document.getElementById('defense-count');
    
    if (attackCount) attackCount.textContent = data.attacks_detected || data.attacks || 0;
    if (alertCount) alertCount.textContent = data.alerts_count || data.alerts || 0;
    if (defenseCount) defenseCount.textContent = data.defenses_count || data.defenses || 0;
}

/**
 * Update alert count
 */
function updateAlertCount() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            const alertCount = document.getElementById('alert-count');
            if (alertCount) {
                alertCount.textContent = data.alerts_count;
            }
        });
}

/**
 * Update defense count
 */
function updateDefenseCount() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            const defenseCount = document.getElementById('defense-count');
            if (defenseCount) {
                defenseCount.textContent = data.defenses_count;
            }
        });
}

/**
 * Refresh network packets display
 */
function refreshPackets() {
    fetch('/api/simulate_packets', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ count: 5 })
    })
    .then(response => response.json())
    .then(data => {
        displayPackets(data.packets);
    })
    .catch(error => {
        console.error('Error refreshing packets:', error);
    });
}

/**
 * Display network packets
 */
function displayPackets(packets) {
    const packetsList = document.getElementById('packets-list');
    if (!packetsList) return;

    if (!packets || packets.length === 0) {
        packetsList.innerHTML = `<div class="empty-state">
            <i class="fas fa-exchange-alt"></i>
            <p>No packets captured</p>
        </div>`;
        return;
    }

    let html = '';
    packets.forEach(packet => {
        html += `
        <div class="packet-item">
            <span class="packet-src">${packet.source_ip}</span>
            <span class="packet-arrow">→</span>
            <span class="packet-dst">${packet.dest_ip}</span>
            <span class="protocol">${packet.protocol}</span>
            <span class="packet-size">${packet.payload_size}B</span>
        </div>`;
    });
    packetsList.innerHTML = html;
}

/**
 * Add entry to inference log
 */
function addInferenceLog(timestamp, message) {
    const logContainer = document.getElementById('inference-log');
    if (!logContainer) return;

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${timestamp}</span>
        <span class="log-msg">${message}</span>
    `;
    
    logContainer.appendChild(entry);
    logContainer.scrollTop = logContainer.scrollHeight;

    // Keep only last 50 entries
    while (logContainer.children.length > 50) {
        logContainer.removeChild(logContainer.firstChild);
    }
}

/**
 * Display new alert notification
 */
function displayNewAlert(alert) {
    const alertsList = document.getElementById('alerts-list');
    if (!alertsList) return;

    // Remove empty state if present
    const emptyState = alertsList.querySelector('.empty-state');
    if (emptyState) {
        emptyState.remove();
    }

    const alertItem = document.createElement('div');
    alertItem.className = `alert-item ${alert.level.toLowerCase()}`;
    alertItem.innerHTML = `
        <div class="alert-header">
            <strong>${alert.level}</strong>
            <span class="alert-time">${alert.timestamp}</span>
        </div>
        <div class="alert-message">${alert.message}</div>
    `;
    
    alertsList.insertBefore(alertItem, alertsList.firstChild);

    // Flash effect
    alertItem.style.animation = 'flash 0.5s';

    // Keep only last 10 alerts
    while (alertsList.children.length > 10) {
        alertsList.removeChild(alertsList.lastChild);
    }
}

/**
 * Display new defense action
 */
function displayNewDefense(defense) {
    // This can be customized based on where defense actions should appear
    console.log('New defense action:', defense);
}

/**
 * Clear alerts list
 */
function clearAlerts() {
    const alertsList = document.getElementById('alerts-list');
    if (alertsList) {
        alertsList.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <p>No alerts - System secure</p>
        </div>`;
    }
}

/**
 * Format timestamp
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return '--:--:--';
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show notification toast
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add CSS for toast
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    .toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: #333;
        color: white;
        border-radius: 8px;
        opacity: 0;
        transform: translateY(20px);
        transition: all 0.3s ease;
        z-index: 9999;
    }
    .toast.show {
        opacity: 1;
        transform: translateY(0);
    }
    .toast-success { background: #2ecc71; }
    .toast-error { background: #e74c3c; }
    .toast-warning { background: #f39c12; }
    .toast-info { background: #3498db; }
    
    @keyframes flash {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
`;
document.head.appendChild(toastStyles);
