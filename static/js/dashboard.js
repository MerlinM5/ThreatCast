let isFetching = false;
let intervalId; // Store the interval ID

let threatChart; // Store the Chart.js instance
let chartLabels = [];
let chartDataCritical = [];
let chartDataHigh = [];
let chartDataMedium = [];

function initChart() {
    const ctx = document.getElementById('threatGraph');
    if (!ctx) return;
    
    threatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [
                {
                    label: 'Critical Threats',
                    data: chartDataCritical,
                    borderColor: '#ff4c4c', // var(--critical-red)
                    backgroundColor: 'rgba(255, 76, 76, 0.2)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'High Threats',
                    data: chartDataHigh,
                    borderColor: '#ff9800', // var(--high-orange)
                    backgroundColor: 'rgba(255, 152, 0, 0.2)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Medium Threats',
                    data: chartDataMedium,
                    borderColor: '#ffeb3b', // var(--medium-yellow)
                    backgroundColor: 'rgba(255, 235, 59, 0.2)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 500
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#8b949e' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#8b949e' }
                }
            },
            plugins: {
                legend: { labels: { color: '#c9d1d9' } }
            }
        }
    });
}

// Function to control the traffic generation engine
async function controlTraffic(action) {
    try {
        const res = await fetch('/api/control', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action})
        });
        const data = await res.json();
        console.log(`[Engine] ${data.message}`);
    } catch (e) {
        console.error("Control Error:", e);
    }
}

// NEW FEATURE: Function to handle packet export (Now handles JSON and CSV)
async function exportPackets(type = 'json') {
    try {
        const endpoint = type === 'csv' ? '/api/export_packets_csv' : '/api/export_packets';
        
        const res = await fetch(endpoint);
        
        if (res.status === 404) {
            alert('Error: No packets in buffer to export.');
            return;
        }

        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }

        // Extract the suggested filename from the response header
        const contentDisposition = res.headers.get('Content-Disposition');
        let filename = type === 'csv' ? 'export.csv' : 'export.json';
        if (contentDisposition) {
            const match = contentDisposition.match(/filename="(.+?)"/);
            if (match && match[1]) {
                filename = match[1];
            }
        }

        // Create a blob from the response body and trigger a download
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        console.log(`[Export] Successfully downloaded ${filename}`);

    } catch (e) {
        console.error("Export Error:", e);
        alert('Failed to export data. See console for details.');
    }
}


// NEW ADVANCED FEATURE: Function to trigger a historical forensic sweep (SOAR simulation)
async function triggerForensicSweep(ip) {
    try {
        const res = await fetch('/api/soar_forensic_sweep', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip_address: ip})
        });
        const data = await res.json();
        
        console.log(`[SOAR] ${data.message}`);

    } catch (e) {
        console.error("SOAR API Error:", e);
    }
}

// MODIFIED: Function to trigger WAF prevention and log the reason
// NEW: Added parsing for escaped packetData
async function blockIp(ip, escapedPacketData, elementId) {
    
    // Parse the escaped JSON string back into a JavaScript object
    const packetData = JSON.parse(escapedPacketData.replace(/&quot;/g, '"'));
    
    if (!confirm(`Confirm Block: Are you sure you want to block IP ${ip} at the WAF perimeter? (Action: BLOCK_IP)`)) {
        return;
    }
    
    try {
        const res = await fetch('/api/block_ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip_address: ip, packet_data: packetData, action: 'BLOCK_IP'})
        });
        const data = await res.json();
        
        if (data.status === 'blocked') {
            alert(`[SUCCESS] WAF Rule Applied: ${data.message}`);
            console.log(data.message);
            
            // CRITICAL WORKFLOW: Remove the row from the live monitor table immediately
            const rowToRemove = document.getElementById(elementId);
            if(rowToRemove) {
                rowToRemove.remove();
            }
            
            // --- ADVANCED ACTION: TRIGGER FORENSIC SWEEP (SOAR) ---
            triggerForensicSweep(ip);
            
            // Trigger an update to refresh the blocked list
            updateBlockedList();

        } else {
            alert(`[ERROR] Block Failed: ${data.error}`);
        }
    } catch (e) {
        console.error("Block API Error:", e);
        alert('Failed to communicate with WAF API.');
    }
}


// NEW FEATURE: Function to fetch and display the Blocked IP Log
async function updateBlockedList() {
    try {
        const res = await fetch('/api/blocked_ips');
        const blockedIps = await res.json();
        const tbody = document.getElementById('blockedBody');

        if (tbody) {
            if (blockedIps.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No IPs currently blocked.</td></tr>';
                return;
            }

            tbody.innerHTML = blockedIps.reverse().map(entry => {
                const log = entry.details;
                const reasonDetail = log.reason || 'Manual Block Triggered';
                const scoreDetail = log.score_basis || 'N/A';
                
                return `
                    <tr class="row-malicious" style="background: var(--successful-exploit-bg);">
                        <td>${entry.timestamp}</td>
                        <td style="font-weight: bold; color: var(--critical-red);">${entry.ip}</td>
                        <td style="color: var(--high-orange);">${entry.action}</td>
                        <td class="severity-${entry.severity}">${entry.severity}</td>
                        <td style="font-size: 0.9em;">
                            <strong>Source:</strong> ${log.source || 'WAF Manual'}
                            <br>
                            <strong>Justification:</strong> ${reasonDetail} 
                            <span style="color:var(--text-secondary); margin-left: 10px;">|</span>
                            <strong>Basis:</strong> ${scoreDetail}
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.error("Blocked List Fetch Error:", e);
    }
}


// Function to fetch and update the packet list (Updated for Explainability & Dashboard)
async function updatePackets() {
    if(isFetching) return;
    isFetching = true;

    try {
        const res = await fetch('/api/packets');
        const packets = await res.json();
        
        // --- 1. Update Monitor Table (if on monitor page) ---
        const tbody = document.getElementById('packetBody');
        const filterSelect = document.getElementById('attackFilter');
        
        if (tbody) {
            const selectedAttackType = filterSelect ? filterSelect.value : 'ALL';
            
            // Filter packets based on selection
            const filteredPackets = packets.filter(p => {
                if (selectedAttackType === 'ALL') return true;
                if (selectedAttackType === 'THREATS') return p.severity !== 'Low';
                if (selectedAttackType === 'SUCCESSFUL') return p.is_successful === true;
                if (selectedAttackType === 'Normal') return p.type === 'Normal';
                return p.type === selectedAttackType;
            });

            // OPTIMIZATION: Limit display to the latest 50 packets
            tbody.innerHTML = filteredPackets.slice().reverse().slice(0, 50).map(p => {
                const isMalicious = p.severity !== 'Low';
                const isSuccessful = p.is_successful === true;
                let rowClass = isMalicious ? 'row-malicious' : '';
                if (isSuccessful) {
                    rowClass = 'row-successful-exploit'; 
                }
                
                // Create a unique ID for the row to allow JS removal upon block
                const rowId = `packet-${p.id}`;

                const successIcon = isSuccessful ? `<i class="fas fa-flag-checkered" style="margin-left:5px;" title="Successful Exploit"></i>` : '';
                const severityCellClass = `severity-${p.severity} ${isSuccessful ? 'is-successful' : ''}`;
                
                // NEW: CONSTRUCT THE DETAILED EXPLAINABILITY LOG
                const log = p.detection_log;
                let detailInfo = '';
                
                if (isMalicious && log && log.source !== 'Traffic Logger') {
                    // FIX: Ensure the ' | RESPONSE: ...' part is stripped reliably for all packet types.
                    const infoWithoutProof = p.info.split(" | RESPONSE:")[0];
                    const cleanPayload = infoWithoutProof.split(" GET ")[1] || infoWithoutProof;
                    
                    detailInfo = `
                        <div style="font-size:0.95em; color:var(--text-primary);">
                            <strong>Attack:</strong> ${p.type} 
                            <span style="color:var(--text-secondary); margin-left: 10px;">|</span>
                            <strong>Source:</strong> <span style="color:var(--accent);">${log.source}</span>
                        </div>
                        <div style="font-size:0.8em; color:var(--text-secondary); margin-top: 3px;">
                            <i class="fas fa-microscope"></i> <strong>Justification:</strong> ${log.reason} 
                            <span style="color:var(--accent); margin-left: 10px;">|</span>
                            <strong>HTS Basis:</strong> ${log.score_basis}
                        </div>
                        <div style="font-size:0.8em; color:var(--text-secondary); margin-top: 3px;">
                           <i class="fas fa-link"></i> <strong>Payload:</strong> ${cleanPayload}
                        </div>
                    `;
                } else {
                    detailInfo = p.info; // Default logging for Low/Normal traffic
                }

                // Action Button logic - Must pass full packet JSON and row ID for removal
                let actionBtn = '';
                if (p.prevention_action === 'BLOCK_IP' && p.severity !== 'Low') {
                    // FIX: Escape JSON string for safe use in the onclick HTML attribute 
                    const escapedPacketData = JSON.stringify(p).replace(/"/g, '&quot;');
                    
                    // Use double quotes for the onclick attribute, and single quotes for the string arguments
                    actionBtn = `<button onclick="blockIp('${p.source}', '${escapedPacketData}', '${rowId}')" class="btn btn-red btn-small" title="Auto-Triggered WAF Block"><i class="fas fa-ban"></i></button>`;
                } else if (p.prevention_action === 'RATE_LIMIT' && p.severity !== 'Low') {
                    actionBtn = `<button class="btn btn-grey btn-small" disabled title="Rate-Limited"><i class="fas fa-bolt"></i></button>`;
                } else {
                     actionBtn = `<span style="color: var(--text-secondary); opacity: 0.6;">N/A</span>`;
                }

                return `
                    <tr class="${rowClass}" id="${rowId}">
                        <td>${p.id}</td>
                        <td>${p.timestamp}</td>
                        <td>${p.source}</td>
                        <td>${p.destination}</td>
                        <td>${p.protocol}</td>
                        <td>${detailInfo}</td> 
                        <td class="${severityCellClass}">${p.severity} ${successIcon}</td>
                        <td>${actionBtn}</td>
                    </tr>
                `;
            }).join('');
            
            // ... (omitting filter dropdown population logic) ...
        }

        // --- 2. Update Dashboard Stats (if on dashboard) ---
        // RECTIFICATION: Implement missing dashboard update logic
        const totalPacketsElement = document.getElementById('totalPackets');
        const totalThreatsElement = document.getElementById('totalThreats');
        const activeProtocolElement = document.getElementById('activeProtocol');
        const alertList = document.getElementById('alertList');

        if (totalPacketsElement && totalThreatsElement) {
            totalPacketsElement.innerText = packets.length;
            
            const threats = packets.filter(p => p.severity !== 'Low');
            totalThreatsElement.innerText = threats.length;
            
            // NEW LOGIC: Determine Active Protocol
            if (activeProtocolElement) {
                const protocolCounts = {};
                packets.forEach(p => {
                    protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
                });

                let maxCount = 0;
                let activeProtocol = 'N/A';
                
                // Find the protocol with the highest count
                for (const proto in protocolCounts) {
                    if (protocolCounts[proto] > maxCount) {
                        maxCount = protocolCounts[proto];
                        activeProtocol = proto;
                    }
                }
                
                activeProtocolElement.innerText = packets.length > 0 ? activeProtocol : 'No Traffic';
            }
            
            // Update Recent Alerts (High/Critical only)
            if (alertList) {
                // Filter and get top 5 Critical/High alerts
                const highAlerts = packets
                    .filter(p => p.severity === 'CRITICAL' || p.severity === 'HIGH')
                    .slice()
                    .reverse()
                    .slice(0, 5);
                
                if (highAlerts.length > 0) {
                    // Clear the current list
                    alertList.innerHTML = '';
                    
                    highAlerts.map(p => {
                        const icon = p.severity === 'CRITICAL' ? 'fas fa-skull-crossbones' : 'fas fa-exclamation-triangle';
                        const color = p.severity === 'CRITICAL' ? 'var(--critical-red)' : 'var(--high-orange)';
                        
                        // NEW: Determine the attack status (SUCCESS or ATTEMPT) and style
                        const statusText = p.is_successful ? 'SUCCESS' : 'ATTEMPT';
                        const statusColor = p.is_successful ? 'var(--critical-red)' : 'var(--high-orange)';

                        // Clean up the info for display, removing the simulated response/payload
                        let cleanInfo = p.info.split(" | RESPONSE:")[0]; 
                        
                        // NEW FIX: Truncate long payloads for dashboard display only
                        const MAX_DASHBOARD_LENGTH = 80;
                        if (cleanInfo.length > MAX_DASHBOARD_LENGTH) {
                            cleanInfo = cleanInfo.substring(0, MAX_DASHBOARD_LENGTH) + '... (truncated)';
                        }

                        const listItem = document.createElement('li');
                        listItem.innerHTML = `<i class="${icon}" style="color: ${color};"></i> ${p.timestamp} - <span style="color: ${statusColor}; font-weight: bold;">[${statusText}]</span> ${cleanInfo} (${p.severity})`;
                        alertList.appendChild(listItem);
                    });
                } else if (packets.length > 0) {
                    alertList.innerHTML = '<li><i class="fas fa-check-circle" style="color: var(--low-green);"></i> System nominal. Only Low/Medium traffic detected.</li>';
                } else {
                     alertList.innerHTML = '<li><i class="fas fa-check-circle" style="color: var(--low-green);"></i> System nominal. Waiting for traffic generation...</li>';
                }
            }
        }
        
        // Always update the blocked list after updating the packets
        updateBlockedList();

        // Update the Live Threat Analysis Graph
        if (threatChart) {
            const now = new Date().toLocaleTimeString();
            
            // Count threats in the current batch
            let criticalCount = 0, highCount = 0, mediumCount = 0;
            
            packets.forEach(p => {
                if (p.severity === 'CRITICAL') criticalCount++;
                else if (p.severity === 'HIGH') highCount++;
                else if (p.severity === 'MEDIUM') mediumCount++;
            });

            chartLabels.push(now);
            chartDataCritical.push(criticalCount);
            chartDataHigh.push(highCount);
            chartDataMedium.push(mediumCount);

            // Keep only the last 20 data points
            if (chartLabels.length > 20) {
                chartLabels.shift();
                chartDataCritical.shift();
                chartDataHigh.shift();
                chartDataMedium.shift();
            }

            threatChart.update();
        }

    } catch (e) {
        console.error("Fetch error", e);
    } finally {
        isFetching = false;
    }
}

// Start the continuous packet updates when the page loads
function startUpdates() {
    initChart(); // Initialize the chart first
    // Run once immediately
    updatePackets(); 
    // UI LAG FIX: Increased interval to 4000ms (4 seconds) for smoother UI performance under high load (12 threads)
    if (!intervalId) {
        intervalId = setInterval(updatePackets, 4000); 
    }
}

window.onload = startUpdates;