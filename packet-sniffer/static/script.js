let eventSource = null;
let packetCount = 0;
let isCapturing = false;
let currentFilters = {};

function showAlert(message, type = 'success') {
    const alert = document.getElementById('alert');
    alert.className = `alert alert-${type} show`;
    
    // Add icon based on type
    const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : '⚠️';
    alert.textContent = `${icon} ${message}`;
    
    setTimeout(() => {
        alert.classList.remove('show');
    }, 5000);
}

function getProtocolClass(protocol) {
    const proto = protocol.toLowerCase();
    if (proto.includes('ftp')) return 'protocol-ftp';
    if (proto.includes('smtp')) return 'protocol-smtp';
    if (proto.includes('pop3')) return 'protocol-pop3';
    if (proto.includes('imap')) return 'protocol-imap';
    if (proto.includes('http')) return 'protocol-http';
    if (proto.includes('https')) return 'protocol-https';
    if (proto.includes('tcp')) return 'protocol-tcp';
    if (proto.includes('udp')) return 'protocol-udp';
    if (proto.includes('icmp')) return 'protocol-icmp';
    if (proto.includes('arp')) return 'protocol-arp';
    if (proto.includes('dns')) return 'protocol-dns';
    if (proto.includes('ipv6')) return 'protocol-ipv6';
    return 'protocol-tcp';
}

async function startCapture() {
    const params = {
        protocol: document.getElementById('protocol').value,
        ip: document.getElementById('ip').value,
        domain: document.getElementById('domain').value,
        port: document.getElementById('port').value,
        max_packets: document.getElementById('max_packets').value,
        interface: document.getElementById('interface').value,
        ping_reply_only: document.getElementById('ping_reply_only').checked,
        detect_security: document.getElementById('detect_security').checked
    };

    // Save current filters
    currentFilters = {...params};

    // Show filter info
    showFilterInfo(params);

    try {
        const response = await fetch('/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        });

        const result = await response.json();

        if (result.status === 'success') {
            isCapturing = true;
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
            document.getElementById('statusDot').classList.add('active');
            document.getElementById('statusText').textContent = 'Đang bắt gói tin...';
            
            showAlert(result.message, 'success');
            
            // Bắt đầu nhận packets
            startEventStream();
        } else {
            showAlert(result.message, 'error');
        }
    } catch (error) {
        showAlert('Lỗi kết nối: ' + error.message, 'error');
    }
}

function showFilterInfo(params) {
    const filters = [];
    if (params.protocol) filters.push(`Protocol: ${params.protocol.toUpperCase()}`);
    if (params.ip) filters.push(`IP: ${params.ip}`);
    if (params.domain) filters.push(`Domain: ${params.domain}`);
    if (params.port) filters.push(`Port: ${params.port}`);
    if (params.max_packets) filters.push(`Max: ${params.max_packets} packets`);
    if (params.ping_reply_only) filters.push(`ICMP Echo Reply Only`);
    if (params.detect_security) filters.push(`🔒 Security Detection ON`);

    if (filters.length > 0) {
        document.getElementById('filterDetails').textContent = filters.join(' | ');
        document.getElementById('filterInfo').style.display = 'block';
    } else {
        document.getElementById('filterInfo').style.display = 'none';
    }
}

async function stopCapture() {
    try {
        const response = await fetch('/stop', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'success') {
            isCapturing = false;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            document.getElementById('statusDot').classList.remove('active');
            document.getElementById('statusText').textContent = 'Đã dừng';
            
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }
            
            showAlert(`${result.message} Tổng: ${packetCount} gói tin`, 'success');
        }
    } catch (error) {
        showAlert('Lỗi: ' + error.message, 'error');
    }
}

function startEventStream() {
    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource('/stream');

    eventSource.onmessage = function(event) {
        if (event.data && event.data !== ': heartbeat') {
            try {
                const packet = JSON.parse(event.data);
                addPacketToTable(packet);
                packetCount++;
                updateStats();
            } catch (e) {
                console.error('Error parsing packet:', e);
            }
        }
    };

    eventSource.onerror = function(error) {
        console.error('EventSource error:', error);
        if (!isCapturing && eventSource) {
            eventSource.close();
            eventSource = null;
        }
    };
}

function addPacketToTable(packet) {
    const tbody = document.getElementById('packetsBody');
    
    // Xóa message "Chưa có gói tin nào"
    if (tbody.querySelector('.no-packets')) {
        tbody.innerHTML = '';
    }

    const row = tbody.insertRow(0);
    
    const source = packet.src_port ? 
        `${packet.src_ip}:${packet.src_port}` : packet.src_ip;
    const dest = packet.dest_port ? 
        `${packet.dest_ip}:${packet.dest_port}` : packet.dest_ip;

    row.innerHTML = `
        <td><strong>#${packet.num}</strong></td>
        <td>${packet.timestamp}</td>
        <td><span class="protocol-badge ${getProtocolClass(packet.protocol)}">${packet.protocol}</span></td>
        <td title="${source}">${truncate(source, 35)}</td>
        <td title="${dest}">${truncate(dest, 35)}</td>
        <td>${packet.length}</td>
        <td title="${packet.info}">${truncate(packet.info, 50)}</td>
        <td><button class="btn" style="padding: 6px 16px; font-size: 0.85em;" onclick="viewPacketDetails(${packet.num})">📋 Chi tiết</button></td>
    `;

    // Highlight row animation
    row.style.animation = 'slideDown 0.3s';

    // Giới hạn số dòng hiển thị
    if (tbody.rows.length > 1000) {
        tbody.deleteRow(tbody.rows.length - 1);
    }
}

function truncate(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.substring(0, maxLen) + '...' : str;
}

function updateStats() {
    document.getElementById('totalPackets').textContent = packetCount;
    
    // Cập nhật stats từ server
    fetch('/statistics')
        .then(response => response.json())
        .then(data => {
            if (data.stats) {
                document.getElementById('tcpCount').textContent = data.stats.tcp || 0;
                document.getElementById('udpCount').textContent = data.stats.udp || 0;
                document.getElementById('packetsPerSec').textContent = 
                    (data.packets_per_second || 0).toFixed(1);
            }
        })
        .catch(err => console.error('Error fetching stats:', err));
}

function clearPackets() {
    const tbody = document.getElementById('packetsBody');
    tbody.innerHTML = `
        <tr>
            <td colspan="8" class="no-packets">
                ✨ Đã xóa tất cả gói tin. Sẵn sàng bắt gói tin mới.
            </td>
        </tr>
    `;
    packetCount = 0;
    document.getElementById('totalPackets').textContent = '0';
    document.getElementById('tcpCount').textContent = '0';
    document.getElementById('udpCount').textContent = '0';
    document.getElementById('packetsPerSec').textContent = '0';
    showAlert('Đã xóa tất cả gói tin!', 'success');
}

async function viewPacketDetails(packetNum) {
    const modal = document.getElementById('packetModal');
    const modalBody = document.getElementById('modalBody');
    
    modal.style.display = 'block';
    modalBody.innerHTML = '<div style="text-align: center; padding: 50px;"><div class="loading"></div><p style="margin-top: 20px; color: #667eea; font-weight: 600;">Đang tải chi tiết...</p></div>';
    
    try {
        const response = await fetch(`/packet/${packetNum}`);
        const result = await response.json();
        
        if (result.status === 'success') {
            displayPacketDetails(result.packet);
        } else {
            modalBody.innerHTML = '<p style="text-align: center; color: red; padding: 50px;">❌ Không tìm thấy gói tin!</p>';
        }
    } catch (error) {
        modalBody.innerHTML = `<p style="text-align: center; color: red; padding: 50px;">❌ Lỗi: ${error.message}</p>`;
    }
}

function displayPacketDetails(packet) {
    const modalBody = document.getElementById('modalBody');
    const layers = packet.osi_layers;
    
    let html = `
        <div style="margin-bottom: 35px; padding: 25px; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 16px; border: 2px solid #dee2e6;">
            <h3 style="color: #667eea; margin-bottom: 15px; font-size: 1.5em;">📦 Packet #${packet.num} - ${packet.protocol}</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 20px;">
                <div><strong>⏰ Timestamp:</strong> ${packet.timestamp}</div>
                <div><strong>📏 Length:</strong> ${packet.length} bytes</div>
                <div><strong>🔼 Source:</strong> ${packet.src_ip}${packet.src_port ? ':' + packet.src_port : ''}</div>
                <div><strong>🔽 Destination:</strong> ${packet.dest_ip}${packet.dest_port ? ':' + packet.dest_port : ''}</div>
            </div>
            ${packet.info ? `<div style="margin-top: 15px; padding: 12px; background: white; border-radius: 8px;"><strong>ℹ️ Info:</strong> ${escapeHtml(packet.info)}</div>` : ''}
        </div>
    `;
    
    // Render all OSI layers
    for (let i = 1; i <= 7; i++) {
        const layer = layers[`layer${i}`];
        if (layer) {
            html += renderOSILayer(i, layer);
        }
    }
    
    modalBody.innerHTML = html;
}

function renderOSILayer(layerNum, layer) {
    let html = `
        <div class="osi-layer">
            <div class="layer-header">
                <div class="layer-number">${layerNum}</div>
                <div class="layer-title">
                    <h3>${layer.name}</h3>
                    <p>${getLayerDescription(layerNum)}</p>
                </div>
            </div>
            <div class="layer-content">
    `;
    
    // Simple info
    if (layer.info) {
        html += `<div class="layer-info-box">${escapeHtml(layer.info)}</div>`;
    }
    
    // Protocol and IPs for Layer 2-3
    if (layer.protocol) {
        html += `<div class="detail-row">
            <div class="detail-label">Protocol:</div>
            <div class="detail-value">${escapeHtml(layer.protocol)}</div>
        </div>`;
    }
    
    if (layer.src_mac) {
        html += `<div class="detail-row">
            <div class="detail-label">Source MAC:</div>
            <div class="detail-value">${escapeHtml(layer.src_mac)}</div>
        </div>`;
    }
    
    if (layer.dest_mac) {
        html += `<div class="detail-row">
            <div class="detail-label">Destination MAC:</div>
            <div class="detail-value">${escapeHtml(layer.dest_mac)}</div>
        </div>`;
    }
    
    if (layer.src_ip) {
        html += `<div class="detail-row">
            <div class="detail-label">Source IP:</div>
            <div class="detail-value">${escapeHtml(layer.src_ip)}</div>
        </div>`;
    }
    
    if (layer.dest_ip) {
        html += `<div class="detail-row">
            <div class="detail-label">Destination IP:</div>
            <div class="detail-value">${escapeHtml(layer.dest_ip)}</div>
        </div>`;
    }
    
    // Details
    if (layer.details) {
        for (let [key, value] of Object.entries(layer.details)) {
            html += `<div class="detail-row">
                <div class="detail-label">${escapeHtml(key)}:</div>
                <div class="detail-value">${escapeHtml(String(value))}</div>
            </div>`;
        }
    }
    
    // Application layer protocols
    if (layer.ftp) {
        html += renderProtocolDetails('FTP', layer.ftp, '#fef3c7');
    }
    if (layer.smtp) {
        html += renderProtocolDetails('SMTP', layer.smtp, '#d4edda');
    }
    if (layer.pop3) {
        html += renderProtocolDetails('POP3', layer.pop3, '#f8d7da');
    }
    if (layer.imap) {
        html += renderProtocolDetails('IMAP', layer.imap, '#cce5ff');
    }
    if (layer.http) {
        html += renderHTTPDetails(layer.http);
    }
    if (layer.dns) {
        html += renderDNSDetails(layer.dns);
    }
    
    // Preview
    if (layer.preview) {
        html += `<div class="layer-info-box" style="margin-top: 15px;">
            <strong>📄 Data Preview:</strong><br><br>
            ${escapeHtml(layer.preview)}
        </div>`;
    }
    
    html += `</div></div>`;
    return html;
}

function renderHTTPDetails(http) {
    let html = `
        <div style="margin-top: 20px; padding: 20px; background: linear-gradient(135deg, #e0f2fe 0%, #bae6fd 100%); border-radius: 12px; border: 2px solid #38bdf8;">
            <strong style="font-size: 1.1em; color: #0369a1;">🌐 HTTP ${http.type === 'request' ? 'Request' : 'Response'} Details:</strong><br>
            <div style="margin-top: 15px; display: grid; gap: 10px;">
    `;
    
    if (http.type === 'request') {
        html += `
            <div><strong>Method:</strong> <span style="color: #0369a1; font-weight: 600;">${escapeHtml(http.method)}</span></div>
            <div><strong>URI:</strong> ${escapeHtml(http.uri)}</div>
            <div><strong>Version:</strong> ${escapeHtml(http.version)}</div>
        `;
        if (http.host) {
            html += `<div><strong>Host:</strong> ${escapeHtml(http.host)}</div>`;
        }
        if (http.user_agent) {
            html += `<div><strong>User-Agent:</strong> ${escapeHtml(http.user_agent)}</div>`;
        }
    } else if (http.type === 'response') {
        html += `
            <div><strong>Version:</strong> ${escapeHtml(http.version)}</div>
            <div><strong>Status Code:</strong> <span style="color: #0369a1; font-weight: 600;">${escapeHtml(http.status_code)}</span></div>
            <div><strong>Status Message:</strong> ${escapeHtml(http.status_message)}</div>
        `;
        if (http.content_type) {
            html += `<div><strong>Content-Type:</strong> ${escapeHtml(http.content_type)}</div>`;
        }
        if (http.content_length) {
            html += `<div><strong>Content-Length:</strong> ${escapeHtml(http.content_length)} bytes</div>`;
        }
    }
    
    if (http.headers && Object.keys(http.headers).length > 0) {
        html += `<div style="margin-top: 15px;"><strong>Headers:</strong></div>`;
        html += `<div style="margin-top: 10px; padding: 15px; background: white; border-radius: 8px; font-family: monospace; font-size: 0.9em; max-height: 200px; overflow-y: auto;">`;
        for (let [key, value] of Object.entries(http.headers)) {
            html += `<div style="margin-bottom: 5px;"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(value)}</div>`;
        }
        html += `</div>`;
    }
    
    html += `</div></div>`;
    return html;
}

function renderDNSDetails(dns) {
    return `
        <div style="margin-top: 20px; padding: 20px; background: linear-gradient(135deg, #e9d5ff 0%, #d8b4fe 100%); border-radius: 12px; border: 2px solid #a855f7;">
            <strong style="font-size: 1.1em; color: #6b21a8;">🌐 DNS Information:</strong><br>
            <div style="margin-top: 15px; display: grid; gap: 10px;">
                ${Object.entries(dns).map(([key, value]) => 
                    `<div><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</div>`
                ).join('')}
            </div>
        </div>
    `;
}

function renderProtocolDetails(protocol, data, bgColor) {
    let html = `
        <div style="margin-top: 20px; padding: 20px; background: ${bgColor}; border-radius: 12px; border: 2px solid ${darkenColor(bgColor)};">
            <strong style="font-size: 1.1em;">📁 ${protocol} Protocol Details:</strong><br>
            <div style="margin-top: 15px; display: grid; gap: 10px;">
    `;
    
    if (data.type === 'command') {
        html += `
            <div><strong>Type:</strong> Command</div>
            <div><strong>Command:</strong> <span style="font-weight: 600;">${escapeHtml(data.command)}</span></div>
            <div><strong>Full:</strong> ${escapeHtml(data.full)}</div>
        `;
        if (data.filename) html += `<div><strong>Filename:</strong> ${escapeHtml(data.filename)}</div>`;
        if (data.directory) html += `<div><strong>Directory:</strong> ${escapeHtml(data.directory)}</div>`;
        if (data.username) html += `<div><strong>Username:</strong> ${escapeHtml(data.username)}</div>`;
        if (data.email) html += `<div><strong>Email:</strong> ${escapeHtml(data.email)}</div>`;
        if (data.domain) html += `<div><strong>Domain:</strong> ${escapeHtml(data.domain)}</div>`;
        if (data.mailbox) html += `<div><strong>Mailbox:</strong> ${escapeHtml(data.mailbox)}</div>`;
        if (data.message_id) html += `<div><strong>Message ID:</strong> ${escapeHtml(data.message_id)}</div>`;
        if (data.tag) html += `<div><strong>Tag:</strong> ${escapeHtml(data.tag)}</div>`;
    } else if (data.type === 'response') {
        html += `
            <div><strong>Type:</strong> Response</div>
        `;
        if (data.code) html += `<div><strong>Code:</strong> <span style="font-weight: 600;">${escapeHtml(data.code)}</span></div>`;
        if (data.status) html += `<div><strong>Status:</strong> ${escapeHtml(data.status)}</div>`;
        if (data.success !== undefined) html += `<div><strong>Success:</strong> ${data.success ? '✅ Yes' : '❌ No'}</div>`;
        if (data.message) html += `<div><strong>Message:</strong> ${escapeHtml(data.message)}</div>`;
        if (data.tag) html += `<div><strong>Tag:</strong> ${escapeHtml(data.tag)}</div>`;
    }
    
    html += `</div></div>`;
    return html;
}

function darkenColor(color) {
    // Simple color darkening
    return color.replace(/[0-9a-f]/gi, c => Math.max(0, parseInt(c, 16) - 2).toString(16));
}

function getLayerDescription(layerNum) {
    const descriptions = {
        1: 'Tầng Vật Lý - Physical Layer',
        2: 'Tầng Liên Kết Dữ Liệu - Data Link Layer',
        3: 'Tầng Mạng - Network Layer',
        4: 'Tầng Giao Vận - Transport Layer',
        5: 'Tầng Phiên - Session Layer',
        6: 'Tầng Trình Diễn - Presentation Layer',
        7: 'Tầng Ứng Dụng - Application Layer'
    };
    return descriptions[layerNum] || '';
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

function closeModal() {
    document.getElementById('packetModal').style.display = 'none';
}

// Đóng modal khi click bên ngoài
window.onclick = function(event) {
    const modal = document.getElementById('packetModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

// Cập nhật stats định kỳ
setInterval(() => {
    if (isCapturing) {
        updateStats();
    }
}, 2000);

// Show welcome message
window.addEventListener('load', function() {
    setTimeout(() => {
        showAlert('👋 Chào mừng! Hãy cấu hình bộ lọc và nhấn "Bắt đầu bắt gói tin"', 'success');
    }, 500);
});