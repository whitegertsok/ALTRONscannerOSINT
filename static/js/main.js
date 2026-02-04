document.addEventListener('DOMContentLoaded', () => {
    const toolsGrid = document.getElementById('toolsGrid');
    const resultModal = document.getElementById('resultModal');
    const modalTitle = document.getElementById('modalTitle');
    const closeModal = document.getElementById('closeModal');

    const modalInputSection = document.getElementById('modalInputSection');
    const modalLoader = document.getElementById('modalLoader');
    const modalResult = document.getElementById('modalResult');

    const modalTargetInput = document.getElementById('modalTargetInput');
    const modalRunBtn = document.getElementById('modalRunBtn');

    let currentToolId = null;

    // INLINE SVGs - Each scanner has a unique, descriptive icon
    const svgs = {
        1: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8.5 14.5L4 10l1.41-1.41L8.5 11.67L15.18 5 16.6 6.41l-8.1 8.09zM12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-2-8H8v-2h2V8h2v2h2v2h-2v2h-2v-2z"/></svg>', // Port Scanner - network ports
        2: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-5 14H4v-4h11v4zm0-5H4V9h11v4zm5 5h-4V9h4v9z"/></svg>', // Whois - document/card
        3: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4c-1.48 0-2.85.43-4.01 1.17l1.46 1.46C10.21 6.23 11.08 6 12 6c3.04 0 5.5 2.46 5.5 5.5v.5H19c1.66 0 3 1.34 3 3 0 1.13-.64 2.11-1.56 2.62l1.45 1.45C23.16 18.16 24 16.68 24 15c0-2.64-2.05-4.78-4.65-4.96zM3 5.27l2.75 2.74C2.56 8.15 0 10.77 0 14c0 3.31 2.69 6 6 6h11.73l2 2L21 20.73 4.27 4 3 5.27zM7.73 10l8 8H6c-2.21 0-4-1.79-4-4s1.79-4 4-4h1.73z"/></svg>', // DNS Enumerator - cloud/DNS
        4: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l-5.5 9h11z M17.5 11L12 20l-5.5-9h11z M12 7.5l2.5 4h-5z"/></svg>', // Subdomain Finder - sitemap/tree structure
        6: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>', // SSL/TLS - lock
        7: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>', // HTTP Headers - code brackets
        8: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 9V7c0-1.1-.9-2-2-2h-3c0-1.66-1.34-3-3-3S9 3.34 9 5H6c-1.1 0-2 .9-2 2v2c-1.66 0-3 1.34-3 3s1.34 3 3 3v4c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2v-4c1.66 0 3-1.34 3-3s-1.34-3-3-3zM12 4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm6 15H6V7h12v12z"/></svg>', // Robots.txt - robot
        9: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z"/></svg>', // Social Media - link
        10: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>', // Directory Buster - folder
        11: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14.17 13.71l1.4-2.42c.09-.15.05-.34-.09-.44-.04-.03-.09-.05-.14-.05h-1.14l.89-1.53c.09-.15.05-.34-.09-.44-.04-.03-.09-.05-.14-.05h-3.3c-.09 0-.17.05-.21.13l-2.21 3.83c-.09.15-.05.34.09.44.04.03.09.05.14.05h1.14l-.89 1.53c-.09.15-.05.34.09.44.04.03.09.05.14.05h3.3c.09 0 .17-.05.21-.13zM20 8H4V6h16v2zm0 10H4v-8h16v8zm0-12H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/></svg>', // Backup File Finder - archive/save
        12: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.5.67s.74 2.65.74 4.8c0 2.06-1.35 3.73-3.41 3.73-2.07 0-3.63-1.67-3.63-3.73l.03-.36C5.21 7.51 4 10.62 4 14c0 4.42 3.58 8 8 8s8-3.58 8-8C20 8.61 17.41 3.8 13.5.67zM11.71 19c-1.78 0-3.22-1.4-3.22-3.14 0-1.62 1.05-2.76 2.81-3.12 1.77-.36 3.6-1.21 4.62-2.58.39 1.29.59 2.65.59 4.04 0 2.65-2.15 4.8-4.8 4.8z"/></svg>', // Clickjacking - cursor/click
        13: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11zM8.82 13.05L7.4 14.46 10.94 18l5.66-5.66-1.41-1.41-4.24 4.24-2.13-2.12z"/></svg>', // Git Exposure - git branch/file
        14: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm2 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>', // CORS Tester - clipboard
        15: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 15l-6 6-1.42-1.42L15.17 16H4V4h2v10h9.17l-3.59-3.58L13 9l6 6z"/></svg>', // Open Redirect - redirect arrow
        16: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 6h-8l-2-2H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-1 12H5c-.55 0-1-.45-1-1s.45-1 1-1h14c.55 0 1 .45 1 1s-.45 1-1 1zm0-4H5c-.55 0-1-.45-1-1s.45-1 1-1h14c.55 0 1 .45 1 1s-.45 1-1 1z"/></svg>' // Directory Traversal - folder search
    };

    const toolDescriptions = {
        1: "Scans for open ports",
        2: "Domain registration info",
        3: "DNS records analysis",
        4: "Discovers subdomains",
        6: "Checks SSL certificates",
        7: "Security headers check",
        8: "Analyzes robots.txt",
        9: "Finds social profiles",
        10: "Brute-forces directories",
        11: "Finds exposed backups",
        12: "Tests UI redressing",
        13: "Checks .git exposure",
        14: "CORS misconfigurations",
        15: "Open redirect vulns",
        16: "Path traversal vulns"
    };

    // 1. FETCH AND RENDER TOOLS
    fetch('/api/tools')
        .then(res => res.json())
        .then(tools => {
            toolsGrid.innerHTML = '';
            Object.entries(tools).forEach(([id, name]) => {
                const card = document.createElement('div');
                card.className = 'tool-card';
                card.innerHTML = `
                    <div class="tool-icon">${svgs[id] || svgs[1]}</div>
                    <div class="tool-name">${name}</div>
                    <div class="tool-status" style="font-size: 0.8em; opacity: 0.7; letter-spacing: 0.5px;">${toolDescriptions[id] || 'Security Scanner'}</div>
                `;
                card.onclick = () => openModal(id, name);
                toolsGrid.appendChild(card);
            });
        })
        .catch(err => console.error("API Error:", err));

    // 2. MODAL LOGIC
    function openModal(id, name) {
        currentToolId = id;
        modalTitle.textContent = name;
        modalTargetInput.value = '';

        modalResult.innerHTML = '';
        modalInputSection.classList.remove('hidden');
        modalLoader.classList.add('hidden');
        modalResult.classList.add('hidden');

        resultModal.classList.remove('hidden');
        modalTargetInput.focus();
    }

    closeModal.onclick = () => {
        resultModal.classList.add('hidden');
    };

    window.onclick = (e) => {
        if (e.target === resultModal) {
            resultModal.classList.add('hidden');
        }
    };

    // 3. RUN SCAN LOGIC
    function validateTarget(target) {
        target = target.trim();
        if (!target) {
            return { valid: false, error: "Please enter a target URL or domain!" };
        }
        if (target.length > 500) {
            return { valid: false, error: "Target is too long (max 500 characters)" };
        }

        // Check for SQL/XSS injection attempts (combined)
        const injectionPatterns = [
            // SQL patterns
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/i,
            /(--|\*\/|\/\*|;|xp_|sp_)/i,
            /('|('))/,
            /(OR|AND)\s+[\d']/i,
            // XSS patterns
            /<script[\s\S]*?>[\s\S]*?<\/script>/i,
            /<iframe[\s\S]*?>/i,
            /javascript:/i,
            /on(load|error|click|mouse)=/i,
            /<img[\s\S]*?>/i,
            /eval\(/i,
            /alert\(/i
        ];

        // Check for any injection attempt
        for (const pattern of injectionPatterns) {
            if (pattern.test(target)) {
                return {
                    valid: false,
                    error: "Damn, are you serious? :)"
                };
            }
        }

        const domainPattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const urlPattern = /^https?:\/\//;

        if (urlPattern.test(target)) {
            try {
                const url = new URL(target);
                if (!url.hostname || url.hostname.length < 3) {
                    return { valid: false, error: "Invalid URL hostname" };
                }
                return { valid: true, value: target };
            } catch (e) {
                return { valid: false, error: "Invalid URL format" };
            }
        }

        if (domainPattern.test(target) || ipPattern.test(target)) {
            return { valid: true, value: target };
        }

        return { valid: false, error: "Invalid format. Use: example.com or http://example.com (public domains only)" };
    }

    modalRunBtn.onclick = () => {
        const target = modalTargetInput.value.trim();
        const validation = validateTarget(target);

        if (!validation.valid) {
            alert(validation.error);
            return;
        }

        startScan(currentToolId, validation.value);
    };

    modalTargetInput.onkeypress = (e) => {
        if (e.key === 'Enter') modalRunBtn.click();
    };

    async function startScan(id, target) {
        modalInputSection.classList.add('hidden');
        modalLoader.classList.remove('hidden');
        modalResult.classList.add('hidden');
        modalResult.innerHTML = '';

        try {
            const res = await fetch(`/api/run/${id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });
            const data = await res.json();

            if (data.error) throw new Error(data.error);

            poll(data.scan_id, id);
        } catch (e) {
            showError(e.message);
        }
    }

    function poll(scanId, toolId) {
        let attempts = 0;
        const maxAttempts = 60;

        const interval = setInterval(async () => {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(interval);
                showError("Scan timed out. Please try again.");
                return;
            }

            try {
                const res = await fetch(`/api/status/${scanId}`);
                const data = await res.json();

                if (data.error && !data.status) {
                    clearInterval(interval);
                    showError(data.error);
                    return;
                }

                if (data.status === 'completed') {
                    clearInterval(interval);
                    render(data.result, toolId);
                } else if (data.status === 'error') {
                    clearInterval(interval);
                    showError(data.error);
                }
            } catch (e) {
                clearInterval(interval);
                showError(e.message);
            }
        }, 1000);
    }

    function showError(msg) {
        modalLoader.classList.add('hidden');
        modalResult.classList.remove('hidden');
        modalResult.innerHTML = `<div class="vuln-card" style="border-color:red"><h4 style="color:red">ERROR</h4>${msg}</div>`;
    }

    // 4. RENDER REPORT LOGIC
    function render(data, toolId) {
        modalLoader.classList.add('hidden');
        modalResult.classList.remove('hidden');

        let html = `
            <div class="scan-status-banner">
                <div style="width:24px;height:24px;">${svgs[12]}</div>
                <span>SCAN COMPLETED SUCCESSFULLY</span>
            </div>
        `;

        if (data.error) {
            showError(data.error);
            return;
        }

        const tid = parseInt(toolId);

        if (tid === 1) {
            html += `
                <div class="vuln-card" style="border-color:${data.open_ports.length ? 'red' : 'green'}">
                    <h4>${data.open_ports.length} PORTS OPEN</h4>
                </div>
                <table class="report-table">
                    <thead><tr><th>PORT</th><th>SERVICE</th><th>BANNER</th><th>STATUS</th></tr></thead>
                    <tbody>
                        ${data.open_ports.map(p => `
                            <tr>
                                <td>${p.port}</td>
                                <td>${p.service}</td>
                                <td style="color:#888;font-size:0.8em">${p.banner}</td>
                                <td><span class="badge danger">OPEN</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`;
        }
        else if (tid === 2) {
            html += `<ul class="report-list">
                ${Object.entries(data).map(([k, v]) => `<li><span class="key">${k.toUpperCase()}</span><span class="value">${v}</span></li>`).join('')}
            </ul>`;
        }
        else if (tid === 3) {
            html += Object.entries(data).map(([type, recs]) => `
                <h3 style="color:var(--primary);margin-top:1rem">${type}</h3>
                <ul class="report-list">${recs.map(r => `<li>${r}</li>`).join('')}</ul>
            `).join('');
        }
        else if (tid === 4) {
            const activeCount = data.active_count || 0;
            const totalFound = data.total_found || 0;
            const totalChecked = data.total_checked || 0;
            const method = data.method || 'unknown';

            html += `
            <div style="display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
                <div class="badge success">FOUND: ${activeCount}</div>
                <div class="badge info">DISCOVERED: ${totalFound}</div>
                <div class="badge warning">CHECKED: ${totalChecked}</div>
                <div class="badge ${method === 'gobuster' ? 'success' : 'info'}" style="margin-left:auto">
                    ${method === 'gobuster' ? '⚡ GOBUSTER' : '🐍 PYTHON'}
                </div>
            </div>`;

            if (activeCount === 0) {
                html += `<div class="vuln-card" style="border-color:#888">
                    <h4 style="color:#888">NO SUBDOMAINS FOUND</h4>
                    <p style="color:#666;margin-top:0.5rem">No subdomains resolved via DNS</p>
                </div>`;
            } else {
                html += `<h3>${activeCount} ACTIVE SUBDOMAINS</h3>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:1rem">
                    ${data.subdomains.map(s => {
                    let borderColor = '#0f9';
                    let statusColor = '#0f9';

                    if (s.http_status === 0) {
                        borderColor = '#888';
                        statusColor = '#888';
                    } else if (s.http_status >= 200 && s.http_status < 300) {
                        borderColor = '#0f9';
                        statusColor = '#0f9';
                    } else if (s.http_status >= 300 && s.http_status < 400) {
                        borderColor = '#00b8ff';
                        statusColor = '#00b8ff';
                    } else if (s.http_status >= 400 && s.http_status < 500) {
                        borderColor = '#ffbd2e';
                        statusColor = '#ffbd2e';
                    } else if (s.http_status >= 500) {
                        borderColor = '#ff5f56';
                        statusColor = '#ff5f56';
                    }

                    return `
                            <div style="background:#222;padding:10px;border-left:3px solid ${borderColor}">
                                <div style="font-weight:bold;font-size:0.9em">${s.subdomain}</div>
                                <div style="font-size:0.75em;color:${statusColor};margin-top:3px">
                                    ✓ ${s.status}
                                </div>
                            </div>
                        `;
                }).join('')}
                </div>`;
            }
        }
        else if (tid === 6) {
            html += `<ul class="report-list">
                <li><span class="key">ISSUER</span><span class="value">${data.issuer?.commonName || 'Unknown'}</span></li>
                <li><span class="key">SUBJECT</span><span class="value">${data.subject?.commonName || 'Unknown'}</span></li>
                <li><span class="key">EXPIRES</span><span class="value">${data.expires}</span></li>
                <li><span class="key">SERIAL</span><span class="value">${data.serial}</span></li>
            </ul>`;
        }
        else if (tid === 7) {
            html += `<table class="report-table">
                <thead><tr><th>HEADER</th><th>STATUS</th><th>RISK</th></tr></thead>
                <tbody>
                    ${data.headers.map(h => `
                        <tr>
                            <td>${h.header}</td>
                            <td><span class="badge ${h.status === 'Present' ? 'success' : 'danger'}">${h.status}</span></td>
                            <td><span class="badge ${h.risk === 'Low' ? 'success' : 'warning'}">${h.risk}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>`;
        }
        else if (tid === 8) {
            html += `<h3>ROBOTS.TXT ENTRIES</h3>
            <div style="background:#222;padding:1rem;margin-top:1rem;font-family:monospace">
                ${data.found ? data.entries.map(e => `<div style="color:${e.startsWith('Disallow') ? '#ff5f56' : '#0f9'}">${e}</div>`).join('') : 'No robots.txt found'}
            </div>`;
        }
        else if (tid === 9) {
            const socialMedia = data.social_media || {};
            const totalFound = data.total_found || 0;

            // Platform icons and colors
            const platformConfig = {
                telegram: { icon: '✈️', color: '#0088cc', name: 'Telegram' },
                instagram: { icon: '📷', color: '#E4405F', name: 'Instagram' },
                vk: { icon: '🔵', color: '#4680C2', name: 'VKontakte' },
                facebook: { icon: '👤', color: '#1877F2', name: 'Facebook' },
                twitter: { icon: '🐦', color: '#1DA1F2', name: 'Twitter/X' },
                youtube: { icon: '▶️', color: '#FF0000', name: 'YouTube' },
                linkedin: { icon: '💼', color: '#0A66C2', name: 'LinkedIn' },
                tiktok: { icon: '🎵', color: '#000000', name: 'TikTok' },
                github: { icon: '🔗', color: '#333', name: 'GitHub' },
                whatsapp: { icon: '💬', color: '#25D366', name: 'WhatsApp' }
            };

            html += `
            <div style="display:flex;gap:1rem;margin-bottom:1rem">
                <div class="badge ${totalFound > 0 ? 'success' : 'warning'}">FOUND: ${totalFound} PROFILES</div>
            </div>`;

            if (totalFound === 0) {
                html += `<div class="vuln-card" style="border-color:#888">
                    <h4 style="color:#888">NO SOCIAL MEDIA FOUND</h4>
                    <p style="color:#666;margin-top:0.5rem">No social media profiles detected on this page</p>
                </div>`;
            } else {
                // Display each platform
                for (const [platform, profiles] of Object.entries(socialMedia)) {
                    if (profiles && profiles.length > 0) {
                        const config = platformConfig[platform] || { icon: '🔗', color: '#00b8ff', name: platform.toUpperCase() };

                        html += `
                        <div class="vuln-card" style="border-color:${config.color};margin-top:1rem;background:rgba(0,184,255,0.05)">
                            <h4 style="color:${config.color}">${config.icon} ${config.name.toUpperCase()} (${profiles.length})</h4>
                            <ul class="report-list" style="margin-top:0.5rem">
                                ${profiles.map(url => `
                                    <li>
                                        <a href="${url}" target="_blank" style="color:${config.color};text-decoration:none;font-family:monospace;font-size:0.9em">
                                            ${url}
                                        </a>
                                    </li>
                                `).join('')}
                            </ul>
                        </div>`;
                    }
                }
            }
        }
        else if ([10, 11].includes(tid)) {
            const items = data.directories || data.backups;
            if (!items || items.length === 0) html += `<div class="vuln-card" style="border-color:green"><h4 style="color:green">NO SENSITIVE FILES FOUND</h4></div>`;
            else {
                html += `<table class="report-table">
                    <thead><tr><th>PATH</th><th>STATUS</th><th>LINK</th></tr></thead>
                    <tbody>
                        ${items.map(i => `
                            <tr>
                                <td>${i.path || i.file}</td>
                                <td><span class="badge warning">${i.status || 'FOUND'}</span></td>
                                <td><a href="${i.url}" target="_blank" style="color:var(--primary)">OPEN</a></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`;
            }
        }
        else if (tid === 12) {
            const vulnerable = data.vulnerable || false;
            const riskLevel = data.risk_level || 'Safe';
            const issues = data.issues || [];
            const headersFound = data.headers_found || {};
            const totalIssues = data.total_issues || 0;

            // Color coding based on risk
            let riskColor = 'green';
            if (riskLevel === 'HIGH') riskColor = '#ff5f56';
            else if (riskLevel === 'MEDIUM') riskColor = '#ffbd2e';

            html += `
            <div class="vuln-card" style="border-color:${riskColor}">
                <h4 style="color:${riskColor}">${vulnerable ? '⚠️ CLICKJACKING VULNERABILITY' : '✓ PROTECTED AGAINST CLICKJACKING'}</h4>
                <div style="margin-top:0.5rem">
                    <span class="badge ${riskLevel === 'HIGH' ? 'danger' : riskLevel === 'MEDIUM' ? 'warning' : 'success'}">
                        RISK: ${riskLevel}
                    </span>
                </div>
                <p style="margin-top:1rem;color:#ccc">${data.description}</p>
            </div>`;

            // Display found headers
            if (Object.keys(headersFound).length > 0) {
                html += `
                <h3 style="margin-top:1.5rem">PROTECTION HEADERS FOUND</h3>
                <table class="report-table" style="margin-top:1rem">
                    <thead><tr><th>HEADER</th><th>VALUE</th></tr></thead>
                    <tbody>
                        ${Object.entries(headersFound).map(([header, value]) => `
                            <tr>
                                <td style="font-family:monospace;font-size:0.85em">${header}</td>
                                <td style="font-family:monospace;font-size:0.85em">${value}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`;
            }

            // Display issues
            if (issues.length > 0) {
                html += `<h3 style="margin-top:1.5rem">${issues.length} CLICKJACKING ISSUES</h3>`;

                issues.forEach(issue => {
                    let issueColor = '#00b8ff';
                    if (issue.severity === 'HIGH') issueColor = '#ff5f56';
                    else if (issue.severity === 'MEDIUM') issueColor = '#ffbd2e';

                    html += `
                    <div class="vuln-card" style="border-color:${issueColor};margin-top:1rem;background:rgba(255,95,86,0.05)">
                        <h4 style="color:${issueColor}">${issue.type}</h4>
                        <div style="margin-top:0.5rem">
                            <span class="badge ${issue.severity === 'HIGH' ? 'danger' : issue.severity === 'MEDIUM' ? 'warning' : 'info'}">
                                ${issue.severity}
                            </span>
                        </div>
                        <p style="margin-top:1rem;color:#ccc"><strong>Description:</strong> ${issue.description}</p>
                        <p style="margin-top:0.5rem;color:#ccc"><strong>Impact:</strong> ${issue.impact}</p>
                        <p style="margin-top:0.5rem;color:#0f9"><strong>Recommendation:</strong> ${issue.recommendation}</p>
                    </div>`;
                });

                // Remediation advice
                html += `
                <div class="vuln-card" style="border-color:#ffbd2e;margin-top:1rem;background:rgba(255,189,46,0.1)">
                    <h4 style="color:#ffbd2e">⚠️ HOW CLICKJACKING WORKS</h4>
                    <p style="margin-top:0.5rem;color:#ccc">
                        Clickjacking tricks users into clicking on hidden elements by embedding your site in an invisible iframe.<br><br>
                        <strong>Attack scenario:</strong><br>
                        1. Attacker creates malicious page with invisible iframe containing your site<br>
                        2. User thinks they're clicking on attacker's content<br>
                        3. Actually clicking on your site's buttons (delete account, transfer money, etc.)<br><br>
                        <strong>Prevention:</strong><br>
                        • Add <code style="background:#222;padding:2px 6px">X-Frame-Options: DENY</code> header<br>
                        • Or use <code style="background:#222;padding:2px 6px">Content-Security-Policy: frame-ancestors 'none'</code><br>
                        • Use SAMEORIGIN if you need to embed on same domain
                    </p>
                </div>`;
            }
        }
        else if (tid === 16) { // Directory Traversal Tester
            const vulns = data.vulnerable_urls || [];
            const riskLevel = data.risk_level || 'Safe';

            // Color coding based on risk
            let riskColor = 'green';
            if (riskLevel === 'HIGH') riskColor = '#ff5f56';

            html += `
            <div class="vuln-card" style="border-color:${riskColor}">
                <h4 style="color:${riskColor}">${riskLevel === 'HIGH' ? '⚠️ DIRECTORY TRAVERSAL VULNERABILITY' : '✓ NO TRAVERSAL DETECTED'}</h4>
                <div style="margin-top:0.5rem">
                    <span class="badge ${riskLevel === 'HIGH' ? 'danger' : 'success'}">
                        RISK: ${riskLevel}
                    </span>
                </div>
                <p style="margin-top:1rem;color:#ccc">${data.description}</p>
            </div>`;

            if (vulns.length > 0) {
                html += `<h3 style="margin-top:1.5rem">${vulns.length} VULNERABLE URLS</h3>`;

                vulns.forEach(v => {
                    html += `
                    <div class="vuln-card" style="border-color:#ff5f56;margin-top:1rem;background:rgba(255,95,86,0.05)">
                        <h4 style="color:#ff5f56">PATH TRAVERSAL</h4>
                        <div style="margin-top:0.5rem">
                            <span class="badge danger">CRITICAL</span>
                        </div>
                        <p style="margin-top:1rem;color:#ccc"><strong>URL:</strong> <a href="${v.url}" target="_blank" style="color:#0f9">${v.url}</a></p>
                        <p style="margin-top:0.5rem;color:#ccc"><strong>Status:</strong> ${v.status}</p>
                        <div style="margin-top:0.5rem;background:#111;padding:0.5rem;border-radius:4px">
                            <code style="color:#0f9;font-family:monospace;font-size:0.85em">${v.snippet}</code>
                        </div>
                    </div>`;
                });
            }
        }
        else if (tid === 13) {
            const exposed = data.exposed || false;
            const riskLevel = data.risk_level || 'Safe';
            const files = data.accessible_files || [];
            const githubUsers = data.github_users || [];
            const githubRepos = data.github_repos || [];
            const emails = data.emails || [];

            // Color coding based on risk
            let riskColor = 'green';
            if (riskLevel === 'CRITICAL') riskColor = '#ff5f56';
            else if (riskLevel === 'HIGH') riskColor = '#ffbd2e';
            else if (riskLevel === 'MEDIUM') riskColor = '#00b8ff';

            html += `
            <div class="vuln-card" style="border-color:${riskColor}">
                <h4 style="color:${riskColor}">${exposed ? '⚠️ GIT EXPOSURE DETECTED' : '✓ NO GIT EXPOSURE'}</h4>
                <div style="margin-top:0.5rem">
                    <span class="badge ${riskLevel === 'CRITICAL' ? 'danger' : riskLevel === 'HIGH' ? 'warning' : riskLevel === 'MEDIUM' ? 'info' : 'success'}">
                        RISK: ${riskLevel}
                    </span>
                </div>
                <p style="margin-top:1rem;color:#ccc">${data.description}</p>
            </div>`;

            // GitHub Users Section
            if (githubUsers.length > 0) {
                html += `
                <div class="vuln-card" style="border-color:#ff5f56;margin-top:1rem;background:rgba(255,95,86,0.1)">
                    <h4 style="color:#ff5f56">👤 DISCOVERED GITHUB USERS (${githubUsers.length})</h4>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:1rem">
                        ${githubUsers.map(user => `
                            <a href="https://github.com/${user}" target="_blank" 
                               style="background:#2d2d2d;padding:8px 15px;border-radius:5px;color:#00b8ff;text-decoration:none;border:1px solid #00b8ff">
                                <span style="margin-right:5px">🔗</span>${user}
                            </a>
                        `).join('')}
                    </div>
                </div>`;
            }

            // GitHub Repositories Section
            if (githubRepos.length > 0) {
                html += `
                <div class="vuln-card" style="border-color:#00b8ff;margin-top:1rem;background:rgba(0,184,255,0.1)">
                    <h4 style="color:#00b8ff">📦 RELATED GITHUB REPOSITORIES (${githubRepos.length})</h4>
                    <ul class="report-list" style="margin-top:0.5rem">
                        ${githubRepos.map(repo => `
                            <li>
                                <a href="https://github.com/${repo}" target="_blank" style="color:#00b8ff;text-decoration:none">
                                    <span style="margin-right:5px">📁</span>${repo}
                                </a>
                            </li>
                        `).join('')}
                    </ul>
                </div>`;
            }

            // Emails Section
            if (emails.length > 0) {
                html += `
                <div class="vuln-card" style="border-color:#ffbd2e;margin-top:1rem;background:rgba(255,189,46,0.1)">
                    <h4 style="color:#ffbd2e">📧 DISCOVERED EMAILS (${emails.length})</h4>
                    <ul class="report-list" style="margin-top:0.5rem">
                        ${emails.map(email => `<li style="font-family:monospace">${email}</li>`).join('')}
                    </ul>
                </div>`;
            }

            if (files.length > 0) {
                html += `<h3 style="margin-top:1.5rem">${files.length} ACCESSIBLE .GIT FILES</h3>
                <table class="report-table" style="margin-top:1rem">
                    <thead><tr><th>FILE</th><th>SIZE</th><th>CRITICAL</th><th>LINK</th></tr></thead>
                    <tbody>
                        ${files.map(f => `
                            <tr>
                                <td style="font-family:monospace;font-size:0.85em">${f.file}</td>
                                <td>${f.size} bytes</td>
                                <td><span class="badge ${f.critical ? 'danger' : 'warning'}">${f.critical ? 'YES' : 'NO'}</span></td>
                                <td><a href="${f.url}" target="_blank" style="color:var(--primary)">VIEW</a></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <div class="vuln-card" style="border-color:#ffbd2e;margin-top:1rem;background:rgba(255,189,46,0.1)">
                    <h4 style="color:#ffbd2e">⚠️ REMEDIATION</h4>
                    <p style="margin-top:0.5rem;color:#ccc">
                        • Block access to .git directory in web server configuration<br>
                        • Add deny rules in .htaccess or nginx.conf<br>
                        • Never deploy .git folders to production servers<br>
                        • Rotate credentials if developer emails/usernames are exposed
                    </p>
                </div>`;
            }
        }
        else if (tid === 14) {
            const vulns = data.vulnerabilities || [];
            const corsHeaders = data.cors_headers || {};
            const riskLevel = data.risk_level || 'Safe';
            const totalFound = data.total_found || 0;

            // Color coding based on risk
            let riskColor = 'green';
            if (riskLevel === 'CRITICAL') riskColor = '#ff5f56';
            else if (riskLevel === 'HIGH') riskColor = '#ffbd2e';
            else if (riskLevel === 'MEDIUM') riskColor = '#00b8ff';

            html += `
            <div class="vuln-card" style="border-color:${riskColor}">
                <h4 style="color:${riskColor}">${totalFound > 0 ? '⚠️ CORS MISCONFIGURATION DETECTED' : '✓ SECURE CORS POLICY'}</h4>
                <div style="margin-top:0.5rem">
                    <span class="badge ${riskLevel === 'CRITICAL' ? 'danger' : riskLevel === 'HIGH' ? 'warning' : riskLevel === 'MEDIUM' ? 'info' : 'success'}">
                        RISK: ${riskLevel}
                    </span>
                </div>
                <p style="margin-top:1rem;color:#ccc">${data.description}</p>
            </div>`;

            // Display CORS headers
            if (Object.keys(corsHeaders).length > 0) {
                html += `
                <h3 style="margin-top:1.5rem">DETECTED CORS HEADERS</h3>
                <table class="report-table" style="margin-top:1rem">
                    <thead><tr><th>HEADER</th><th>VALUE</th></tr></thead>
                    <tbody>
                        ${Object.entries(corsHeaders).map(([header, value]) => `
                            <tr>
                                <td style="font-family:monospace;font-size:0.85em">${header}</td>
                                <td style="font-family:monospace;font-size:0.85em">${value}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`;
            }

            // Display vulnerabilities
            if (vulns.length > 0) {
                html += `<h3 style="margin-top:1.5rem">${vulns.length} CORS VULNERABILITIES</h3>`;

                vulns.forEach(v => {
                    let vulnColor = '#00b8ff';
                    if (v.severity === 'CRITICAL') vulnColor = '#ff5f56';
                    else if (v.severity === 'HIGH') vulnColor = '#ffbd2e';

                    html += `
                    <div class="vuln-card" style="border-color:${vulnColor};margin-top:1rem;background:rgba(255,95,86,0.05)">
                        <h4 style="color:${vulnColor}">${v.type}</h4>
                        <div style="margin-top:0.5rem">
                            <span class="badge ${v.severity === 'CRITICAL' ? 'danger' : v.severity === 'HIGH' ? 'warning' : 'info'}">
                                ${v.severity}
                            </span>
                        </div>
                        <p style="margin-top:1rem;color:#ccc"><strong>Description:</strong> ${v.description}</p>
                        <p style="margin-top:0.5rem;color:#ccc"><strong>Header:</strong> <code style="background:#222;padding:2px 6px;border-radius:3px">${v.header}</code></p>
                        <p style="margin-top:0.5rem;color:#ccc"><strong>Impact:</strong> ${v.impact}</p>
                        ${v.dangerous_methods ? `<p style="margin-top:0.5rem;color:#ffbd2e"><strong>Dangerous Methods:</strong> ${v.dangerous_methods.join(', ')}</p>` : ''}
                    </div>`;
                });

                // Remediation advice
                html += `
                <div class="vuln-card" style="border-color:#ffbd2e;margin-top:1rem;background:rgba(255,189,46,0.1)">
                    <h4 style="color:#ffbd2e">⚠️ REMEDIATION</h4>
                    <p style="margin-top:0.5rem;color:#ccc">
                        • Never use wildcard (*) with Access-Control-Allow-Credentials<br>
                        • Whitelist specific trusted origins instead of reflecting all origins<br>
                        • Avoid allowing 'null' origin<br>
                        • Restrict Access-Control-Allow-Methods to necessary methods only<br>
                        • Validate and sanitize Origin header before reflecting it
                    </p>
                </div>`;
            }
        }
        else if (tid === 15) {
            const vulns = data.vulnerabilities;
            if (!vulns || vulns.length === 0) html += `<div class="vuln-card" style="border-color:green"><h4 style="color:green">NO VULNERABILITIES FOUND</h4></div>`;
            else {
                html += vulns.map(v => `
                    <div class="vuln-card">
                        <h4>OPEN REDIRECT DETECTED</h4>
                        <div><span class="key">PARAM:</span> ${v.param}</div>
                        <div style="margin-top:5px"><a href="${v.url}" target="_blank" style="color:#fff;text-decoration:underline">TEST LINK</a></div>
                    </div>
                `).join('');
            }
        }
        else {
            html += `<pre style="background:#222;padding:1rem;overflow:auto">${JSON.stringify(data, null, 2)}</pre>`;
        }

        modalResult.innerHTML = html;
    }
});
