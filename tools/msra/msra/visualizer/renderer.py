"""Visualization renderer - generates HTML reports with interactive diagrams."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .analyzer import AppStructure
from .graphs import (
    Graph,
    ComponentGraph,
    CallGraph,
    DataFlowGraph,
    ClassHierarchyGraph,
    EntryPointGraph,
)


@dataclass
class VisualizationConfig:
    """Configuration for visualization rendering."""
    include_component_graph: bool = True
    include_call_graph: bool = True
    include_data_flow: bool = True
    include_class_hierarchy: bool = True
    include_entry_points: bool = True
    include_statistics: bool = True
    include_attack_surface: bool = True  # New: Attack surface with ADB commands
    include_injection_points: bool = True  # New: Injection point detection
    include_frida_scripts: bool = True  # New: Frida hook scripts
    dark_mode: bool = False
    max_classes_in_hierarchy: int = 50


class VisualizationRenderer:
    """Renders application visualizations as HTML."""

    def __init__(self, structure: AppStructure, config: Optional[VisualizationConfig] = None):
        self.structure = structure
        self.config = config or VisualizationConfig()
        self.graphs: Dict[str, Graph] = {}

    def build_graphs(self) -> None:
        """Build all configured graphs."""
        if self.config.include_component_graph:
            self.graphs['components'] = ComponentGraph(self.structure)

        if self.config.include_call_graph:
            self.graphs['calls'] = CallGraph(self.structure)

        if self.config.include_data_flow:
            self.graphs['data_flow'] = DataFlowGraph(self.structure)

        if self.config.include_class_hierarchy:
            self.graphs['hierarchy'] = ClassHierarchyGraph(self.structure)

        if self.config.include_entry_points:
            self.graphs['entry_points'] = EntryPointGraph(self.structure)

    def render_html(self, output_path: str) -> str:
        """Render complete HTML visualization."""
        self.build_graphs()

        html_content = self._generate_html()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path


    def _generate_html(self) -> str:
        """Generate HTML content."""
        stats = self._calculate_statistics()

        # Build sections
        sections = []

        # Statistics section
        if self.config.include_statistics:
            sections.append(self._render_statistics_section(stats))

        # Entry Points section
        if 'entry_points' in self.graphs:
            sections.append(self._render_graph_section(
                'entry_points',
                'Attack Surface & Entry Points',
                'Shows all external entry points an attacker could use to interact with the application.',
                self.graphs['entry_points'],
            ))

        # Component Graph section
        if 'components' in self.graphs:
            sections.append(self._render_graph_section(
                'components',
                'Component Interactions',
                'Shows Android components (Activities, Services, Receivers, Providers) and their interactions.',
                self.graphs['components'],
            ))

        # Data Flow section
        if 'data_flow' in self.graphs:
            sections.append(self._render_graph_section(
                'data_flow',
                'Data Flow Analysis',
                'Shows how data flows through the application from sources to sinks.',
                self.graphs['data_flow'],
            ))
            # Add detailed data flow table with parameters
            sections.append(self._render_data_flow_details())

        # Call Graph section
        if 'calls' in self.graphs:
            sections.append(self._render_graph_section(
                'calls',
                'Call Graph',
                'Shows method call relationships between classes.',
                self.graphs['calls'],
            ))

        # Class Hierarchy section
        if 'hierarchy' in self.graphs:
            sections.append(self._render_graph_section(
                'hierarchy',
                'Class Hierarchy',
                'Shows class inheritance and interface implementations.',
                self.graphs['hierarchy'],
            ))

        # Component details section
        sections.append(self._render_component_details())

        # Entry points details section
        sections.append(self._render_entry_points_details())

        # Attack Surface with ADB commands
        if self.config.include_attack_surface:
            sections.append(self._render_attack_surface_section())

        # Injection Points
        if self.config.include_injection_points:
            sections.append(self._render_injection_points_section())

        # Frida Scripts
        if self.config.include_frida_scripts:
            sections.append(self._render_frida_scripts_section())

        return self._html_template(
            title=f"Application Visualization - {self.structure.package_name}",
            sections='\n'.join(sections),
            stats=stats,
        )

    def _calculate_statistics(self) -> Dict:
        """Calculate application statistics."""
        stats = {
            'package_name': self.structure.package_name,
            'total_classes': len(self.structure.classes),
            'activities': sum(1 for c in self.structure.classes.values() if c.is_activity),
            'services': sum(1 for c in self.structure.classes.values() if c.is_service),
            'receivers': sum(1 for c in self.structure.classes.values() if c.is_receiver),
            'providers': sum(1 for c in self.structure.classes.values() if c.is_provider),
            'fragments': sum(1 for c in self.structure.classes.values() if c.is_fragment),
            'total_methods': sum(len(c.methods) for c in self.structure.classes.values()),
            'exported_components': sum(1 for c in self.structure.components.values() if c.exported),
            'total_components': len(self.structure.components),
            'permissions': len(self.structure.permissions),
            'entry_points': len(self.structure.entry_points),
            'data_flows': len(self.structure.data_flows),
            'intents': len(self.structure.intents),
        }
        return stats

    def _render_statistics_section(self, stats: Dict) -> str:
        """Render statistics section."""
        return f'''
        <section id="statistics" class="section">
            <h2>Application Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_classes']}</div>
                    <div class="stat-label">Classes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['activities']}</div>
                    <div class="stat-label">Activities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['services']}</div>
                    <div class="stat-label">Services</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['receivers']}</div>
                    <div class="stat-label">Receivers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['providers']}</div>
                    <div class="stat-label">Providers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['fragments']}</div>
                    <div class="stat-label">Fragments</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-value">{stats['exported_components']}</div>
                    <div class="stat-label">Exported Components</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['entry_points']}</div>
                    <div class="stat-label">Entry Points</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['permissions']}</div>
                    <div class="stat-label">Permissions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['total_methods']}</div>
                    <div class="stat-label">Methods</div>
                </div>
            </div>
        </section>
        '''

    def _render_graph_section(self, graph_id: str, title: str, description: str, graph: Graph) -> str:
        """Render a graph section."""
        mermaid_code = graph.to_mermaid()

        return f'''
        <section id="{graph_id}" class="section">
            <h2>{title}</h2>
            <p class="description">{description}</p>
            <div class="diagram-container">
                <pre class="mermaid">
{mermaid_code}
                </pre>
            </div>
        </section>
        '''

    def _render_component_details(self) -> str:
        """Render detailed component information."""
        rows = []

        for name, comp in sorted(self.structure.components.items()):
            short_name = name.split('.')[-1]
            exported_badge = '<span class="badge danger">EXPORTED</span>' if comp.exported else '<span class="badge">internal</span>'
            permission_badge = f'<span class="badge info">{comp.permission}</span>' if comp.permission else ''

            # Intent filters
            filters = []
            for f in comp.intent_filters:
                actions = ', '.join(f.get('actions', []))
                if actions:
                    filters.append(f"Actions: {actions}")
                for data in f.get('data', []):
                    scheme = data.get('scheme', '')
                    host = data.get('host', '')
                    if scheme:
                        filters.append(f"URI: {scheme}://{host}")

            filter_html = '<br>'.join(filters) if filters else '-'

            rows.append(f'''
                <tr>
                    <td><code>{short_name}</code></td>
                    <td>{comp.type}</td>
                    <td>{exported_badge} {permission_badge}</td>
                    <td class="small">{filter_html}</td>
                </tr>
            ''')

        return f'''
        <section id="component-details" class="section">
            <h2>Component Details</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Intent Filters</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        '''

    def _render_entry_points_details(self) -> str:
        """Render entry points details."""
        rows = []

        for entry in self.structure.entry_points:
            parts = entry.split(':', 1)
            entry_type = parts[0]
            entry_name = parts[1] if len(parts) > 1 else entry

            type_badges = {
                'launcher': '<span class="badge success">LAUNCHER</span>',
                'activity': '<span class="badge warning">ACTIVITY</span>',
                'service': '<span class="badge info">SERVICE</span>',
                'receiver': '<span class="badge">RECEIVER</span>',
                'provider': '<span class="badge danger">PROVIDER</span>',
                'deeplink': '<span class="badge warning">DEEPLINK</span>',
            }

            badge = type_badges.get(entry_type, f'<span class="badge">{entry_type}</span>')

            rows.append(f'''
                <tr>
                    <td>{badge}</td>
                    <td><code>{entry_name}</code></td>
                </tr>
            ''')

        return f'''
        <section id="entry-points-details" class="section">
            <h2>Entry Points</h2>
            <p class="description">These are the external entry points where attackers can interact with the application.</p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Entry Point</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        '''

    def _render_data_flow_details(self) -> str:
        """Render detailed data flow table with parameters for pentesting."""
        if not self.structure.data_flows:
            return ''

        # Sort by risk level
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_flows = sorted(
            self.structure.data_flows,
            key=lambda f: risk_order.get(f.risk_level, 2)
        )

        rows = []
        risk_badges = {
            'critical': '<span class="badge danger">CRITICAL</span>',
            'high': '<span class="badge warning">HIGH</span>',
            'medium': '<span class="badge info">MEDIUM</span>',
            'low': '<span class="badge">LOW</span>',
        }

        for flow in sorted_flows[:30]:  # Limit to 30 flows
            risk_badge = risk_badges.get(flow.risk_level, '<span class="badge">MEDIUM</span>')
            user_badge = '<span class="badge danger">USER</span>' if flow.is_user_controllable else ''

            # Format parameters
            params_html = ''
            if flow.parameters:
                escaped_params = [html.escape(p) for p in flow.parameters[:5]]
                params_html = '<code>' + '</code>, <code>'.join(escaped_params) + '</code>'
            else:
                params_html = '<span class="text-muted">-</span>'

            # Format taint chain
            taint_html = ''
            if flow.taint_chain:
                escaped_taint = [html.escape(t) for t in flow.taint_chain[:5]]
                taint_html = ' → '.join(f'<code>{t}</code>' for t in escaped_taint)
            else:
                taint_html = '<span class="text-muted">-</span>'

            rows.append(f'''
                <tr class="filterable" data-risk="{flow.risk_level}" data-category="data-flow" data-source="{html.escape(flow.source)}">
                    <td>{risk_badge} {user_badge}</td>
                    <td><span class="source-tag">{html.escape(flow.source)}</span> → <span class="sink-tag">{html.escape(flow.sink)}</span></td>
                    <td><code class="method">{html.escape(flow.source_method)}</code></td>
                    <td><code class="method">{html.escape(flow.sink_method)}</code></td>
                    <td class="params-cell">{params_html}</td>
                    <td class="taint-cell">{taint_html}</td>
                </tr>
            ''')

        return f'''
        <section id="data-flow-details" class="section filterable-section" data-section="data-flow">
            <h2>📊 Data Flow Details</h2>
            <p class="description">Detailed data flow analysis showing source-to-sink paths, parameters, and taint propagation for security testing.</p>
            <div class="table-container">
                <table class="data-flow-table filterable-table">
                    <thead>
                        <tr>
                            <th>Risk</th>
                            <th>Flow</th>
                            <th>Source Method</th>
                            <th>Sink Method</th>
                            <th>Parameters</th>
                            <th>Taint Chain</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        '''

    def _render_attack_surface_section(self) -> str:
        """Render attack surface section with ADB commands."""
        if not self.structure.attack_surfaces:
            return ''

        cards = []
        for surface in self.structure.attack_surfaces:
            if not surface.exported and surface.permission:
                continue  # Skip non-exported protected components

            # Component type badge
            type_colors = {
                'activity': 'warning',
                'service': 'info',
                'receiver': 'success',
                'provider': 'danger',
            }
            color = type_colors.get(surface.component_type, '')

            # Deep links (escape HTML)
            deep_links_html = ''
            if surface.deep_links:
                links = ''.join(f'<li><code>{html.escape(link)}</code></li>' for link in surface.deep_links[:5])
                deep_links_html = f'''
                <div class="attack-section">
                    <h5>🔗 Deep Links</h5>
                    <ul>{links}</ul>
                </div>'''

            # ADB commands (escape HTML to prevent XSS)
            adb_html = ''
            if surface.adb_commands:
                cmds = ''.join(f'''
                    <div class="adb-command">
                        <code>{html.escape(cmd)}</code>
                        <button class="copy-btn" onclick="copyToClipboard(this)">📋</button>
                    </div>''' for cmd in surface.adb_commands[:5])
                adb_html = f'''
                <div class="attack-section">
                    <h5>⚡ ADB Commands</h5>
                    {cmds}
                </div>'''

            # Frida hooks (escape HTML)
            frida_html = ''
            if surface.frida_hooks:
                hook = html.escape(surface.frida_hooks[0]) if surface.frida_hooks else ''
                frida_html = f'''
                <div class="attack-section">
                    <h5>🪝 Frida Hook</h5>
                    <pre class="frida-code"><code>{hook}</code></pre>
                </div>'''

            cards.append(f'''
            <div class="attack-card">
                <div class="attack-header">
                    <span class="badge {color}">{html.escape(surface.component_type.upper())}</span>
                    <span class="component-name">{html.escape(surface.component_name.split(".")[-1])}</span>
                    {'<span class="badge danger">EXPORTED</span>' if surface.exported else ''}
                </div>
                <div class="attack-body">
                    <p class="full-name"><code>{html.escape(surface.component_name)}</code></p>
                    {deep_links_html}
                    {adb_html}
                    {frida_html}
                </div>
            </div>
            ''')

        return f'''
        <section id="attack-surface" class="section">
            <h2>🎯 Attack Surface</h2>
            <p class="description">Exported components with ready-to-use ADB commands for penetration testing.</p>
            <div class="attack-grid">
                {''.join(cards)}
            </div>
        </section>
        '''

    def _render_injection_points_section(self) -> str:
        """Render injection points section."""
        if not self.structure.injection_points:
            return ''

        rows = []
        type_badges = {
            'sql': '<span class="badge danger">SQL</span>',
            'path': '<span class="badge warning">PATH</span>',
            'command': '<span class="badge danger">CMD</span>',
            'xss': '<span class="badge warning">XSS</span>',
            'intent': '<span class="badge info">INTENT</span>',
        }

        risk_map = {'sql': 'high', 'command': 'high', 'path': 'medium', 'xss': 'medium', 'intent': 'medium'}

        for point in self.structure.injection_points[:20]:  # Limit to 20
            badge = type_badges.get(point.injection_type, f'<span class="badge">{html.escape(point.injection_type)}</span>')
            risk = risk_map.get(point.injection_type, 'medium')

            rows.append(f'''
                <tr class="filterable" data-risk="{risk}" data-category="injection" data-type="{html.escape(point.injection_type)}">
                    <td>{badge}</td>
                    <td><code>{html.escape(point.class_name.split(".")[-1])}</code></td>
                    <td>Line {point.line_number}</td>
                    <td><code class="sink">{html.escape(point.sink_method)}</code></td>
                    <td><code class="exploit">{html.escape(point.exploit_example)}</code></td>
                </tr>
            ''')

        return f'''
        <section id="injection-points" class="section filterable-section" data-section="injection">
            <h2>💉 Potential Injection Points</h2>
            <p class="description">Locations where user-controlled input may reach dangerous sinks.</p>
            <div class="table-container">
                <table class="filterable-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Class</th>
                            <th>Location</th>
                            <th>Sink</th>
                            <th>Exploit Example</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        '''

    def _render_frida_scripts_section(self) -> str:
        """Render Frida scripts section."""
        if not self.structure.frida_scripts:
            return ''

        tabs = []
        contents = []

        for i, (name, script) in enumerate(self.structure.frida_scripts.items()):
            active = 'active' if i == 0 else ''
            display_name = name.replace('_', ' ').title()

            tabs.append(f'''
                <button class="tab-btn {active}" onclick="showFridaTab('{html.escape(name)}')">{html.escape(display_name)}</button>
            ''')

            contents.append(f'''
                <div id="frida-{html.escape(name)}" class="tab-content {active}">
                    <div class="script-header">
                        <span>{html.escape(display_name)}</span>
                        <button class="copy-btn" onclick="copyScript('{html.escape(name)}')">📋 Copy Script</button>
                    </div>
                    <pre class="frida-script"><code id="script-{html.escape(name)}">{html.escape(script)}</code></pre>
                </div>
            ''')

        return f'''
        <section id="frida-scripts" class="section">
            <h2>🪝 Frida Scripts</h2>
            <p class="description">Ready-to-use Frida scripts for dynamic analysis and hooking.</p>
            <div class="frida-container">
                <div class="tab-buttons">
                    {''.join(tabs)}
                </div>
                <div class="tab-contents">
                    {''.join(contents)}
                </div>
            </div>
        </section>
        '''

    def _html_template(self, title: str, sections: str, stats: Dict) -> str:
        """Generate complete HTML template."""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --accent-color: #0d6efd;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --success-color: #198754;
            --info-color: #0dcaf0;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
        }}

        header .package {{
            opacity: 0.9;
            font-family: monospace;
            font-size: 1.1rem;
        }}

        .nav {{
            background: var(--bg-primary);
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .nav a {{
            color: var(--accent-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 4px;
            transition: background 0.2s;
        }}

        .nav a:hover {{
            background: var(--bg-secondary);
        }}

        /* Filter Bar */
        .filter-bar {{
            background: var(--bg-primary);
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }}

        .filter-group {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .filter-group label {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 500;
        }}

        .filter-group select,
        .filter-group input {{
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 0.9rem;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-width: 120px;
        }}

        .filter-group input {{
            min-width: 180px;
        }}

        .filter-group select:focus,
        .filter-group input:focus {{
            outline: none;
            border-color: var(--accent-color);
            box-shadow: 0 0 0 2px rgba(13, 110, 253, 0.15);
        }}

        .filter-reset {{
            padding: 8px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            color: var(--text-primary);
            transition: background 0.2s;
        }}

        .filter-reset:hover {{
            background: var(--border-color);
        }}

        .filter-count {{
            margin-left: auto;
            font-size: 0.85rem;
            color: var(--text-secondary);
            background: var(--bg-secondary);
            padding: 6px 12px;
            border-radius: 20px;
        }}

        .filterable.hidden {{
            display: none;
        }}

        @media (max-width: 768px) {{
            .filter-bar {{
                flex-direction: column;
                align-items: stretch;
            }}
            .filter-group {{
                flex-direction: column;
                align-items: stretch;
            }}
            .filter-count {{
                margin-left: 0;
                text-align: center;
            }}
        }}

        .section {{
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section h2 {{
            color: var(--text-primary);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }}

        .description {{
            color: var(--text-secondary);
            margin-bottom: 20px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 15px;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card.warning {{
            background: #fff3cd;
            border: 1px solid var(--warning-color);
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-color);
        }}

        .stat-card.warning .stat-value {{
            color: #856404;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }}

        .diagram-container {{
            overflow-x: auto;
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
        }}

        .mermaid {{
            display: flex;
            justify-content: center;
        }}

        .table-container {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--bg-secondary);
            font-weight: 600;
        }}

        tr:hover {{
            background: var(--bg-secondary);
        }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            background: var(--bg-secondary);
            color: var(--text-secondary);
        }}

        .badge.danger {{
            background: #f8d7da;
            color: #842029;
        }}

        .badge.warning {{
            background: #fff3cd;
            color: #856404;
        }}

        .badge.success {{
            background: #d1e7dd;
            color: #0f5132;
        }}

        .badge.info {{
            background: #cff4fc;
            color: #055160;
        }}

        code {{
            background: var(--bg-secondary);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
        }}

        .small {{
            font-size: 0.85rem;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        /* Attack Surface Styles */
        .attack-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }}

        .attack-card {{
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}

        .attack-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .attack-header .badge {{
            background: rgba(255,255,255,0.2);
            color: white;
        }}

        .attack-header .component-name {{
            font-weight: 600;
            flex-grow: 1;
        }}

        .attack-body {{
            padding: 15px;
        }}

        .attack-body .full-name {{
            font-size: 0.85em;
            color: var(--text-secondary);
            margin-bottom: 15px;
            word-break: break-all;
        }}

        .attack-section {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }}

        .attack-section h5 {{
            font-size: 0.9rem;
            margin-bottom: 10px;
            color: var(--text-primary);
        }}

        .attack-section ul {{
            list-style: none;
            padding: 0;
        }}

        .attack-section li {{
            padding: 5px 0;
        }}

        .adb-command {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: #1e1e1e;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 8px;
        }}

        .adb-command code {{
            flex-grow: 1;
            color: #4ec9b0;
            background: transparent;
            font-size: 0.85em;
            word-break: break-all;
        }}

        .copy-btn {{
            background: transparent;
            border: none;
            cursor: pointer;
            padding: 5px;
            border-radius: 4px;
            transition: background 0.2s;
        }}

        .copy-btn:hover {{
            background: rgba(255,255,255,0.1);
        }}

        .frida-code {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.8em;
            max-height: 200px;
            overflow-y: auto;
        }}

        /* Injection Points Styles */
        .sink {{
            color: var(--danger-color);
        }}

        .exploit {{
            color: var(--warning-color);
            background: #1e1e1e;
        }}

        /* Data Flow Details Styles */
        .data-flow-table {{
            font-size: 0.9rem;
        }}

        .data-flow-table td {{
            vertical-align: top;
        }}

        .source-tag {{
            background: #d4edda;
            color: #155724;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .sink-tag {{
            background: #f8d7da;
            color: #721c24;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .method {{
            color: #6f42c1;
            font-size: 0.85rem;
            word-break: break-all;
        }}

        .params-cell code {{
            background: #e3f2fd;
            color: #1565c0;
            margin: 2px;
            display: inline-block;
        }}

        .taint-cell {{
            font-size: 0.85rem;
        }}

        .taint-cell code {{
            background: #fff3e0;
            color: #e65100;
        }}

        .text-muted {{
            color: var(--text-secondary);
            font-style: italic;
        }}

        /* Frida Scripts Styles */
        .frida-container {{
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}

        .tab-buttons {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            padding: 15px;
            background: #2d2d2d;
        }}

        .tab-btn {{
            padding: 10px 20px;
            border: none;
            background: #404040;
            color: #d4d4d4;
            cursor: pointer;
            border-radius: 4px;
            transition: background 0.2s;
        }}

        .tab-btn:hover {{
            background: #505050;
        }}

        .tab-btn.active {{
            background: var(--accent-color);
            color: white;
        }}

        .tab-content {{
            display: none;
            padding: 0;
        }}

        .tab-content.active {{
            display: block;
        }}

        .script-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #2d2d2d;
            color: white;
        }}

        .frida-script {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            margin: 0;
            overflow-x: auto;
            font-size: 0.85em;
            line-height: 1.5;
            max-height: 500px;
            overflow-y: auto;
        }}

        .frida-script code {{
            background: transparent;
            color: inherit;
        }}

        /* Toast notification */
        .toast {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #333;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s ease;
            z-index: 1000;
            font-size: 0.9rem;
        }}

        .toast.show {{
            opacity: 1;
            transform: translateY(0);
        }}

        .toast.success {{
            background: var(--success-color);
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Application Visualization</h1>
            <div class="package">{stats['package_name']}</div>
        </div>
    </header>

    <div class="container">
        <nav class="nav">
            <a href="#statistics">Overview</a>
            <a href="#entry_points">Entry Points</a>
            <a href="#components">Components</a>
            <a href="#data_flow">Data Flow</a>
            <a href="#data-flow-details">📊 Flow Details</a>
            <a href="#attack-surface">🎯 Attack Surface</a>
            <a href="#injection-points">💉 Injections</a>
            <a href="#frida-scripts">🪝 Frida</a>
            <a href="#component-details">Details</a>
        </nav>

        <!-- Filter Bar -->
        <div class="filter-bar">
            <div class="filter-group">
                <label>Risk Level:</label>
                <select id="filter-risk" onchange="applyFilters()">
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Category:</label>
                <select id="filter-category" onchange="applyFilters()">
                    <option value="all">All</option>
                    <option value="data-flow">Data Flow</option>
                    <option value="injection">Injection</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Search:</label>
                <input type="text" id="filter-search" placeholder="Search..." oninput="applyFilters()">
            </div>
            <button class="filter-reset" onclick="resetFilters()">Reset</button>
            <span class="filter-count"><span id="visible-count">0</span> items</span>
        </div>

        {sections}

        <footer>
            Generated by MSRA &mdash; Built by Sai with love &#10084; &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>

    <div id="toast" class="toast"></div>

    <script>
        mermaid.initialize({{
            startOnLoad: true,
            theme: 'default',
            securityLevel: 'loose',
            flowchart: {{
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }}
        }});

        // Toast notification function
        function showToast(message, type = '') {{
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type + ' show';
            setTimeout(() => {{
                toast.className = 'toast';
            }}, 2000);
        }}

        // Copy to clipboard function
        function copyToClipboard(btn) {{
            const code = btn.previousElementSibling.textContent;
            navigator.clipboard.writeText(code).then(() => {{
                const original = btn.textContent;
                btn.textContent = '✓';
                setTimeout(() => btn.textContent = original, 1500);
                showToast('Copied!', 'success');
            }});
        }}

        // Copy Frida script
        function copyScript(name) {{
            const code = document.getElementById('script-' + name).textContent;
            navigator.clipboard.writeText(code).then(() => {{
                showToast('Script copied to clipboard!', 'success');
            }});
        }}

        // Tab switching
        function showFridaTab(name) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

            // Show selected tab
            document.getElementById('frida-' + name).classList.add('active');
            event.target.classList.add('active');
        }}

        // Filtering functionality
        function applyFilters() {{
            const riskFilter = document.getElementById('filter-risk').value;
            const categoryFilter = document.getElementById('filter-category').value;
            const searchFilter = document.getElementById('filter-search').value.toLowerCase();

            const rows = document.querySelectorAll('.filterable');
            let visibleCount = 0;

            rows.forEach(row => {{
                const risk = row.dataset.risk || '';
                const category = row.dataset.category || '';
                const text = row.textContent.toLowerCase();

                const matchRisk = riskFilter === 'all' || risk === riskFilter;
                const matchCategory = categoryFilter === 'all' || category === categoryFilter;
                const matchSearch = !searchFilter || text.includes(searchFilter);

                if (matchRisk && matchCategory && matchSearch) {{
                    row.classList.remove('hidden');
                    visibleCount++;
                }} else {{
                    row.classList.add('hidden');
                }}
            }});

            document.getElementById('visible-count').textContent = visibleCount;
        }}

        function resetFilters() {{
            document.getElementById('filter-risk').value = 'all';
            document.getElementById('filter-category').value = 'all';
            document.getElementById('filter-search').value = '';
            applyFilters();
        }}

        // Initialize count on page load
        document.addEventListener('DOMContentLoaded', function() {{
            const count = document.querySelectorAll('.filterable').length;
            document.getElementById('visible-count').textContent = count;
        }});
    </script>
</body>
</html>'''
