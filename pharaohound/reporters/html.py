#!/usr/bin/env python3
"""
reporters.html — Interactive HTML report writer using Vis.js.
Generates a self-contained HTML graph of attack paths and AD entities.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List

from ..intelligence import EDGE_INTELLIGENCE


def generate_html_report(
    filepath: str,
    stats: Dict[str, int],
    domain: str,
    findings: List[Dict[str, Any]],
    attack_paths: List[Dict[str, Any]],
    recommendations: List[Dict[str, Any]],
) -> str:
    # ── 1. EXTRACT GRAPH NODES AND EDGES ──
    nodes_registry: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def add_node(name: str, node_type: str, severity: str = "INFO"):
        if not name:
            return
        clean_name = name.upper()
        if clean_name not in nodes_registry:
            # Assign colors & shapes based on node type
            shape_map = {
                "user": "dot",
                "computer": "square",
                "group": "triangle",
                "gpo": "database",
                "ou": "box",
                "domain": "star",
                "ca": "hexagon",
                "certtemplate": "diamond",
                "azure": "ellipse",
            }
            color_map = {
                "user": "#29b6f6",        # Light blue
                "computer": "#ab47bc",    # Purple
                "group": "#26a69a",       # Teal
                "gpo": "#ffa726",        # Orange
                "ou": "#78909c",         # Slate blue/grey
                "domain": "#ec407a",     # Pink/red
                "ca": "#ffb300",         # Amber
                "certtemplate": "#00e5ff",# Cyan
                "azure": "#5c6bc0",      # Indigo blue
            }
            nodes_registry[clean_name] = {
                "id": clean_name,
                "label": name,
                "shape": shape_map.get(node_type.lower(), "dot"),
                "color": color_map.get(node_type.lower(), "#bdbdbd"),
                "type": node_type.upper(),
                "severity": severity,
                "details": f"Type: {node_type.upper()}\nName: {name}",
            }

    # Add default root attacker/users
    add_node("ANY DOMAIN USER", "user", "INFO")
    add_node("ANY ATTACKER", "user", "INFO")

    # Parse findings to construct nodes and edges
    for f in findings:
        title = f.get("title", "")
        sev = f.get("severity", "INFO")
        for item in f.get("data", []):
            # 1. ACLs
            if "principal" in item and "source_object" in item:
                p_type = item.get("principal_type", "user")
                t_type = item.get("source_type", "user")
                add_node(item["principal"], p_type, sev)
                add_node(item["source_object"], t_type, sev)
                
                # Check for high-value tag to upgrade node styling
                if item.get("in_high_value_group"):
                    nodes_registry[item["principal"].upper()]["color"] = "#ef5350" # Red
                
                edges.append({
                    "from": item["principal"].upper(),
                    "to": item["source_object"].upper(),
                    "label": item.get("right", "Control"),
                    "title": f"Finding: {title}\nPermission: {item.get('right')}\nSeverity: {sev}",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": item.get("right"),
                })

            # 2. Kerberoasting
            elif "name" in item and "spns" in item:
                add_node(item["name"], "user", sev)
                edges.append({
                    "from": "ANY DOMAIN USER",
                    "to": item["name"].upper(),
                    "label": "Kerberoastable SPN",
                    "title": f"Finding: {title}\nUser holds an SPN, vulnerable to offline cracking.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "Kerberoastable",
                })

            # 3. LAPS
            elif "reader" in item and "target_computer" in item:
                add_node(item["reader"], "user", sev)
                add_node(item["target_computer"], "computer", sev)
                edges.append({
                    "from": item["reader"].upper(),
                    "to": item["target_computer"].upper(),
                    "label": "Read LAPS Password",
                    "title": f"Finding: {title}\nCan read local administrator password.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "ReadLAPSPassword",
                })

            # 4. DCSync
            elif "account" in item and "domain" in item:
                add_node(item["account"], "user", sev)
                add_node(item["domain"], "domain", sev)
                edges.append({
                    "from": item["account"].upper(),
                    "to": item["domain"].upper(),
                    "label": "DCSync Rights",
                    "title": f"Finding: {title}\nCan request password replication sync.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "DCSync",
                })

            # 5. Shadow Credentials
            elif "attacker" in item and "target" in item:
                t_type = item.get("target_type", "computer")
                add_node(item["attacker"], "user", sev)
                add_node(item["target"], t_type, sev)
                edges.append({
                    "from": item["attacker"].upper(),
                    "to": item["target"].upper(),
                    "label": "Write KeyCredentialLink",
                    "title": f"Finding: {title}\nCan take over via Shadow Credentials.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "AddKeyCredentialLink",
                })

            # 6. GPO Abuse (Direct Write)
            elif "attacker" in item and "gpo" in item:
                add_node(item["attacker"], "user", sev)
                add_node(item["gpo"], "gpo", sev)
                edges.append({
                    "from": item["attacker"].upper(),
                    "to": item["gpo"].upper(),
                    "label": "Write GPO",
                    "title": f"Finding: {title}\nCan edit Group Policy Object settings.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "GPLink",
                })

            # GPO linked to high-value OU
            elif "gpo" in item and "ou" in item:
                add_node(item["gpo"], "gpo", sev)
                add_node(item["ou"], "ou", sev)
                edges.append({
                    "from": item["gpo"].upper(),
                    "to": item["ou"].upper(),
                    "label": "GPLink",
                    "title": f"Finding: {title}\nGPO linked to High-Value OU.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "GPLink",
                })

            # AD CS template/CA misconfiguration
            elif "esc" in item:
                esc = item["esc"]
                ca = item.get("ca")
                tpl = item.get("template")
                computer = item.get("computer")
                principal = item.get("principal")
                enrollers = item.get("enrollers")
                
                target_node = ""
                if tpl:
                    add_node(tpl, "certtemplate", sev)
                    target_node = tpl
                elif ca:
                    add_node(ca, "ca", sev)
                    target_node = ca
                elif computer:
                    add_node(computer, "computer", sev)
                    target_node = computer
                
                if target_node:
                    if enrollers:
                        for enroller in enrollers:
                            add_node(enroller, "user", sev)
                            edges.append({
                                "from": enroller.upper(),
                                "to": target_node.upper(),
                                "label": f"{esc} Enroll",
                                "title": f"Finding: {title}\nCan enroll on template/CA via {esc}.",
                                "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                                "intel_key": f"ADCS_{esc}",
                            })
                    elif principal:
                        add_node(principal, "user", sev)
                        edges.append({
                            "from": principal.upper(),
                            "to": target_node.upper(),
                            "label": f"{esc} Abuse",
                            "title": f"Finding: {title}\nCan abuse template/CA via {esc}.",
                            "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                            "intel_key": f"ADCS_{esc}",
                        })
                    else:
                        edges.append({
                            "from": "ANY ATTACKER",
                            "to": target_node.upper(),
                            "label": f"{esc} Vulnerable",
                            "title": f"Finding: {title}\nCA/Template/DC has {esc} misconfiguration.",
                            "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                            "intel_key": f"ADCS_{esc}",
                        })

            # Domain Trust
            elif "direction" in item and "source" in item and "target" in item:
                add_node(item["source"], "domain", sev)
                add_node(item["target"], "domain", sev)
                label = f"{item['direction']} Trust"
                edges.append({
                    "from": item["source"].upper(),
                    "to": item["target"].upper(),
                    "label": label,
                    "title": f"Finding: {title}\nTrust direction: {item['direction']}\nSID Filtering: {'Enabled' if item.get('sid_filtering') else 'DISABLED'}",
                    "color": {"color": "#ef5350" if not item.get("sid_filtering") else "#ffa726"},
                    "intel_key": "Domain Trusts",
                })

            # Machine Account Quota
            elif "machine_account_quota" in item:
                add_node(item["domain"], "domain", sev)
                edges.append({
                    "from": "ANY DOMAIN USER",
                    "to": item["domain"].upper(),
                    "label": f"MAQ: {item['machine_account_quota']}",
                    "title": f"Finding: {title}\nUsers can create up to {item['machine_account_quota']} machine accounts.",
                    "color": {"color": "#ffa726"},
                    "intel_key": "MachineAccountQuota",
                })

            # Pre-Windows 2000 Compatible Access
            elif "member" in item and "group" in item:
                m_type = "group" if "group" in item.get("member_type", "").lower() else "user"
                add_node(item["member"], m_type, sev)
                add_node(item["group"], "group", sev)
                edges.append({
                    "from": item["member"].upper(),
                    "to": item["group"].upper(),
                    "label": "MemberOf (Pre-W2K)",
                    "title": f"Finding: {title}\nMember of Pre-Windows 2000 Compatible Access.",
                    "color": {"color": "#ffa726"},
                    "intel_key": "Pre-Windows 2000 Compatible Access",
                })

            # Constrained Delegation
            elif "delegation_targets" in item:
                add_node(item["name"], item.get("type", "user").lower(), sev)
                for dest in item["delegation_targets"]:
                    d_type = "computer" if "$" in dest or "/" in dest else "user"
                    add_node(dest, d_type, sev)
                    edges.append({
                        "from": item["name"].upper(),
                        "to": dest.upper(),
                        "label": "Constrained Delegation",
                        "title": f"Finding: {title}\nDelegated to target: {dest}",
                        "color": {"color": "#ffa726"},
                        "intel_key": "AllowedToDelegate",
                    })

            # gMSA Password Readers
            elif "gmsa_account" in item:
                add_node(item["reader"], item.get("reader_type", "user").lower(), sev)
                add_node(item["gmsa_account"], "user", sev)
                edges.append({
                    "from": item["reader"].upper(),
                    "to": item["gmsa_account"].upper(),
                    "label": "Read gMSA Password",
                    "title": f"Finding: {title}\nCan read password for gMSA {item['gmsa_account']}",
                    "color": {"color": "#ffa726"},
                    "intel_key": "ReadGMSAPassword",
                })

            # Self-Add to Group
            elif "principal" in item and "target_group" in item:
                p_type = item.get("principal_type", "user")
                add_node(item["principal"], p_type, sev)
                add_node(item["target_group"], "group", sev)
                edges.append({
                    "from": item["principal"].upper(),
                    "to": item["target_group"].upper(),
                    "label": f"Self-Add ({item.get('right')})",
                    "title": f"Finding: {title}\nCan add self to group via {item.get('right')}.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "Self-Add to Group Escalation",
                })

            # 7. AS-REP Roast
            elif "name" in item and title == "AS-REP Roastable Users":
                add_node(item["name"], "user", sev)
                edges.append({
                    "from": "ANY ATTACKER",
                    "to": item["name"].upper(),
                    "label": "AS-REP Roastable",
                    "title": f"Finding: {title}\nPre-authentication is disabled.",
                    "color": {"color": "#ef5350" if sev == "CRITICAL" else "#ffa726"},
                    "intel_key": "ASRepRoastable",
                })

    # If registry has nodes that are target of attack paths, highlight them in red
    for p in attack_paths:
        for tool in p.get("tools", []):
            pass

    # Convert nodes registry to list
    nodes_list = list(nodes_registry.values())

    # Build recommendations details block
    rec_html = ""
    for r in recommendations:
        rec_html += f"""
        <div class="card recommendation-card rank-{r['priority']}">
            <h4>[P{r['priority']}] {r['title']}</h4>
            <p><strong>Impact:</strong> {r['action']}</p>
            <p><strong>Action Command:</strong> <code>{r['command']}</code></p>
            {"<p><strong>Alternative:</strong> <code>" + r['alt_commands'][0] + "</code></p>" if r.get('alt_commands') else ""}
            <p><strong>Defender Remediate:</strong> {r.get('defender_action', 'N/A')}</p>
        </div>
        """

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── 2. COMPILE HTML TEMPLATE ──
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pharaohound Attack Path Graph</title>
    
    <!-- Vis.js network graph library -->
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>

    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            overflow: hidden;
            display: flex;
            height: 100vh;
        }}
        
        /* Sidebar Layout */
        #sidebar {{
            width: 420px;
            background-color: #1e293b;
            border-right: 1px solid #334155;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            z-index: 10;
            box-shadow: 4px 0 15px rgba(0,0,0,0.3);
        }}
        .sidebar-header {{
            padding: 24px;
            border-bottom: 1px solid #334155;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        }}
        .sidebar-header h1 {{
            font-size: 24px;
            font-weight: 800;
            color: #fbbf24; /* Pharaoh Gold */
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }}
        .sidebar-header p {{
            font-size: 13px;
            color: #94a3b8;
        }}
        
        .section-title {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #64748b;
            padding: 16px 24px 8px 24px;
            font-weight: 700;
        }}

        .card-container {{
            padding: 0 24px 24px 24px;
        }}
        
        .card {{
            background-color: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
            transition: all 0.2s ease;
        }}
        .card h4 {{
            color: #38bdf8;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        .card p {{
            font-size: 13px;
            color: #cbd5e1;
            line-height: 1.5;
            margin-bottom: 6px;
        }}
        .card p strong {{
            color: #f1f5f9;
        }}
        .card code {{
            background-color: #1e293b;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 11px;
            color: #fda4af;
            display: block;
            margin-top: 4px;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Recommendations */
        .recommendation-card {{
            border-left: 4px solid #38bdf8;
        }}
        .recommendation-card.rank-1 {{ border-left-color: #ef4444; }} /* Red */
        .recommendation-card.rank-2 {{ border-left-color: #f97316; }} /* Orange */
        .recommendation-card.rank-3 {{ border-left-color: #eab308; }} /* Yellow */

        /* Details Card */
        #details-pane {{
            background-color: #1e293b;
            padding: 20px;
            margin: 0 24px 24px 24px;
            border-radius: 8px;
            border: 1px dashed #475569;
        }}
        #details-pane h3 {{
            font-size: 15px;
            color: #fbbf24;
            margin-bottom: 10px;
        }}
        #details-pane p {{
            font-size: 13px;
            color: #cbd5e1;
            line-height: 1.6;
        }}

        /* Graph Area */
        #graph-container {{
            flex-grow: 1;
            position: relative;
            background-color: #0b0f19;
        }}
        #network {{
            width: 100%;
            height: 100%;
        }}
        
        /* Floating Controls & Legend */
        #legend {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background-color: rgba(30, 41, 59, 0.9);
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
            z-index: 5;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            backdrop-filter: blur(8px);
        }}
        #legend h4 {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #fbbf24;
            margin-bottom: 10px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            font-size: 11px;
            color: #cbd5e1;
            margin-bottom: 6px;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}

        /* Help Box */
        .help-box {{
            background-color: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 16px;
        }}
        .help-box p {{
            font-size: 12px;
            color: #38bdf8;
            line-height: 1.4;
        }}

        /* Search Box */
        .search-box {{
            padding: 0 24px;
            margin-top: 15px;
        }}
        .search-box input {{
            width: 100%;
            background-color: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 10px 12px;
            color: #f8fafc;
            font-size: 13px;
        }}
        .search-box input:focus {{
            outline: none;
            border-color: #fbbf24;
        }}
    </style>
</head>
<body>

    <!-- SIDEBAR -->
    <div id="sidebar">
        <div class="sidebar-header">
            <h1>Pharaohound Graph</h1>
            <p>Domain Analyzed: <strong>{domain}</strong></p>
            <p>Generated: <strong>{now}</strong></p>
        </div>

        <div class="search-box">
            <input type="text" id="search-input" placeholder="Search AD Node (User, Group, Computer)..." oninput="searchNode()">
        </div>

        <div class="section-title">Selected Edge / Node Details</div>
        <div id="details-pane">
            <h3>Click a node or relationship edge</h3>
            <p>Select any circle (node) or connecting arrow (edge/relation) in the graph diagram to view details, abuse paths (ELI5), and remediations.</p>
        </div>

        <div class="section-title">Prioritized Action Plan</div>
        <div class="card-container">
            <div class="help-box">
                <p>💡 <strong>Remediation Note:</strong> These recommendations are sorted by priority. Target P1 fixes first to break the most critical AD attack chains.</p>
            </div>
            {rec_html}
        </div>
    </div>

    <!-- MAIN GRAPH AREA -->
    <div id="graph-container">
        <div id="network"></div>

        <!-- LEGEND -->
        <div id="legend">
            <h4>Legend</h4>
            <div class="legend-item"><span class="legend-color" style="background-color: #ec407a;"></span> Domain Root</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #29b6f6;"></span> User Principal</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #26a69a;"></span> Active Directory Group</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #ab47bc;"></span> Computer / Host</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #ffa726;"></span> Group Policy (GPO)</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #ffb300;"></span> Certificate Authority (CA)</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #00e5ff;"></span> Certificate Template</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #5c6bc0;"></span> Azure / Entra ID</div>
            <div class="legend-item"><span class="legend-color" style="background-color: #ef5350;"></span> Critical Threat (High-Value)</div>
        </div>
    </div>

    <div id="loading-overlay" style="position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(11,15,25,0.95);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:100;">
            <h2 style="color:#fbbf24;margin-bottom:16px;font-size:18px;">Building Attack Graph…</h2>
            <div style="width:300px;height:6px;background:#1e293b;border-radius:3px;overflow:hidden;">
                <div id="progress-bar" style="width:0%;height:100%;background:linear-gradient(90deg,#fbbf24,#f97316);border-radius:3px;transition:width 0.3s;"></div>
            </div>
            <p id="progress-text" style="color:#94a3b8;margin-top:10px;font-size:13px;">Initializing…</p>
        </div>

    <script type="text/javascript">
        // Parse node and edge datasets
        const rawNodes = {json.dumps(nodes_list)};
        const rawEdges = {json.dumps(edges)};
        const EDGE_INTELLIGENCE = {json.dumps(EDGE_INTELLIGENCE)};

        // Format nodes for Vis.js — NO shadows for performance
        const nodes = new vis.DataSet(rawNodes.map(n => ({{
            id: n.id,
            label: n.label,
            shape: n.shape,
            color: {{
                background: n.color,
                border: n.color,
                highlight: {{ background: '#fbbf24', border: '#fbbf24' }},
                hover: {{ background: n.color, border: '#fbbf24' }}
            }},
            font: {{ color: '#f8fafc', size: 11, face: 'Inter, sans-serif' }},
            title: `Type: ${{n.type}}\\nName: ${{n.label}}`
        }})));

        // Format edges — labels hidden by default, shown on hover via title
        const edges = new vis.DataSet(rawEdges.map((e, index) => ({{
            id: `edge_${{index}}`,
            from: e.from,
            to: e.to,
            label: '',
            color: e.color || {{ color: '#475569' }},
            font: {{ color: '#94a3b8', size: 9, align: 'top', face: 'Inter, sans-serif' }},
            arrows: {{ to: {{ scaleFactor: 0.6 }} }},
            width: 1.5,
            title: `${{e.label}}\\n${{e.title || ''}}`,
            hoverWidth: 0.5,
            _label: e.label,
            intel_key: e.intel_key
        }})));

        // Network Config — optimized for performance
        const container = document.getElementById('network');
        const data = {{ nodes: nodes, edges: edges }};
        const nodeCount = rawNodes.length;
        const edgeCount = rawEdges.length;

        // Scale physics based on graph size
        const isLarge = nodeCount > 80;
        const options = {{
            nodes: {{
                size: isLarge ? 18 : 25,
                borderWidth: 1.5,
                shadow: false
            }},
            edges: {{
                shadow: false,
                smooth: {{
                    type: isLarge ? 'straight' : 'continuous',
                    roundness: 0.3
                }},
                selectionWidth: 2
            }},
            physics: {{
                enabled: true,
                barnesHut: {{
                    gravitationalConstant: isLarge ? -5000 : -8000,
                    centralGravity: 0.4,
                    springLength: isLarge ? 120 : 150,
                    springConstant: 0.06,
                    damping: 0.15,
                    avoidOverlap: 0.3
                }},
                stabilization: {{
                    enabled: true,
                    iterations: isLarge ? 200 : 150,
                    updateInterval: 10,
                    fit: true
                }},
                maxVelocity: 50,
                minVelocity: 0.75
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 150,
                hideEdgesOnDrag: isLarge,
                hideEdgesOnZoom: isLarge
            }},
            layout: {{
                improvedLayout: !isLarge
            }}
        }};

        const network = new vis.Network(container, data, options);

        // Update header with graph stats
        const headerP = document.querySelector('.sidebar-header');
        if (headerP) {{
            const statsP = document.createElement('p');
            statsP.style.cssText = 'font-size:12px;color:#64748b;margin-top:6px;';
            statsP.textContent = `Graph: ${{nodeCount}} nodes, ${{edgeCount}} edges`;
            headerP.appendChild(statsP);
        }}

        // Progress bar during stabilization
        const overlay = document.getElementById('loading-overlay');
        const progressBar = document.getElementById('progress-bar');
        const progressText = document.getElementById('progress-text');

        network.on('stabilizationProgress', function(params) {{
            const pct = Math.round((params.iterations / params.total) * 100);
            progressBar.style.width = pct + '%';
            progressText.textContent = `Laying out ${{nodeCount}} nodes… ${{pct}}%`;
        }});

        network.once('stabilizationIterationsDone', function() {{
            progressBar.style.width = '100%';
            progressText.textContent = 'Done!';
            // Stop physics after layout is settled — huge perf win
            network.setOptions({{ physics: {{ enabled: false }} }});
            setTimeout(() => {{
                overlay.style.transition = 'opacity 0.4s';
                overlay.style.opacity = '0';
                setTimeout(() => overlay.remove(), 400);
            }}, 300);
        }});

        // Show edge label on hover, hide on blur
        network.on('hoverEdge', function(params) {{
            const edgeData = edges.get(params.edge);
            if (edgeData && edgeData._label) {{
                edges.update({{ id: params.edge, label: edgeData._label }});
            }}
        }});
        network.on('blurEdge', function(params) {{
            edges.update({{ id: params.edge, label: '' }});
        }});

        // Click interaction
        network.on("click", function (params) {{
            const detailsPane = document.getElementById('details-pane');
            
            // 1. Clicked an Edge
            if (params.edges.length > 0 && params.nodes.length === 0) {{
                const edgeId = params.edges[0];
                const edgeData = edges.get(edgeId);
                const sourceNode = nodes.get(edgeData.from);
                const targetNode = nodes.get(edgeData.to);

                const intel = EDGE_INTELLIGENCE[edgeData.intel_key] || {{}};
                const eli5 = intel.eli5 || "";
                const remediation = intel.remediation || "";

                let eli5Html = "";
                if (eli5) {{
                    eli5Html = `
                        <div style="margin-top:12px; background-color:#0f172a; padding:10px; border-radius:6px; border: 1px solid #334155;">
                            <strong style="color:#a855f7;">ELI5 (Simple Explanation):</strong>
                            <p style="font-size:12px; margin-top:4px;">${{eli5}}</p>
                        </div>
                    `;
                }}

                let remHtml = "";
                if (remediation) {{
                    remHtml = `
                        <div style="margin-top:12px; background-color:#0f172a; padding:10px; border-radius:6px; border: 1px solid #334155;">
                            <strong style="color:#22c55e;">How to fix:</strong>
                            <p style="font-size:12px; margin-top:4px;">${{remediation}}</p>
                        </div>
                    `;
                }}

                detailsPane.innerHTML = `
                    <h3>Relation: ${{edgeData._label || 'Edge'}}</h3>
                    <p><strong>From:</strong> ${{sourceNode ? sourceNode.label : edgeData.from}}</p>
                    <p><strong>To:</strong> ${{targetNode ? targetNode.label : edgeData.to}}</p>
                    ${{eli5Html}}
                    ${{remHtml}}
                `;
            }}
            // 2. Clicked a Node
            else if (params.nodes.length > 0) {{
                const nodeId = params.nodes[0];
                const nodeData = rawNodes.find(n => n.id === nodeId);
                
                // Find connected edges for this node
                const connEdges = rawEdges.filter(e => e.from === nodeId || e.to === nodeId);
                let connHtml = '';
                if (connEdges.length > 0) {{
                    connHtml = `<p style="margin-top:10px;"><strong>Connections:</strong> ${{connEdges.length}} relationships</p><ul style="font-size:12px;color:#94a3b8;margin-top:4px;padding-left:16px;">`;
                    connEdges.slice(0, 10).forEach(ce => {{
                        const direction = ce.from === nodeId ? '→ ' + ce.to : '← ' + ce.from;
                        connHtml += `<li>${{ce.label}}: ${{direction}}</li>`;
                    }});
                    if (connEdges.length > 10) connHtml += `<li>… and ${{connEdges.length - 10}} more</li>`;
                    connHtml += '</ul>';
                }}

                detailsPane.innerHTML = `
                    <h3>Node: ${{nodeData ? nodeData.label : nodeId}}</h3>
                    <p><strong>Type:</strong> ${{nodeData ? nodeData.type : 'Unknown'}}</p>
                    <p><strong>Security Context:</strong> ${{nodeData ? nodeData.severity : 'N/A'}}</p>
                    ${{connHtml}}
                `;
            }}
            // 3. Clicked empty space
            else {{
                detailsPane.innerHTML = `
                    <h3>Click a node or relationship edge</h3>
                    <p>Select any circle (node) or connecting arrow (edge/relation) in the graph diagram to view details, abuse paths (ELI5), and remediations.</p>
                `;
            }}
        }});

        // Search feature
        function searchNode() {{
            const query = document.getElementById('search-input').value.toUpperCase();
            if (!query) return;

            const matchingNode = rawNodes.find(n => n.label.toUpperCase().includes(query) || n.id.includes(query));
            if (matchingNode) {{
                network.focus(matchingNode.id, {{
                    scale: 1.2,
                    animation: {{
                        duration: 600,
                        easingFunction: 'easeInOutQuad'
                    }}
                }});
                network.selectNodes([matchingNode.id]);
            }}
        }}
    </script>
</body>
</html>
"""

    # Ensure output directory exists and write
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filepath
