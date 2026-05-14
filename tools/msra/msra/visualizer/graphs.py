"""Graph builders for application visualization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .analyzer import AppStructure, ClassInfo, ComponentInfo


@dataclass
class Node:
    """Graph node."""
    id: str
    label: str
    type: str  # activity, service, fragment, class, method, etc.
    properties: Dict = field(default_factory=dict)


@dataclass
class Edge:
    """Graph edge."""
    source: str
    target: str
    label: str = ""
    type: str = "default"  # calls, extends, implements, intent, data_flow
    properties: Dict = field(default_factory=dict)


@dataclass
class Graph:
    """Generic graph structure."""
    name: str
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    subgraphs: Dict[str, List[str]] = field(default_factory=dict)  # group_name -> node_ids

    def add_node(self, node: Node) -> None:
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def to_mermaid(self) -> str:
        """Convert graph to Mermaid diagram syntax."""
        raise NotImplementedError


class ComponentGraph(Graph):
    """Graph showing Android component interactions."""

    def __init__(self, structure: AppStructure):
        super().__init__(name="Component Interaction Graph")
        self._build(structure)

    def _build(self, structure: AppStructure) -> None:
        """Build component interaction graph."""
        # Add component nodes
        for name, comp in structure.components.items():
            node_type = comp.type
            short_name = name.split('.')[-1]

            properties = {
                'exported': comp.exported,
                'permission': comp.permission,
                'full_name': name,
            }

            # Add intent filter info
            if comp.intent_filters:
                actions = []
                for f in comp.intent_filters:
                    actions.extend(f.get('actions', []))
                properties['actions'] = actions

            self.add_node(Node(
                id=self._safe_id(name),
                label=short_name,
                type=node_type,
                properties=properties,
            ))

            # Group by type
            if node_type not in self.subgraphs:
                self.subgraphs[node_type] = []
            self.subgraphs[node_type].append(self._safe_id(name))

        # Add edges from intent analysis
        for intent in structure.intents:
            if intent.target:
                source_id = self._safe_id(intent.source_class)
                target_id = self._safe_id(intent.target)

                # Only add if both nodes exist
                source_exists = any(n.id == source_id for n in self.nodes)
                target_exists = any(n.id == target_id for n in self.nodes)

                if source_exists and target_exists:
                    self.add_edge(Edge(
                        source=source_id,
                        target=target_id,
                        label="intent",
                        type="intent",
                    ))

        # Add edges based on manifest intent-filters (implicit connections)
        for name, comp in structure.components.items():
            for intent_filter in comp.intent_filters:
                for action in intent_filter.get('actions', []):
                    # Find other components that might send this action
                    pass  # Complex analysis, skip for now

    def _safe_id(self, name: str) -> str:
        """Create safe ID for Mermaid."""
        return name.replace('.', '_').replace('$', '_').replace('-', '_')

    def to_mermaid(self) -> str:
        """Convert to Mermaid flowchart."""
        lines = ["flowchart TB"]

        # Define subgraphs for each component type
        type_labels = {
            'activity': 'Activities',
            'service': 'Services',
            'receiver': 'Broadcast Receivers',
            'provider': 'Content Providers',
        }

        for comp_type, node_ids in self.subgraphs.items():
            if node_ids:
                label = type_labels.get(comp_type, comp_type.title())
                lines.append(f"    subgraph {comp_type}[{label}]")

                for node_id in node_ids:
                    node = next((n for n in self.nodes if n.id == node_id), None)
                    if node:
                        shape = self._get_shape(node.type, node.label, node.properties.get('exported', False))
                        lines.append(f"        {node.id}{shape}")

                lines.append("    end")

        # Add edges
        for edge in self.edges:
            arrow = self._get_arrow(edge.type)
            if edge.label:
                lines.append(f"    {edge.source} {arrow}|{edge.label}| {edge.target}")
            else:
                lines.append(f"    {edge.source} {arrow} {edge.target}")

        # Style exported components
        for node in self.nodes:
            if node.properties.get('exported'):
                lines.append(f"    style {node.id} fill:#ff6b6b,stroke:#c92a2a")

        return '\n'.join(lines)

    def _get_shape(self, node_type: str, label: str, exported: bool) -> str:
        """Get Mermaid shape for node type."""
        shapes = {
            'activity': f'["{label}"]',  # Rectangle
            'service': f'(["{label}"])',  # Stadium
            'receiver': f'{{"{label}"}}',  # Rhombus
            'provider': f'[("{label}")]',  # Cylindrical
        }
        return shapes.get(node_type, f'["{label}"]')

    def _get_arrow(self, edge_type: str) -> str:
        """Get Mermaid arrow style."""
        arrows = {
            'intent': '-->',
            'data_flow': '-.->',
            'calls': '==>',
        }
        return arrows.get(edge_type, '-->')


class CallGraph(Graph):
    """Graph showing method call relationships."""

    MAX_CLASSES = 30  # Limit to prevent Mermaid overflow

    def __init__(self, structure: AppStructure, max_depth: int = 3):
        super().__init__(name="Call Graph")
        self.max_depth = max_depth
        self._build(structure)

    def _build(self, structure: AppStructure) -> None:
        """Build call graph from method analysis."""
        # Prioritize Android components over regular classes
        component_classes = []
        other_classes = []

        for class_name, class_info in structure.classes.items():
            if class_info.is_activity or class_info.is_service or class_info.is_receiver or class_info.is_provider or class_info.is_fragment:
                component_classes.append((class_name, class_info))
            else:
                other_classes.append((class_name, class_info))

        # Take components first, then fill with other classes up to limit
        classes_to_show = component_classes[:self.MAX_CLASSES]
        remaining = self.MAX_CLASSES - len(classes_to_show)
        if remaining > 0:
            classes_to_show.extend(other_classes[:remaining])

        # Add class nodes with their methods
        for class_name, class_info in classes_to_show:
            # Add class as a grouping node
            short_name = class_info.name

            # Determine class type for styling
            if class_info.is_activity:
                class_type = 'activity'
            elif class_info.is_service:
                class_type = 'service'
            elif class_info.is_receiver:
                class_type = 'receiver'
            elif class_info.is_provider:
                class_type = 'provider'
            elif class_info.is_fragment:
                class_type = 'fragment'
            else:
                class_type = 'class'

            self.add_node(Node(
                id=self._safe_id(class_name),
                label=short_name,
                type=class_type,
                properties={'full_name': class_name},
            ))

            # Group methods by class
            self.subgraphs[self._safe_id(class_name)] = []

            # Add important methods
            important_methods = ['onCreate', 'onStart', 'onResume', 'onReceive',
                                'onBind', 'query', 'insert', 'update', 'delete',
                                'onCreateView', 'onActivityResult', 'onNewIntent']

            for method in class_info.methods:
                if method.name in important_methods or 'public' in method.modifiers:
                    method_id = f"{self._safe_id(class_name)}_{method.name}"
                    self.add_node(Node(
                        id=method_id,
                        label=method.name,
                        type='method',
                        properties={
                            'class': class_name,
                            'return_type': method.return_type,
                        },
                    ))
                    self.subgraphs[self._safe_id(class_name)].append(method_id)

    def _safe_id(self, name: str) -> str:
        """Create safe ID for Mermaid."""
        return name.replace('.', '_').replace('$', '_').replace('-', '_')

    def to_mermaid(self) -> str:
        """Convert to Mermaid flowchart."""
        lines = ["flowchart LR"]

        # Group by class
        for class_id, method_ids in self.subgraphs.items():
            if method_ids:
                class_node = next((n for n in self.nodes if n.id == class_id), None)
                if class_node:
                    lines.append(f"    subgraph {class_id}[{class_node.label}]")
                    for method_id in method_ids[:10]:  # Limit methods shown
                        method_node = next((n for n in self.nodes if n.id == method_id), None)
                        if method_node:
                            lines.append(f"        {method_id}[{method_node.label}]")
                    lines.append("    end")

        # Add edges
        for edge in self.edges:
            lines.append(f"    {edge.source} --> {edge.target}")

        return '\n'.join(lines)


class DataFlowGraph(Graph):
    """Graph showing data flow through the application."""

    MAX_FLOWS = 50  # Limit flows to prevent Mermaid overflow
    MAX_CLASSES = 25  # Limit intermediate classes

    def __init__(self, structure: AppStructure):
        super().__init__(name="Data Flow Graph")
        self._build(structure)

    def _build(self, structure: AppStructure) -> None:
        """Build data flow graph."""
        # Create source nodes
        source_types = set()
        sink_types = set()

        # Limit the number of flows processed
        flows_to_process = structure.data_flows[:self.MAX_FLOWS]

        for flow in flows_to_process:
            source_types.add(flow.source)
            sink_types.add(flow.sink)

        # Add source nodes
        source_icons = {
            'user_input': 'User Input',
            'file': 'File Storage',
            'network': 'Network',
            'database': 'Database',
        }

        for source in source_types:
            self.add_node(Node(
                id=f"source_{source}",
                label=source_icons.get(source, source),
                type='source',
                properties={'data_type': source},
            ))
            if 'sources' not in self.subgraphs:
                self.subgraphs['sources'] = []
            self.subgraphs['sources'].append(f"source_{source}")

        # Add sink nodes
        sink_icons = {
            'network': 'Network Output',
            'file': 'File Write',
            'log': 'Logging',
            'database': 'Database Write',
        }

        for sink in sink_types:
            self.add_node(Node(
                id=f"sink_{sink}",
                label=sink_icons.get(sink, sink),
                type='sink',
                properties={'data_type': sink},
            ))
            if 'sinks' not in self.subgraphs:
                self.subgraphs['sinks'] = []
            self.subgraphs['sinks'].append(f"sink_{sink}")

        # Add intermediate class nodes and edges
        classes_in_flow = set()
        for flow in flows_to_process:
            for class_name in flow.path:
                classes_in_flow.add(class_name)

        # Limit intermediate classes
        classes_list = list(classes_in_flow)[:self.MAX_CLASSES]

        for class_name in classes_list:
            short_name = class_name.split('.')[-1]
            node_id = self._safe_id(class_name)
            self.add_node(Node(
                id=node_id,
                label=short_name,
                type='class',
                properties={'full_name': class_name},
            ))
            if 'processing' not in self.subgraphs:
                self.subgraphs['processing'] = []
            self.subgraphs['processing'].append(node_id)

        # Add flow edges (only for classes that were included)
        classes_set = set(classes_list)
        for flow in flows_to_process:
            # Source to first class
            if flow.path and flow.path[0] in classes_set:
                first_class = self._safe_id(flow.path[0])
                self.add_edge(Edge(
                    source=f"source_{flow.source}",
                    target=first_class,
                    type='data_flow',
                    label=flow.data_type,
                ))

                # Last class to sink
                last_class_name = flow.path[-1]
                if last_class_name in classes_set:
                    last_class = self._safe_id(last_class_name)
                    self.add_edge(Edge(
                        source=last_class,
                        target=f"sink_{flow.sink}",
                        type='data_flow',
                    ))

    def _safe_id(self, name: str) -> str:
        """Create safe ID for Mermaid."""
        return name.replace('.', '_').replace('$', '_').replace('-', '_')

    def to_mermaid(self) -> str:
        """Convert to Mermaid flowchart."""
        lines = ["flowchart LR"]

        # Sources subgraph
        if 'sources' in self.subgraphs and self.subgraphs['sources']:
            lines.append("    subgraph sources[Data Sources]")
            for node_id in self.subgraphs['sources']:
                node = next((n for n in self.nodes if n.id == node_id), None)
                if node:
                    lines.append(f"        {node_id}(({node.label}))")
            lines.append("    end")

        # Processing subgraph
        if 'processing' in self.subgraphs and self.subgraphs['processing']:
            lines.append("    subgraph processing[Processing Classes]")
            for node_id in self.subgraphs['processing']:
                node = next((n for n in self.nodes if n.id == node_id), None)
                if node:
                    lines.append(f"        {node_id}[{node.label}]")
            lines.append("    end")

        # Sinks subgraph
        if 'sinks' in self.subgraphs and self.subgraphs['sinks']:
            lines.append("    subgraph sinks[Data Sinks]")
            for node_id in self.subgraphs['sinks']:
                node = next((n for n in self.nodes if n.id == node_id), None)
                if node:
                    lines.append(f"        {node_id}[/{node.label}/]")
            lines.append("    end")

        # Add edges
        for edge in self.edges:
            if edge.label:
                lines.append(f"    {edge.source} -.->|{edge.label}| {edge.target}")
            else:
                lines.append(f"    {edge.source} -.-> {edge.target}")

        # Style sources and sinks
        for node_id in self.subgraphs.get('sources', []):
            lines.append(f"    style {node_id} fill:#51cf66,stroke:#2f9e44")
        for node_id in self.subgraphs.get('sinks', []):
            lines.append(f"    style {node_id} fill:#ff6b6b,stroke:#c92a2a")

        return '\n'.join(lines)


class ClassHierarchyGraph(Graph):
    """Graph showing class inheritance and relationships."""

    MAX_CLASSES = 50  # Limit to prevent Mermaid overflow

    def __init__(self, structure: AppStructure, include_interfaces: bool = True):
        super().__init__(name="Class Hierarchy")
        self.include_interfaces = include_interfaces
        self._build(structure)

    def _build(self, structure: AppStructure) -> None:
        """Build class hierarchy graph."""
        # Only include Android components to keep diagram manageable
        components_to_show = []

        for class_name, class_info in structure.classes.items():
            if class_info.is_activity or class_info.is_service or class_info.is_receiver or class_info.is_provider or class_info.is_fragment:
                components_to_show.append((class_name, class_info))

        # Limit the number of components
        components_to_show = components_to_show[:self.MAX_CLASSES]
        component_names = {name for name, _ in components_to_show}

        for class_name, class_info in components_to_show:
            node_type = 'class'

            if class_info.is_activity:
                node_type = 'activity'
            elif class_info.is_service:
                node_type = 'service'
            elif class_info.is_receiver:
                node_type = 'receiver'
            elif class_info.is_provider:
                node_type = 'provider'
            elif class_info.is_fragment:
                node_type = 'fragment'

            self.add_node(Node(
                id=self._safe_id(class_name),
                label=class_info.name,
                type=node_type,
                properties={
                    'package': class_info.package,
                    'abstract': class_info.is_abstract,
                },
            ))

            # Group by component type instead of package for cleaner display
            if node_type not in self.subgraphs:
                self.subgraphs[node_type] = []
            self.subgraphs[node_type].append(self._safe_id(class_name))

            # Add inheritance edge only if parent is also shown
            if class_info.extends and class_info.extends in component_names:
                parent_name = class_info.extends
                self.add_edge(Edge(
                    source=self._safe_id(class_name),
                    target=self._safe_id(parent_name),
                    type='extends',
                    label='extends',
                ))

    def _safe_id(self, name: str) -> str:
        """Create safe ID for Mermaid."""
        return name.replace('.', '_').replace('$', '_').replace('-', '_')

    def to_mermaid(self) -> str:
        """Convert to Mermaid class diagram."""
        lines = ["classDiagram"]

        # Add classes with their type indicators
        for node in self.nodes:
            if node.type == 'interface':
                lines.append(f"    class {node.id} {{")
                lines.append(f"        <<interface>>")
                lines.append(f"    }}")
            elif node.type == 'activity':
                lines.append(f"    class {node.id} {{")
                lines.append(f"        <<Activity>>")
                lines.append(f"    }}")
            elif node.type == 'service':
                lines.append(f"    class {node.id} {{")
                lines.append(f"        <<Service>>")
                lines.append(f"    }}")
            elif node.type == 'fragment':
                lines.append(f"    class {node.id} {{")
                lines.append(f"        <<Fragment>>")
                lines.append(f"    }}")

        # Add relationships
        for edge in self.edges:
            if edge.type == 'extends':
                lines.append(f"    {edge.target} <|-- {edge.source}")
            elif edge.type == 'implements':
                lines.append(f"    {edge.target} <|.. {edge.source}")

        return '\n'.join(lines)


class EntryPointGraph(Graph):
    """Graph showing application entry points and attack surface."""

    def __init__(self, structure: AppStructure):
        super().__init__(name="Entry Points & Attack Surface")
        self._build(structure)

    def _build(self, structure: AppStructure) -> None:
        """Build entry point graph."""
        # Add entry point categories
        categories = {
            'launcher': [],
            'exported_activity': [],
            'exported_service': [],
            'exported_receiver': [],
            'exported_provider': [],
            'deeplink': [],
        }

        for entry in structure.entry_points:
            parts = entry.split(':', 1)
            entry_type = parts[0]
            entry_name = parts[1] if len(parts) > 1 else entry

            if entry_type == 'launcher':
                categories['launcher'].append(entry_name)
            elif entry_type == 'activity':
                categories['exported_activity'].append(entry_name)
            elif entry_type == 'service':
                categories['exported_service'].append(entry_name)
            elif entry_type == 'receiver':
                categories['exported_receiver'].append(entry_name)
            elif entry_type == 'provider':
                categories['exported_provider'].append(entry_name)
            elif entry_type == 'deeplink':
                categories['deeplink'].append(entry_name)

        # Add nodes for each category
        for category, entries in categories.items():
            if entries:
                self.subgraphs[category] = []
                for entry in entries:
                    node_id = self._safe_id(entry)
                    short_name = entry.split('.')[-1] if '.' in entry else entry
                    self.add_node(Node(
                        id=node_id,
                        label=short_name,
                        type=category,
                        properties={'full_name': entry},
                    ))
                    self.subgraphs[category].append(node_id)

    def _safe_id(self, name: str) -> str:
        """Create safe ID for Mermaid."""
        # Handle deeplink format
        name = name.replace('://', '_').replace('/', '_').replace(' -> ', '_to_')
        return name.replace('.', '_').replace('$', '_').replace('-', '_').replace('*', 'any')

    def to_mermaid(self) -> str:
        """Convert to Mermaid flowchart."""
        lines = ["flowchart TB"]

        # External attacker node
        lines.append("    attacker((Attacker))")

        category_labels = {
            'launcher': 'Main Entry',
            'exported_activity': 'Exported Activities',
            'exported_service': 'Exported Services',
            'exported_receiver': 'Broadcast Receivers',
            'exported_provider': 'Content Providers',
            'deeplink': 'Deep Links',
        }

        for category, node_ids in self.subgraphs.items():
            if node_ids:
                label = category_labels.get(category, category)
                lines.append(f"    subgraph {category}[{label}]")
                for node_id in node_ids[:10]:  # Limit for readability
                    node = next((n for n in self.nodes if n.id == node_id), None)
                    if node:
                        if category == 'deeplink':
                            lines.append(f"        {node_id}[/\"{node.label}\"/]")
                        elif category == 'launcher':
                            lines.append(f"        {node_id}[[\"{node.label}\"]]")
                        else:
                            lines.append(f"        {node_id}[\"{node.label}\"]")
                lines.append("    end")

        # Connect attacker to all entry points
        for category, node_ids in self.subgraphs.items():
            if node_ids:
                # Connect to first node of each category as representative
                first_node = node_ids[0]
                if category == 'launcher':
                    lines.append(f"    attacker --> {first_node}")
                else:
                    lines.append(f"    attacker -.-> {first_node}")

        # Style
        lines.append("    style attacker fill:#ff6b6b,stroke:#c92a2a")

        return '\n'.join(lines)
