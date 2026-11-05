"""Entity relationship mapping using NetworkX.

Builds a graph of extracted entities and their co-occurrence relationships
within an investigation. Used to feed the React Flow entity relationship view
(Phase 8).
"""
from typing import List, Dict, Any
import networkx as nx


class RelationshipMapper:
    def build_graph(self, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a node/edge graph from extracted entities."""
        graph = nx.Graph()
        for entity in entities:
            graph.add_node(entity.get("value", ""), type=entity.get("entity_type", "unknown"))

        return {
            "nodes": [{"id": n, "data": {"label": n, "type": d.get("type", "unknown")}} for n, d in graph.nodes(data=True)],
            "edges": [],
            "note": "Relationship mapping not yet fully implemented (Phase 8); returning node-only fallback.",
        }