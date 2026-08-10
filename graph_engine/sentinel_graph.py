import sqlite3
import json
import os
import re
import logging
from typing import List, Dict, Any, Tuple, Set

logging.basicConfig(level=logging.INFO, format="[GRAPH ENGINE] %(asctime)s - %(message)s")
logger = logging.getLogger("SentinelGraph")

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Calculates Jaro-Winkler string similarity score between 0.0 and 1.0."""
    s1, s2 = s1.lower().strip(), s2.lower().strip()
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    match_distance = (max(len(s1), len(s2)) // 2) - 1
    match_distance = max(0, match_distance)

    s1_matches = [False] * len(s1)
    s2_matches = [False] * len(s2)

    matches = 0
    transpositions = 0

    for i in range(len(s1)):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len(s2))
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] == s2[j]:
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len(s1)):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (matches / len(s1) + matches / len(s2) + (matches - transpositions / 2) / matches) / 3.0
    
    # Winkler prefix scale adjustment
    prefix = 0
    for i in range(min(4, min(len(s1), len(s2)))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + prefix * 0.1 * (1 - jaro)

class SentinelGraphEngine:
    """
    Embedded Graph Engine & Cross-Precinct Alias Resolution.
    Provides multi-hop link analysis and automated entity disambiguation 
    over extracted NIEM investigative entities.
    """
    def __init__(self, db_path: str = "sentinel_graph.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Nodes Table (Entities: Suspect, Vehicle, Phone, Case)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    canonical_name TEXT,
                    entity_type TEXT,
                    master_node_id TEXT,
                    attributes_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Edges Table (Relationships)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_node_id TEXT,
                    target_node_id TEXT,
                    relationship_type TEXT,
                    weight REAL DEFAULT 1.0,
                    case_ref TEXT,
                    FOREIGN KEY(source_node_id) REFERENCES graph_nodes(node_id),
                    FOREIGN KEY(target_node_id) REFERENCES graph_nodes(node_id)
                )
            """)
            # Aliases Index Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_aliases (
                    alias_id TEXT PRIMARY KEY,
                    alias_name TEXT,
                    node_id TEXT,
                    confidence_score REAL,
                    FOREIGN KEY(node_id) REFERENCES graph_nodes(node_id)
                )
            """)
            conn.commit()

    def add_entity(self, name: str, entity_type: str, attributes: Dict[str, Any] = None, case_ref: str = "UNKNOWN") -> str:
        clean_name = name.strip()
        node_id = f"{entity_type.lower()}_{re.sub(r'[^a-zA-Z0-9]', '_', clean_name.lower())}"
        attributes = attributes or {}

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO graph_nodes (node_id, canonical_name, entity_type, master_node_id, attributes_json)
                VALUES (?, ?, ?, ?, ?)
            """, (node_id, clean_name, entity_type, node_id, json.dumps(attributes)))

            # Add primary alias
            alias_id = f"alias_{node_id}"
            cursor.execute("""
                INSERT OR IGNORE INTO entity_aliases (alias_id, alias_name, node_id, confidence_score)
                VALUES (?, ?, ?, 1.0)
            """, (alias_id, clean_name, node_id))
            conn.commit()

        return node_id

    def add_relationship(self, source_id: str, target_id: str, relationship: str, case_ref: str = "UNKNOWN") -> str:
        edge_id = f"edge_{source_id}_{target_id}_{re.sub(r'[^a-zA-Z0-9]', '_', relationship.lower())}"
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO graph_edges (edge_id, source_node_id, target_node_id, relationship_type, case_ref)
                VALUES (?, ?, ?, ?, ?)
            """, (edge_id, source_id, target_id, relationship, case_ref))
            conn.commit()
        return edge_id

    def multi_hop_search(self, start_node_id: str, max_hops: int = 2) -> Dict[str, Any]:
        """
        Executes a multi-hop graph breadth-first traversal (BFS) starting from target entity.
        Returns connected nodes, edges, and hop distances.
        """
        visited_nodes = {}
        traversed_edges = []
        queue = [(start_node_id, 0)]
        visited_nodes[start_node_id] = 0

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            while queue:
                current_id, current_hop = queue.pop(0)
                if current_hop >= max_hops:
                    continue

                # Query outgoing & incoming edges
                cursor.execute("""
                    SELECT edge_id, source_node_id, target_node_id, relationship_type, case_ref 
                    FROM graph_edges 
                    WHERE source_node_id = ? OR target_node_id = ?
                """, (current_id, current_id))

                rows = cursor.fetchall()
                for row in rows:
                    eid, src, tgt, rel, case_ref = row
                    neighbor_id = tgt if src == current_id else src

                    traversed_edges.append({
                        "edge_id": eid,
                        "source": src,
                        "target": tgt,
                        "relationship": rel,
                        "case_ref": case_ref
                    })

                    if neighbor_id not in visited_nodes:
                        visited_nodes[neighbor_id] = current_hop + 1
                        queue.append((neighbor_id, current_hop + 1))

            # Retrieve node details
            node_details = []
            for nid, hop in visited_nodes.items():
                cursor.execute("SELECT node_id, canonical_name, entity_type, attributes_json FROM graph_nodes WHERE node_id = ?", (nid,))
                row = cursor.fetchone()
                if row:
                    node_details.append({
                        "node_id": row[0],
                        "canonical_name": row[1],
                        "entity_type": row[2],
                        "hop_distance": hop,
                        "attributes": json.loads(row[3])
                    })

        return {
            "start_node_id": start_node_id,
            "max_hops": max_hops,
            "connected_nodes": node_details,
            "relationships": traversed_edges
        }

    def resolve_aliases(self, similarity_threshold: float = 0.85) -> List[Dict[str, Any]]:
        """
        Performs cross-precinct alias resolution using Jaro-Winkler & Levenshtein metrics.
        Identifies duplicate entities (e.g. 'Johnathan Doe' & 'Johnny Doe') and merges master node links.
        """
        merged_pairs = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT node_id, canonical_name, entity_type FROM graph_nodes")
            nodes = cursor.fetchall()

            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    n1_id, n1_name, n1_type = nodes[i]
                    n2_id, n2_name, n2_type = nodes[j]

                    if n1_type != n2_type:
                        continue

                    # Calculate string similarity score
                    jw_score = jaro_winkler_similarity(n1_name, n2_name)
                    lev_dist = levenshtein_distance(n1_name.lower(), n2_name.lower())

                    if jw_score >= similarity_threshold or lev_dist <= 2:
                        # Link master_node_id
                        master_id = min(n1_id, n2_id)
                        sub_id = max(n1_id, n2_id)

                        cursor.execute("UPDATE graph_nodes SET master_node_id = ? WHERE node_id = ?", (master_id, sub_id))
                        
                        merged_pairs.append({
                            "master_node_id": master_id,
                            "resolved_alias_node_id": sub_id,
                            "name_1": n1_name,
                            "name_2": n2_name,
                            "similarity_score": round(jw_score, 4),
                            "edit_distance": lev_dist
                        })

            conn.commit()

        logger.info(f"Alias resolution complete. Resolved {len(merged_pairs)} entity cluster(s).")
        return merged_pairs
