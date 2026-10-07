import networkx as nx
from graphviz import Digraph
from typing import Set
from .cfg_defs import Function, BasicBlock, FunctionCall, PosBlock, CFGCache
from .cfg_builder import CFG


class CFGVisualizer:
    def __init__(self, cfg=None):
        self.cfg = cfg
        self.graph = nx.DiGraph()
        self.dot = Digraph()
        self.processed_functions: Set[Function] = set()

    def escape_label(self, label: str) -> str:
        # Escape special characters
        # label = label.replace('\\', '').replace('"', '').replace(':', '')
        return label.split("::")[-1]

    def draw_graph(self):
        # Create a Digraph object for visualization
        for node, data in self.graph.nodes(data=True):
            self.dot.node(node, label=data["label"])

        # Add edges to the Digraph
        for edge in self.graph.edges(data=True):
            src, dst, data = edge
            label = data["label"]
            self.dot.edge(src, dst, label=label)

    def build_graph(self):
        traversal_result = self.cfg.bfs_traverse_cfg()
        for function, basic_blocks in traversal_result:
            for bb in basic_blocks:
                node_id = self.escape_label(f"{function.qualified_name}_{bb.block_id}")
                self.graph.add_node(node_id, label=node_id)

                for succ_bb, edge_type in bb.successor_blocks.items():
                    succ_node_id = self.escape_label(
                        f"{function.qualified_name}_{succ_bb.block_id}"
                    )
                    self.graph.add_edge(node_id, succ_node_id, label=edge_type)

    def visualize(self, output_file):
        self.build_graph()
        self.draw_graph()
        self.dot.format = "png"
        self.dot.render(output_file, format="png", cleanup=True)
        self.dot.view(f"{output_file}")
