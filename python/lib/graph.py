import csv


def read_input_csv(vertices_file, arcs_file):
    """
    Read the generated attack graph VERTICES.CSV and ARCS.CSV and re-construct the attack graph in Python.
    Args:
        vertices_file (): path to VERTICES.CSV, where the final probabilities are already computed
        arcs_file (): path to ARCS.CSV
    Returns:
        a Graph object
    """
    with open(vertices_file) as f_vert:
        nodes_list = []
        for row in csv.reader(f_vert, delimiter=','):
            nodes_list.append(row)

    with open(arcs_file) as f_arc:
        edges_list = []
        for row in csv.reader(f_arc, delimiter=','):
            edges_list.append(row)

    return nodes_list, edges_list


class Graph:
    def __init__(self, nodes_list, edges_list):
        """
        Construct the attack graph in Python
        Args:
            nodes_list (): the list of nodes from Java attack graph object, where the probs are already final
            edges_list (): the list of edges from Java attack graph object
        """
        self.nodes = {}
        self.edges = []

        for (node_id, desc, node_type, prob) in nodes_list:
            node_id = int(node_id)
            prob = float(prob)

            if node_type == 'LEAF':
                node_type = 'primitive'

            if 'GOAL ' in desc:
                desc = desc[6:-1]

            # Set all of the nodes for the Graph object
            self.nodes[node_id] = Node(node_id, node_type, desc, prob)

        for (dst, src, _) in edges_list:
            dst = int(dst)
            src = int(src)

            # Set all of the edges for the Graph object
            self.edges.append((src, dst))

            # Update the `succ` and `preds` field of the Node object
            self.nodes[src].succ.append(dst)
            self.nodes[dst].preds.append(src)

        # Update the `is_goal` field of the
        for node in self.nodes:
            if not self.nodes[node].succ:
                self.nodes[node].is_goal = True


class Node:
    def __init__(self, node_id, node_type, desc, prob):
        """

        Args:
            node_id (): id of the node
            node_type (): three types: AND, OR, LEAF
            desc (): boolean variable indicating whether the node is the attack goal node
            prob (): the node probability has already been computed by the Java program
        """
        self.node_id = node_id
        self.node_type = node_type
        self.desc = desc
        self.prob = prob

        self.is_goal = False
        self.preds = []
        self.succ = []
        self.severity = 0
