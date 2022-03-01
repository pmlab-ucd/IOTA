import sys
from math import log
from copy import deepcopy
from typing import Dict, List

from lib.graph import Graph, read_input_csv


class TraceNode:
    def __init__(self, id):
        self.id = id
        self.preds = []


def shortest_trace(graph, node):
    """
    Compute the shortest attack trace to the specified attack goal node
    Args:
        graph (): a Graph object
        node (): a specified attack goal node

    Returns:
        a tuple of (the minimum depth, the actual trace)
    """
    res_node = TraceNode(node)

    if graph.nodes[node].node_type == 'primitive':
        return 0, res_node

    # If the current node is an OR node, then take the minimum of predecessors
    if graph.nodes[node].node_type == 'OR':
        pred_list = graph.nodes[node].preds

        (min_depth, min_pred_node) = shortest_trace(graph, pred_list[0])
        res_node.preds.append(min_pred_node)

        for i in range(1, len(pred_list)):
            (cur_depth, cur_pred_node) = shortest_trace(graph, pred_list[i])
            if cur_depth < min_depth:
                min_depth = cur_depth
                min_pred_node = cur_pred_node
                res_node.preds.pop()
                res_node.preds.append(min_pred_node)

        return min_depth + 1, res_node

    # If the current node is an AND node, then take the maximum of predecessors
    if graph.nodes[node].node_type == 'AND':
        pred_list = graph.nodes[node].preds

        (max_depth, max_pred_node) = shortest_trace(graph, pred_list[0])
        res_node.preds.append(max_pred_node)

        for i in range(1, len(pred_list)):
            (cur_depth, cur_pred_node) = shortest_trace(graph, pred_list[i])
            res_node.preds.append(cur_pred_node)
            if cur_depth > max_depth:
                max_depth = cur_depth

        return max_depth + 1, res_node


def blast_radius(graph):
    """
    Compute the blast radius of each vulnerability in the attack graph
    Args:
        graph (): a Graph object representing the attack graph

    Returns:
        a dictionary from `vulnerability node id` to `the list of derivation nodes`
    """
    class Vul:
        def __init__(self, node_id, desc):
            self.node_id = node_id
            self.desc = desc

    vul_list: List[Vul] = []
    for node in graph.nodes:
        if graph.nodes[node].node_type == 'primitive' and 'vulExists(' in graph.nodes[node].desc:
            vul_list.append(Vul(node, graph.nodes[node].desc))

    queue = []
    node_vul_evidences: Dict[int, List[Dict[int, int]]] = {}

    # Initialize node_vul_evidences for all of the primitive fact nodes
    for node in graph.nodes:
        node_vul_evidences[node] = [dict(zip(range(len(vul_list)), [0] * len(vul_list)))]
        if graph.nodes[node].node_type == 'primitive' and 'vulExists(' in graph.nodes[node].desc:
            for i in range(len(vul_list)):
                if graph.nodes[node].desc == vul_list[i].desc:
                    node_vul_evidences[node][0][i] += 1

            for child in graph.nodes[node].succ:
                if child not in queue:
                    queue.append(child)

    # Iteratively update the `node_vul_evidences` for nodes in the `queue`
    while len(queue) != 0:
        cur_node = queue.pop(0)
        cur_vul_evidence = deepcopy(node_vul_evidences[graph.nodes[cur_node].preds[0]])
        for i in range(1, len(graph.nodes[cur_node].preds)):
            if graph.nodes[cur_node].node_type == 'AND':
                cur_vul_evidence = merge_ve_and(cur_vul_evidence, node_vul_evidences[graph.nodes[cur_node].preds[i]], vul_list)
            elif graph.nodes[cur_node].node_type == 'OR':
                cur_vul_evidence = merge_ve_or(cur_vul_evidence, node_vul_evidences[graph.nodes[cur_node].preds[i]])
        node_vul_evidences[cur_node] = cur_vul_evidence

        for child in graph.nodes[cur_node].succ:
            if child not in queue:
                queue.append(child)

    return determine_br(graph, node_vul_evidences, vul_list)


def merge_ve_or(vul_evidence1, vul_evidence2):
    """
    Merge vulnerability evidences for two parent nodes. The child node is an`OR` node.
    Args:
        vul_evidence1 (): vulnerability evidence for parent node 1
        vul_evidence2 (): vulnerability evidence for parent node 2

    Returns:
        the merged vulnerability evidence for the child `OR` node

    Example:
        >>> node_vul_evidences
        {4: [{1: 0, 2: 1, 3: 0}, {1: 0, 2: 0, 3: 1}]}

        >>> vul_evidence1 = node_vul_evidences[4]
        >>> vul_evidence1
        [{1: 0, 2: 1, 3: 0}, {1: 0, 2: 0, 3: 1}]

        >>> foot_print1 = vul_evidence1[0]
        >>> foot_print1
        {1: 0, 2: 1, 3: 0}

        >>> foot_print1 in vul_evidence1
        True
    """
    merged_vul_evidence = deepcopy(vul_evidence1)
    for vul_footprint in vul_evidence2:
        if vul_footprint not in vul_evidence1:
            merged_vul_evidence.append(vul_footprint)
    return merged_vul_evidence


def merge_ve_and(vul_evidence1, vul_evidence2, vul_list):
    """
    Merge vulnerability evidences for two parent nodes. The child node is an`AND` node.
    Args:
        vul_evidence1 (): vulnerability evidence for parent node 1
        vul_evidence2 (): vulnerability evidence for parent node 2
        vul_list (): the list of all of the vulnerabilities in the given attack graph

    Returns:
        the merged vulnerability evidence for the child `AND` node
    """
    merged_vul_evidence = []
    for vul_footprint1 in vul_evidence1:
        for vul_footprint2 in vul_evidence2:
            merged_footprint = dict(zip(range(len(vul_list)), [0]*len(vul_list)))
            for vul_index in range(len(vul_list)):
                merged_footprint[vul_index] = max(vul_footprint1[vul_index], vul_footprint2[vul_index])
            if merged_footprint not in merged_vul_evidence:
                merged_vul_evidence.append(merged_footprint)
    return merged_vul_evidence


def determine_br(graph, node_vul_evidences, vul_list):
    """
    Determine the blast radius for each vulnerability in the attack graph
    Args:
        node_vul_evidences (): vulnerability evidence for all of the nodes in the attack graph
        Example vul_evidences = {4: [{1: 0, 2: 1, 3: 0}, {1: 0, 2: 0, 3: 1}]} means node 4 has two
        vulnerability footprints, the first one being {1: 0, 2: 1, 3: 0} and the second one being {1: 0, 2: 0, 3: 1}
        vul_list (): the list of all of the vulnerabilities in the given attack graph

    Returns:
        blast radius for each vulnerability in the attack graph

    Example:
        >>> br = {3: [1, 5, 43, 49], 12: [], 17: [15], 21: [15], 26: [24, 36, 39, 41], 29: [], 32: [30, 33, 46, 51]}
        >>> br[3]
        [1, 5, 43, 49]
        means the blast radius of `vulnerability node 3` contains derivation node 1, 5, 43, 49
    """
    br = {}
    for i in range(len(vul_list)):
        br[vul_list[i].node_id] = []
    for node in node_vul_evidences:
        if graph.nodes[node].node_type == 'OR':
            for foot_print in node_vul_evidences[node]:
                vul_count = sum(foot_print.values())
                if vul_count == 1:
                    key = find_key_from_dict(foot_print)
                    br[vul_list[key].node_id].append(node)
    return br


def find_key_from_dict(d):
    """
    Return the key of the dictionary whose corresponding value is 1.
    Args:
        d (): a dictionary such as {0: 1, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0}

    Returns:
        0
    """
    for key in d:
        if d[key] == 1:
            return key
