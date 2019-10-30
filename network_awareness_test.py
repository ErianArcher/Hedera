import unittest
from collections import deque

import networkx as nx

"""
    Two functions that need to be tested
"""
def neighbors(graph, src, exclusive=None):
	src_neighbors = nx.neighbors(graph, src)
	if exclusive in src_neighbors:
		src_neighbors.remove(exclusive)
	return src_neighbors

def bfs_tree(graph, source, depth_limit=None, exclusive_neighbor=None):
	visited = {source}

	if not depth_limit:
		depth_limit = len(graph)

	queue = deque([(source, depth_limit, neighbors(graph, source, exclusive_neighbor))])
	tree = {}
	while queue:
		parent, depth_now, children = queue.pop()
		next_children = []
		for child in children:
			if child not in visited:
				next_children.append(child)
				visited.add(child)
				if depth_now > 1:
					queue.append((child, depth_now - 1, neighbors(graph, child)))
		if next_children:
			tree[parent] = next_children
	return tree

class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.graph = nx.DiGraph()
        self.graph.add_path([0, 1, 2])
        self.graph.add_path([0, 2, 3])
        self.graph.add_path([1, 4, 5])

    def testNeighbors(self):
        neighbors_of_zero = neighbors(self.graph, 0)
        self.assertEqual(neighbors_of_zero, [1, 2])
        neighbors_of_zero_ex1 = neighbors(self.graph, 0, exclusive=1)
        self.assertEqual(neighbors_of_zero_ex1, [2])
        neighbors_of_one = neighbors(self.graph, 1)
        self.assertEqual(neighbors_of_one, [2, 4])

    def testBfsTree(self):
        bfs_tree_from_zero_base = {0: [1, 2], 1: [4], 2: [3], 4: [5]}
        bfs_tree_from_zero_ex2_base = {0: [1], 1: [2, 4], 2: [3], 4: [5]}
        bfs_tree_from_zero = bfs_tree(self.graph, 0)
        bfs_tree_from_zero_ex2 = bfs_tree(self.graph, 0, exclusive_neighbor=2)
        self.assertDictEqual(bfs_tree_from_zero, bfs_tree_from_zero_base)
        print bfs_tree_from_zero
        self.assertDictEqual(bfs_tree_from_zero_ex2, bfs_tree_from_zero_ex2_base)
        print bfs_tree_from_zero_ex2

if __name__ == '__main__':
    unittest.main()
