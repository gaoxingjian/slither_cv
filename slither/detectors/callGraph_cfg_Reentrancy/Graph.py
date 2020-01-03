class MyGraph(object):
    def __init__(self, node_num):   # node_num代表节点数量
        self._vertexList = []
        self._adjMat = [[0] * (node_num+2) for i in range(node_num+2)]
        self._node_num = node_num   # 节点数量

    def adjMat(self):
        return self._adjMat

    def addEdge(self, node_index, node2_index):  # 传递实参的时候就要+1，也就是说node_index 是 对_adjMat来说的
        self._adjMat[node_index][node2_index] = 1   # 起始节点node_index = 1 而不是0

    def findAllPathBetweenTwoNodes(self, start, end):  # 开始节点（start）对应与mat中的索引也就是1。end也是+1后传进来的
        is_in_stack = [False] * (self._node_num+2)  # 入栈状态变量
        node_stack = []
        path = []  # 存储单条路径
        allPaths = []  # 存储所有路径

        node_stack.append(start)  # 起点入栈，开始节点（start）对应与mat中的索引也就是1，这时is_in_stack[1]应该置为True
        is_in_stack[1] = True  # 设置起点已入栈，true表示在栈中，false表示不在
        c_position = 1
        while len(node_stack) != 0:
            #print('ma')
            top_element = node_stack[-1]

            if top_element == end:
                while len(node_stack) != 0:
                    temp = node_stack[-1]
                    node_stack.pop()
                    path.append(temp)
                allPaths.append(path)
                for item in reversed(path):
                    node_stack.append(item)
                path = []  # 清除单条路径
                node_stack.pop()
                is_in_stack[top_element] = False
                c_position = node_stack[-1]    # 记录位置，以便从该位置之后进行搜索
                top_element = node_stack[-1]
                node_stack.pop()
                is_in_stack[top_element] = False
            else:
                index = 0
                for i in range(c_position+1, self._node_num+2):  # i 是列索引
                    index = i
                    if (is_in_stack[i] is False) and (self._adjMat[top_element][i] != 0):
                        is_in_stack[i] = True

                        node_stack.append(i)
                        c_position = 1  # 位置置临街矩阵第一列，是因为从记录的位置开始搜索完以后，在新的行上搜索，自然从零开始，以免漏掉节点
                        break
                if index == self._node_num+1:

                    top_element = node_stack[-1]

                    is_in_stack[top_element] = False

                    c_position = node_stack[-1]
                    node_stack.pop()
        return allPaths
