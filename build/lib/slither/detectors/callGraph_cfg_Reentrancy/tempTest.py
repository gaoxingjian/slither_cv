from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph

def test():
    graph = MyGraph(7)
    lian = [[0, 1], [1, 4], [4, 5], [5, 1], [4, 6]]
    for item in lian:
        graph.addEdge(item[0]+1, item[1]+1)
    for gitem in graph.adjMat():
        print(gitem)

    allPaths = graph.findAllPathBetweenTwoNodes(1, 7)
    for path in allPaths:
        print(path)
    # a = [[0] * 3for i in range(4)]
    # print(a)
    # print(set([1,3]))
    # a = set()
    # a.add(4)
    # a.add(5)
    # print(a)
#test()
import copy
class C:
    def __init__(self):
        self.age = 18
class A:
    def __init__(self):
        self.num = 10
        self.c = C()
def test2():
    a = []
    print(a == None)
test2()
