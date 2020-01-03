from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph


def getCfgAllPath(startToendList):
    node_num = len(startToendList)
    myGraph = MyGraph(node_num)
    for node in startToendList[0:node_num - 1]:
        for son in node.sons:
            myGraph.addEdge(startToendList.index(node) + 1, startToendList.index(son) + 1)
    allPaths = myGraph.findAllPathBetweenTwoNodes(0 + 1, (len(startToendList) - 1) + 1)
    return allPaths

def getIcfgAllPath(startToendList):
    node_num = len(startToendList)
    myGraph = MyGraph(node_num)
    for node in startToendList[0:node_num - 1]:
        for son in node.sons + node.icfgSons + node.backIcfgSons:
            myGraph.addEdge(startToendList.index(node) + 1, startToendList.index(son) + 1)
    allPaths = myGraph.findAllPathBetweenTwoNodes(0 + 1, (len(startToendList) - 1) + 1)
    return allPaths