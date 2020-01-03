from slither.core.variables.variable import Variable
from slither.core.declarations.function import Function

def get_CFGnode_Calls(node):
    '''
    :param node: cfg中的call节点
    :return: callee
    '''
    internalCalls = node.internal_calls
    externalCalls = []
    for external_call in node.high_level_calls:
        external_contract, external_function = external_call
        if isinstance(external_function, (Function)):
            externalCalls.append(external_function)
    return internalCalls + externalCalls


def getCFG_endNodes(function):
    cfgEndNodes = []
    for node in function.nodes:
        if len(node.sons) == 0:
            cfgEndNodes.append(node)
    return cfgEndNodes


def link_nodes(n1, n2):
    n1.add_son(n2)
    n2.add_father(n1)

def link_icfgNodes(n1, n2):
    n1.add_icfgSon(n2)
    n2.add_icfgFather(n1)

def link_backIcfgNodes(n1, n2):
    n1.add_backIcfgSon(n2)
    n2.add_backIcfgFather(n1)

def getadjMatrix(startToEndVertexList):
    vertexNum = len(startToEndVertexList)
    adjMatrix = [[0] * vertexNum for i in range(vertexNum)]
    for node in startToEndVertexList:
        for son in node.sons:
            adjMatrix[startToEndVertexList.index(node)][startToEndVertexList.index(son)] = 1
    return adjMatrix

def getICFGadjMatrix(startToEndVertexList):
    vertexNum = len(startToEndVertexList)
    adjMatrix = [[0] * vertexNum for i in range(vertexNum)]
    count = 3
    for node in startToEndVertexList:
        for son in node.sons:
            adjMatrix[startToEndVertexList.index(node)][startToEndVertexList.index(son)] = 1
        for son in node.icfgSons:
            adjMatrix[startToEndVertexList.index(node)][startToEndVertexList.index(son)] = count
            adjMatrix[startToEndVertexList.index(son)][startToEndVertexList.index(node)] = count-1
            count += 2
    return adjMatrix

def defenseModifier():
    defenseModifierList = ['onlyOwner', 'ownerOnly', 'isAnOwner', 'onlyPartner', 'noFromContract', 'nonReentrant', 'noReentrancy', 'isYHT', 'onlyHuman', 'onlyAdmin', 'onlyPlayer', 'isWhitelisted', 'notContract', 'isHuman', 'noFromContract', 'onlyOwnerOrPartner', 'reentrancy', 'onlyManager', 'onlywhitelisted']
    return defenseModifierList