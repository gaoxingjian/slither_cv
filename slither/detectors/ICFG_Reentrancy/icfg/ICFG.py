from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.function import Function
from slither.core.callGraph.functionNode import FunctionNode
from slither.core.variables.variable import Variable
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph
from slither.detectors.ICFG_Reentrancy.smallUtils import (get_CFGnode_Calls, getCFG_endNodes, link_nodes, link_icfgNodes, link_backIcfgNodes)
from slither.core.cfg.node import (Node, NodeType)
from slither.solc_parsing.cfg.node import NodeSolc



class ICFG:
    def __init__(self, slither):
        self._slither = slither
        self.allNodes = []
        self.visitedList = []
    def build_ICFG(self):
        id = 100
        for function in self._slither.functions:
            if not function.is_implemented:
                continue
            if function in self.visitedList:
                return
            self.visitedList.append(function)
            for node in function.nodes:
                callees = get_CFGnode_Calls(node)
                if callees:
                    dummInode = NodeSolc(NodeType.DUMMY, id)
                    function.addNode(dummInode)
                    dummInode.set_function(function)
                    dummInode.set_sons(node.sons)
                    node.set_sons([])
                    link_nodes(node, dummInode)
                    id = id + 1
                # if any(callee.is_implemented for callee in callees):
                #     link_nodes(node, Node(NodeType.DUMMY, id))
                #     id -= 1
                #     dummyInode = Node(NodeType.DUMMY, id)
                #     dummyInode.set_sons(node.sons)
                #     node.set_sons([])
                #     link_icfgNodes(node, dummyInode)
                #     link_nodes(node, dummyInode)
                for callee in callees:
                    #print('被调用函数的名字：{}'.format(callee.full_name))
                    # node.add_icfgSon(callee.entry_point)
                    if callee.entry_point is None:
                        continue
                    # dummyInode = Node(NodeType.DUMMY, id)
                    # dummyInode.set_fathers(node.sons)
                    # node.set_sons([])
                    # link_nodes(node, dummyInode)
                    # id -= 1
                    link_icfgNodes(node, callee.entry_point)
                    callee_cfgEndNodes = getCFG_endNodes(callee)
                    for callee_cfgEndNode in callee_cfgEndNodes:
                        # for cfgSon in node.sons:
                        link_backIcfgNodes(callee_cfgEndNode, node.sons[0])
            self.allNodes.extend(function.nodes)


