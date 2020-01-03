from slither.core.cfg.node import NodeType
from slither.core.declarations import Function, SolidityFunction, SolidityVariable
from slither.core.expressions import UnaryOperation, UnaryOperationType
from slither.detectors.abstract_detector import (AbstractDetector,
                                                 DetectorClassification)
from slither.slithir.operations import (HighLevelCall, LowLevelCall,
                                        LibraryCall,
                                        Send, Transfer)
from slither.core.variables.variable import Variable
from slither.detectors.callGraph_cfg_Reentrancy.getAallPaths import getCfgAllPath
from slither.core.cfg.node import NodeType
from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.detectors.ICFG_Reentrancy.smallUtils import defenseModifier
from slither.detectors.ICFG_Reentrancy.smallUtils import getadjMatrix
from slither.detectors.ICFG_Reentrancy.testDFS import MyDeepGraph


def allPaths_intToNode(allPathsInt, startToEndNodes):
    allPathsNode = []
    for path in allPathsInt:
        tempPath = []
        for i in path:
            tempPath.append(startToEndNodes[i])  # 原来是有-1的
        allPathsNode.append(tempPath)
    return allPathsNode


class DM:
    def __init__(self, function):
        self.function = function

    def advancedUpdateEth(self, function):
        allNodes = function.nodes
        for ethNode in function.ethNodes:

            entryPointToethNode = []
            entryPointToethNode.append(function.entry_point)
            pilotProcessNodes = list(set(allNodes) - set([function.entry_point, ethNode]))
            entryPointToethNode.extend(pilotProcessNodes)
            entryPointToethNode.append(ethNode)

            adjMatrix = getadjMatrix(entryPointToethNode)
            mydeepGraph = MyDeepGraph(len(entryPointToethNode))
            mydeepGraph.setadjMetrix(adjMatrix)
            allPaths = mydeepGraph.getPathofTwoNode(0, len(entryPointToethNode) - 1)
            allPaths_Node = allPaths_intToNode(allPaths, entryPointToethNode)

            for path in allPaths_Node:
                careifNodeStack = []
                care_if_StateVariablesRead = set()
                care_RequireOrAssert_StateVariableRead = set()
                state_variables_written = set()
                for node in path:  # [start, end]
                    if node.contains_require_or_assert():
                        care_RequireOrAssert_StateVariableRead |= set(node.state_variables_read)
                    state_variables_written |= set(node.state_variables_written)
                    if node.type == NodeType.IF:
                        careifNodeStack.append(node)
                    if node.type == NodeType.ENDIF:
                        if careifNodeStack:
                            careifNodeStack.pop()
                if careifNodeStack:  # eth被包裹在if中
                    for careifNode in careifNodeStack:
                        care_if_StateVariablesRead |= set(careifNode.state_variables_read)
                    for stateVariableWritten in state_variables_written:
                        for careStateVariableRead in care_if_StateVariablesRead | care_RequireOrAssert_StateVariableRead:
                            result = is_dependent(stateVariableWritten, careStateVariableRead, function.contract)
                            if result == True:
                                return True

                else:  # 如果 转账语句不在if block中
                    for stateVariableWritten in state_variables_written:
                        for careStateVariableRead in care_RequireOrAssert_StateVariableRead:
                            result = is_dependent(stateVariableWritten, careStateVariableRead, function.contract)
                            if result == True:
                                return True

        return False

    def privateVisibility(self, function):
        if function.visibility == 'private':
            return True
        return False

    def haveDefenseModifier(self, function):
        defenseModifiers = defenseModifier()
        if any(modifier.name in defenseModifiers for modifier in function.modifiers):
            return True
        return False




