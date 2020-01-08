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
# from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.detectors.ICFG_Reentrancy.smallUtils import defenseModifier
from slither.detectors.ICFG_Reentrancy.smallUtils import getadjMatrix
from slither.detectors.ICFG_Reentrancy.testDFS import MyDeepGraph
from slither.core.declarations import SolidityVariableComposed


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

    def requireMsgSender(self, function):
        from slither.analyses.data_dependency.data_dependency import is_dependent
        for modifier in function.modifiers:
            for node in modifier.nodes:
                if node.contains_require_or_assert():
                    solidity_var_read = node.solidity_variables_read
                    if solidity_var_read:
                        for v in solidity_var_read:
                            if v.name == 'msg.sender':
                                return True
                        #return any(v.name == 'msg.sender' for v in solidity_var_read)
                    # for variable in node.variables_read:
                    #     if variable.name == 'msg.sender':
                    #     #if is_dependent(variable, SolidityVariableComposed('msg.sender'), function.contract):
                    #         return True

        for node in function.nodes:
            if node.contains_require_or_assert():
                solidity_var_read = node.solidity_variables_read
                if solidity_var_read:
                    for v in solidity_var_read:
                        if v.name == 'msg.sender':
                            return True
        # if function.is_protected():
        #     return True
        return False
                    #return any(v.name == 'msg.sender' for v in solidity_var_read)
        # variables_readInrequireOrAssert = function.reading_in_require_or_assert()
        # for variable in variables_readInrequireOrAssert:
        #     # if is_dependent(variable, SolidityVariableComposed('msg.sender'), function.contract):
        #     #     return True
        #     if variable:
        #         if variable.name == 'msg.sender':
        #             return True
        # return False

    def advancedUpdateEth(self, function):
        from slither.analyses.data_dependency.data_dependency import is_dependent

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

            for path in allPaths_Node[:]:

                careifNodeStack = []
                care_if_StateVariablesRead = set()
                care_RequireOrAssert_StateVariableRead = set()
                state_variables_written = set()
                for node in path:  # [start, end]    # 直接转帐函数cfg上的路径节点
                    if node.contains_require_or_assert():
                        care_RequireOrAssert_StateVariableRead |= set(node.state_variables_read)
                    state_variables_written |= set(node.state_variables_written)
                    if node.type == NodeType.IF:
                        for son in node.sons:
                            if son.type == NodeType.THROW or son.type == NodeType.RETURN:
                                careifNodeStack.append(node)
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
                                # allPaths_Node.remove(path)

                else:  # 如果 转账语句不在if block中
                    for stateVariableWritten in state_variables_written:
                        for careStateVariableRead in care_RequireOrAssert_StateVariableRead:
                            result = is_dependent(stateVariableWritten, careStateVariableRead, function.contract)
                            if result == True:
                                return True
                                #allPaths_Node.remove(path)
                                #return False
            # if allPaths_Node:
            #     return False
        return False

    def advancedUpdateEth_2(self, function):
        from slither.analyses.data_dependency.data_dependency import is_dependent
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
                for ir in path[-1].irs:
                    if isinstance(ir, (HighLevelCall, LowLevelCall, Transfer, Send)):
                        if ir.call_value:
                            for node in path[0:len(path)-1]:
                                for stateVariableWritten in node.state_variables_written:
                                    if is_dependent(ir.call_value, stateVariableWritten, function.contract):
                                        return True
                                    # elif is_dependent(stateVariableWritten, ir.call_value, function.contract):
                                    #     return True
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




