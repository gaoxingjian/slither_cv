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
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.expression import Expression
from slither.core.expressions.tuple_expression import TupleExpression
from slither.core.expressions.identifier import Identifier
from slither.slithir.operations.binary import Binary
from slither.slithir.operations.unary import Unary
from slither.slithir.operations.condition import Condition
from slither.slithir.operations.assignment import Assignment
from z3 import *

CONTROL_SYMBOL = ['&&', '||', '==', '!=', '!']
import re

def allPaths_intToNode(allPathsInt, startToEndNodes):
    allPathsNode = []
    for path in allPathsInt:
        tempPath = []
        for i in path:
            tempPath.append(startToEndNodes[i])  # 原来是有-1的
        allPathsNode.append(tempPath)
    return allPathsNode

def get_value_from_variable_name(var):
    pass

def get_type_from_variable_name(var):
    pass

def solve_expression(ssa_list, r_v):
    for ssa in ssa_list:
        if isinstance(ssa, Unary):
            var_1 = Bool(ssa.rvalue.pure_name)
            s = Solver()
            right_value = BoolVal(r_v)
            s.add(Not(var_1) == right_value)
            if s.check() == sat:
                s.reset()
                return False
        elif isinstance(ssa, Condition):
            var_1 = Bool(ssa.value.pure_name)
            s = Solver()
            right_value = BoolVal(r_v)
            s.add(var_1 == right_value)
            if s.check() == sat:
                s.reset()
                return False
        else:
            return True

def exp_iteration(exp, var_list):
    if isinstance(exp, Identifier):
        var_list.append(exp.value)
        return;
    else:
        if isinstance(exp, TupleExpression):
            for exp in exp.expressions:
        # exp = BinaryOperation(exp.expression_left, exp.expression_right, TupleExpression)
                exp_iteration(exp.expression_left, var_list)
                exp_iteration(exp.expression_right, var_list)
        else:
            exp_iteration(exp.expression_left, var_list)
            exp_iteration(exp.expression_right, var_list)

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
                var_in_requires = []
                for exp in node.expression.arguments:
                    exp_iteration(exp, var_in_requires)
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

    def advancedUpdateEth(self, function): # PPT，检查程序执行锁
        from slither.analyses.data_dependency.data_dependency import is_dependent

        allNodes = function.nodes
        path_between_sender_and_if = []
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
                        path_between_sender_and_if.append(node)
                    if node.type == NodeType.ENDIF:
                        if careifNodeStack:
                            careifNodeStack.pop()
                            path_between_sender_and_if = []
                    else:
                        path_between_sender_and_if.append(node)
                if careifNodeStack:  # 被包裹在if语句中的Node
                    for careifNode in careifNodeStack:
                        care_if_StateVariablesRead |= set(careifNode.state_variables_read)
                        # print(careifNode.irs_ssa)
                        # print(careifNode.irs_ssa[0].lvalue, end = ' ')
                        # print(careifNode.irs_ssa[0].rvalue, end = ' ')
                        # print(careifNode.irs_ssa[0].type)
                        # print(careifNode.irs_ssa[1].lvalue, end = ' ')
                        # print(careifNode.irs_ssa[1].variable_left, end = ' ')
                        # print(careifNode.irs_ssa[1].variable_right, end = ' ')
                        # print(careifNode.irs_ssa[1].type)
                        # print(careifNode.irs_ssa[2].value)
                    
                    for stateVariableWritten in state_variables_written:
                        if len(list(care_if_StateVariablesRead | care_RequireOrAssert_StateVariableRead)) > 1:
                            return True
                        careStateVariableRead = list(care_if_StateVariablesRead | care_RequireOrAssert_StateVariableRead)[0]
                        for suspicious_node in path_between_sender_and_if:
                            ir_list = suspicious_node.irs_ssa
                            for ir in ir_list:
                                # print(dir(ir))
                                if isinstance(ir, Assignment):
                                    if ir.lvalue.pure_name == careStateVariableRead.name:
                                        r_v = ir.rvalue
                                else:
                                    continue
                        for careifNode in careifNodeStack:
                            symbol_result = solve_expression(careifNode.irs_ssa, r_v)
                            if symbol_result == False:
                                print("solving successfully")
                            else:
                                print("solving failed")
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




