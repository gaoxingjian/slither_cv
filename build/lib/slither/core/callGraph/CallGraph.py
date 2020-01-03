from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.function import Function
from slither.core.callGraph.functionNode import FunctionNode
from slither.core.variables.variable import Variable
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.slithir.operations import (HighLevelCall, LowLevelCall, LibraryCall, Send, Transfer)
from slither.slithir.variables.constant import Constant


def node_taint(node):
    if node.internal_calls:
        for internalCall in node.internal_calls:
            if isinstance(internalCall, Function):
                node.callee.append(internalCall)
    if node.high_level_calls or node.low_level_calls:
        for highLevelCall in node.high_level_calls:
            contract, functionOrVariable = highLevelCall
            if isinstance(functionOrVariable, Function):
                node.callee.append(functionOrVariable)
                for ir in node.irs:
                    if hasattr(ir, 'destination'):
                        taintflag = is_tainted(ir.destination, node.function.contract)
                        if taintflag is True:
                            return True
    if node.low_level_calls:
        for ir in node.irs:
            if hasattr(ir, 'destination'):
                taintflag = is_tainted(ir.destination, node.function.contract)
                if taintflag is True:
                    return True
    return False
class CallGraph:
    def __init__(self, slither):
        self.slither = slither
        self._counter_FunctionNodes = 0
        self._FunctionNodes = []       # 存储这个图中所有的functionNode
        self.function_Map_node = {}     # 一个映射， 通过这个映射可以找到function对象对应的functionNode对象
        self._all_contracts = set()     # 存储这个图中所涉及到的合约
        self._taintFunctionNodes = []   # 存储这个图中所有的被标记为taint的functionNode
        self._ethFunctionNodes = []
        self._adjoin = []
        self._setFunctionNodes(self.slither.functions)
        self._process_functionNodes(self._FunctionNodes)
        #self.addIndirectTaintFunctionNodes(self._FunctionNodes)
    #
    # def addIndirectTaintFunctionNodes(self, allFunctionNodes):
    #     '''
    #
    #     :param allFunctionNodes:
    #     :return:
    #     解决一些functionNode不是直接可以判断为taintFunctionNode,但却间接的调用了那些直观的taintFunctionNode
    #     '''
    #     node_num = len(allFunctionNodes)
    #     myGraph = MyGraph(node_num)
    #     possibleCleanfunctionNodes = list(set(allFunctionNodes) - set(self._taintFunctionNodes))    # 全部节点 - 直接taint节点
    #     for possibleCleanfunctionNode in possibleCleanfunctionNodes:
    #         for taintFunctionNode in self._taintFunctionNodes:
    #             if taintFunctionNode is possibleCleanfunctionNode:
    #                 continue
    #             possibleCleanfunctionNodeToTaintFuncitonNodeList = []
    #             possibleCleanfunctionNodeToTaintFuncitonNodeList.append(possibleCleanfunctionNode)
    #             pilotProcessNodes = set(allFunctionNodes) - set([possibleCleanfunctionNode, taintFunctionNode])
    #             possibleCleanfunctionNodeToTaintFuncitonNodeList.extend(list(pilotProcessNodes))
    #             possibleCleanfunctionNodeToTaintFuncitonNodeList.append(taintFunctionNode)
    #
    #             for functionNode in possibleCleanfunctionNodeToTaintFuncitonNodeList[0:node_num - 1]:  # index 范围【0:node_num-2】, 不去管终点的sons
    #                 for son in functionNode.sons:
    #                     myGraph.addEdge(possibleCleanfunctionNodeToTaintFuncitonNodeList.index(functionNode) + 1,
    #                                   possibleCleanfunctionNodeToTaintFuncitonNodeList.index(son) + 1)  # 在构建邻接矩阵的时候要注意index+1!!
    #             allPaths = myGraph.findAllPathBetweenTwoNodes(possibleCleanfunctionNodeToTaintFuncitonNodeList.index(possibleCleanfunctionNode) + 1,
    #                                                         possibleCleanfunctionNodeToTaintFuncitonNodeList.index(taintFunctionNode) + 1)
    #             for path in allPaths:
    #                 care_callee_FunctionNode = possibleCleanfunctionNodeToTaintFuncitonNodeList[path[-2]-1]
    #                 for node in possibleCleanfunctionNode.function.nodes:
    #                     internal_calls = node.internal_calls
    #                     external_calls = []
    #                     for external_call in node.high_level_calls:
    #                         external_contract, external_function = external_call
    #                         external_calls.append(external_function)
    #
    #                     for call in set(internal_calls + external_calls):
    #                         if isinstance(call, Function):
    #                             if call == care_callee_FunctionNode.function:
    #                                 possibleCleanfunctionNode.function.taintNodes.append(node)
    #                                 possibleCleanfunctionNode.setTaint(True)
    #                                 self._taintFunctionNodes.append(possibleCleanfunctionNode)
    #             # type list of list


    def _setFunctionNodes(self, funcitons):
        for function in funcitons:
            taintFlag = False
            ethFlag = False
            for node in function.nodes:
                # if node.high_level_calls or node.low_level_calls: # 这个地方没有考虑LibaryCalls!!!
                #     for ir in node.irs:
                #         if hasattr(ir, 'destination'):
                #             result = is_tainted(ir.destination, node.function.contract)
                #             if result == True:
                #                 taintFlag = True
                #                 break
                #     if taintFlag:
                #         break
                res = node_taint(node)
                if res == True:
                    taintFlag = True
                    break
            for node in function.nodes:
                if self._can_send_eth(node.irs):
                    function.ethNodes.append(node)
                    ethFlag = True
                    break
            functionNode = FunctionNode(self._counter_FunctionNodes, function)
            self._counter_FunctionNodes += 1
            functionNode.set_contract(function.contract)
            functionNode.setTaint(taintFlag)
            functionNode.setEth(ethFlag)
            if taintFlag == True:
                self._taintFunctionNodes.append(functionNode)
            if ethFlag == True:
                self._ethFunctionNodes.append(functionNode)
            self._FunctionNodes.append(functionNode)
            self.function_Map_node[function] = functionNode
            self._all_contracts.add(function.contract)

    @property
    def functionNodes(self):
        return self._FunctionNodes

    @property
    def taintFunctionNodes(self):
        return self._taintFunctionNodes

    @property
    def ethFunctionNodes(self):
        return self._ethFunctionNodes

    def _process_functionNodes(self, functionNodes):  # 处理每一个functionNode
        for functionNode in functionNodes:
            self._process_functionNode(functionNode)

    def _process_functionNode(self, functionNode):
        for internal_call in functionNode.function.internal_calls:   # 拿到这个node的internal calls
            self._process_internal_call(functionNode, internal_call)

        for external_call in functionNode.function.high_level_calls:    # 拿到这个node的external calls
            self._process_external_call(functionNode, external_call)

    def _process_internal_call(self, functionNode, internal_call):
        if isinstance(internal_call, (Function)):
            if internal_call in self.function_Map_node:
                internal_callNode = self.function_Map_node.get(internal_call)
                self.link_FuncitonNodes(functionNode, internal_callNode)  # 将functionNode和他的internal_callNode进行连接
        elif isinstance(internal_call, (SolidityFunction)):  # 这个地方还得研究一下
            if internal_call in self.function_Map_node:
                internal_callNode = self.function_Map_node.get(internal_call)
                self.link_FuncitonNodes(functionNode, internal_callNode)

    def _process_external_call(self, functionNode, external_call):
        external_contract, external_function = external_call

        if not external_contract in self._all_contracts:
            return
        if isinstance(external_function, (Variable)):
            return
        if external_function in self.function_Map_node:
            external_callNode = self.function_Map_node.get(external_function)
            self.link_FuncitonNodes(functionNode, external_callNode)

    def link_FuncitonNodes(self, n1, n2):
        n1.add_son(n2)
        n2.add_father(n1)

    def set_adjoin(self):   # 设置临街矩阵
        for functionNode in self._FunctionNodes:
            for son in functionNode.sons:
                self._adjoin.append(set([functionNode, son]))
    @property
    def adjoin(self):
        return self._adjoin

    def _can_send_eth(self, irs):
        """
            Detect if the node can send eth
        """
        for ir in irs:
            if isinstance(ir, (HighLevelCall, LowLevelCall, Transfer, Send)):
                if ir.call_value:
                    # print(type(ir.call_value))  # <class 'slither.slithir.variables.constant.Constant'>
                    # print(str(ir.call_value))
                    if isinstance(ir.call_value, Constant) and str(ir.call_value) == '0':
                        return False
                    return True
        return False

    def test(self, function):
        functionNode = self.function_Map_node.get(function)
        print('函数{}的儿子们 {} 父亲们 {}'.format(function.full_name,
                                                list(node.function.full_name for node in functionNode.sons),
                                                list(node.function.full_name for node in functionNode.fathers)))
