from slither.detectors.abstract_detector import (AbstractDetector, DetectorClassification)
from slither.core.cfg.node import NodeType
from slither.slithir.operations import (HighLevelCall, LowLevelCall, LibraryCall, Send, Transfer)
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.slithir.variables.constant import Constant
from slither.core.callGraph.CallGraph import CallGraph
from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph
from slither.core.declarations.function import Function
from slither.detectors.callGraph_cfg_Reentrancy.DM import DM
from slither.detectors.callGraph_cfg_Reentrancy.getAallPaths import (getIcfgAllPath, getCfgAllPath)
from slither.detectors.callGraph_cfg_Reentrancy.DM import allPaths_intToNode
from slither.detectors.ICFG_Reentrancy.icfg.ICFG import ICFG
import copy
from slither.detectors.callGraph_cfg_Reentrancy.DM import allPaths_intToNode
from slither.core.callGraph.CallGraph import CallGraph
from slither.detectors.ICFG_Reentrancy.smallUtils import (getadjMatrix, getICFGadjMatrix)
from slither.detectors.ICFG_Reentrancy.testDFS import MyDeepGraph
from slither.detectors.ICFG_Reentrancy.smallUtils import defenseModifier

def callerVisibilityHavePublic(function, callGraph, dm):

    functionNode = callGraph.function_Map_node.get(function)
    if functionNode is None:
        return False
    for father in functionNode.fathers:
        if father.function.visibility == 'public' and dm.haveDefenseModifier(father.function) is False and dm.requireMsgSender(father.function) is False:
            return True
        if callerVisibilityHavePublic(father, callGraph, dm):
            return True
    return False

def Allnodes(slither):
    allnodes = []
    for function in slither.functions:
        allnodes.extend(function.nodes)
    return allnodes

class EffectIcfgReentrancy(AbstractDetector):
    ARGUMENT = 'EffectIcfgReentrancy'
    HELP = 'Benign reentrancy vulnerabilities'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-2'

    WIKI_TITLE = 'Reentrancy vulnerabilities'
    WIKI_DESCRIPTION = '''
    Detection of the [re-entrancy bug](https://github.com/trailofbits/not-so-smart-contracts/tree/master/reentrancy).
    Only report reentrancy that acts as a double call (see `reentrancy-eth`, `reentrancy-no-eth`).'''
    WIKI_EXPLOIT_SCENARIO = '''
    ```solidity
        function callme(){
            if( ! (msg.sender.call()() ) ){
                throw;
            }
            counter += 1
        }   
    ```

    `callme` contains a reentrancy. The reentrancy is benign because it's exploitation would have the same effect as two consecutive calls.'''

    WIKI_RECOMMENDATION = 'Apply the [check-effects-interactions pattern](http://solidity.readthedocs.io/en/v0.4.21/security-considerations.html#re-entrancy).'

    def _detect(self):
        #icfg = ICFG(self.slither)
        #icfg.build_ICFG()
        ethNodeList, taintNodeList, cfgEndNodeList = self.getAllEthNode_AllTaintNode()
        callGraph = CallGraph(self.slither)


        for c in self.contracts:
            self.detect_reentrancy(c, ethNodeList, taintNodeList, callGraph)
        return []

    def detect_reentrancy(self, contract, ethNodeList, taintNodeList, callGraph):
        print('Start Contract {}'.format(contract.name))
        for function in contract.functions:
            if function.is_implemented:
                print('\tTo analyze：{}.{}'.format(function.contract.name, function.full_name))
                dm = DM(function)   # 声明dm防御对象
                reentrancyFlag = False

                # for node in function.nodes:
                #     self._node_taint(node)



                function_ethNodeList = []   # 存储本函数体内的eth
                functon_taintNodeList = []  # 存储本函数体内的taint
                for node in function.nodes:
                    if node in taintNodeList:
                        functon_taintNodeList.append(node)
                    if node in ethNodeList:
                        function_ethNodeList.append(node)
                #
                for function_taintNode in functon_taintNodeList:
                    '''
                    startToend = [start, ... ,end]
                    '''
                    cfgEntryNodeTotaint = []
                    cfgEntryNodeTotaint.append(function.entry_point)
                    cfgEntryNodeTotaint.extend(list(set(function.nodes) - set([function.entry_point, function_taintNode])))
                    cfgEntryNodeTotaint.append(function_taintNode)

                    adjMatrix = getadjMatrix(cfgEntryNodeTotaint)
                    mydeepGraph = MyDeepGraph(len(cfgEntryNodeTotaint))
                    mydeepGraph.setadjMetrix(adjMatrix)
                    cfgAllPath = mydeepGraph.getPathofTwoNode(0, len(cfgEntryNodeTotaint)-1)
                    cfgAllPath_Node = allPaths_intToNode(cfgAllPath, cfgEntryNodeTotaint)

                    cfgCandidateAllPath_Node = []
                    for path in cfgAllPath_Node[:]:
                       if any(iNode in ethNodeList for iNode in path):
                           cfgCandidateAllPath_Node.append(path)

                    if cfgCandidateAllPath_Node:   # 证明cfg本身就找到Reentrancy了，准备humanlook, 注意reversed, DM


                        human_cfgCandidateAllPath_Node = []
                        for path in cfgCandidateAllPath_Node:
                            tempPath = []
                            for everyNode in path:
                                if everyNode.type == NodeType.ENTRYPOINT:
                                    everyNode.add_expression('entryPoint')
                                tempPath.append(str(everyNode.expression))
                            human_cfgCandidateAllPath_Node.append(tempPath)
                        advanceUpdateFlag = dm.advancedUpdateEth(function)
                        privateVisibility = dm.privateVisibility(function)
                        havePublicCaller = callerVisibilityHavePublic(function, callGraph, dm)
                        haveDefenModifier = dm.haveDefenseModifier(function)
                        haveDefenRequire = dm.requireMsgSender(function)
                        #ethAdvanceUpdateFlag = dm.advancedUpdateEth_2(function)

                        if privateVisibility is True or haveDefenModifier is True or haveDefenRequire is True:
                            # print('privateVisibility: ', privateVisibility)
                            # print('haveDefenModifier: ', haveDefenModifier)
                            # print('haveDefenRequire: ', haveDefenRequire)
                            # print('function.is_protected() ', function.is_protected())
                            # accessPermision = True
                            # havePublicCaller = True
                            if havePublicCaller is True:
                                reentrancyFlag = True
                                print('\t\tcontract: {} | function: {} | accessPermision: {} | publicCaller: {} | 锁: {} '.format(
                                    function.contract.name, function.full_name, accessPermision, havePublicCaller, advanceUpdateFlag))
                                for human_cfgCandidatePath_Node in human_cfgCandidateAllPath_Node:
                                    print('\t\t\tpath: {}'.format(human_cfgCandidatePath_Node))
                        else:
                            accessPermision = False
                            reentrancyFlag = True
                            print(
                                '\t\tcontract: {} | function: {} | accessPermision: {} | 锁: {}'.format(
                                    function.contract.name, function.full_name, accessPermision, advanceUpdateFlag))
                            for human_cfgCandidatePath_Node in human_cfgCandidateAllPath_Node:
                                print('\t\t\tpath: {}'.format(human_cfgCandidatePath_Node))
                if reentrancyFlag is True:
                    print('[cfg_Reentrancy in] contract: {} . function: {} | {}'.format(function.contract.name, function.full_name, function.source_mapping_str))
                    continue


                if reentrancyFlag is False:  # 证明cfg本身没找到Reentrancy
                    careTaintNode = set()
                    careEthNode = set()
                    careTaintFunction = set()
                    careEthFunction = set()
                    callGraphToTaintAllPath_Node = []
                    callGraphToEthAllPath_Node = []
                    print('\t\tcfg分析安全，所以开始ICFG的分析'.format(function.full_name))
                    currentFunctionNode = callGraph.function_Map_node.get(function)

                    '''
                    把钱更新的那些个ethFunction剔除掉
                    '''
                    for ethFunctionNode in callGraph.ethFunctionNodes[:]:
                        if dm.advancedUpdateEth(ethFunctionNode.function):# or dm.advancedUpdateEth_2(ethFunctionNode.function):
                            callGraph.ethFunctionNodes.remove(ethFunctionNode)

                    # for taintFunctionNode in callGraph.taintFunctionNodes[:]:
                    #     if dm.requireMsgSender(taintFunctionNode.function):
                    #         callGraph.taintFunctionNodes.remove(taintFunctionNode)

                    for taintFunctionNode in callGraph.taintFunctionNodes:
                        functionNode_to_taintFunctionNode = []
                        functionNode_to_taintFunctionNode.append(currentFunctionNode)
                        functionNode_to_taintFunctionNode.extend(list(set(callGraph.functionNodes) - set([currentFunctionNode, taintFunctionNode])))
                        functionNode_to_taintFunctionNode.append(taintFunctionNode)

                        adjMatrix = getadjMatrix(functionNode_to_taintFunctionNode)
                        mydeepGraph = MyDeepGraph(len(functionNode_to_taintFunctionNode))
                        mydeepGraph.setadjMetrix(adjMatrix)
                        callGraphToOneofTaintAllPath = mydeepGraph.getPathofTwoNode(0, len(functionNode_to_taintFunctionNode) - 1)
                        callGraphToOneofTaintAllPath_Node = allPaths_intToNode(callGraphToOneofTaintAllPath, functionNode_to_taintFunctionNode)
                        callGraphToTaintAllPath_Node.extend(callGraphToOneofTaintAllPath_Node)
                    for ethFunctionNode in callGraph.ethFunctionNodes:
                        functionNode_to_ethFunctionNode = []
                        functionNode_to_ethFunctionNode.append(currentFunctionNode)
                        functionNode_to_ethFunctionNode.extend(list(set(callGraph.functionNodes) - set([currentFunctionNode, ethFunctionNode])))
                        functionNode_to_ethFunctionNode.append(ethFunctionNode)
                        adjMatrix = getadjMatrix(functionNode_to_ethFunctionNode)
                        mydeepGraph = MyDeepGraph(len(functionNode_to_ethFunctionNode))
                        mydeepGraph.setadjMetrix(adjMatrix)
                        callGraphToOneOfEthAllPath = mydeepGraph.getPathofTwoNode(0, len(functionNode_to_ethFunctionNode) - 1)
                        callGraphToOneofEthAllPath_Node = allPaths_intToNode(callGraphToOneOfEthAllPath, functionNode_to_ethFunctionNode)
                        callGraphToEthAllPath_Node.extend(callGraphToOneofEthAllPath_Node)

                    for path in callGraphToTaintAllPath_Node:
                        careTaintFunction.add(path[1].function)
                    for path in callGraphToEthAllPath_Node:
                        careEthFunction.add(path[1].function)

                    for node in function.nodes:
                        for highLevelCall in node.high_level_calls:
                            contract, functionOrVariable = highLevelCall
                            if isinstance(functionOrVariable, Function):
                                if functionOrVariable in careEthFunction:
                                    careEthNode.add(node)
                                if functionOrVariable in careTaintFunction:
                                    careTaintNode.add(node)
                        for internalCall in node.internal_calls:
                            if isinstance(internalCall, Function):
                                if internalCall in careEthFunction:
                                    careEthNode.add(node)
                                if internalCall in careTaintFunction:
                                    careTaintNode.add(node)
                    careTaintNode = careTaintNode | set(functon_taintNodeList)
                    careEthNode = careEthNode | set(function_ethNodeList)

                    for taintNode in careTaintNode:
                        cfgEntryNodeTotaint = []
                        cfgEntryNodeTotaint.append(function.entry_point)
                        cfgEntryNodeTotaint.extend(list(set(function.nodes) - set([function.entry_point, taintNode])))
                        cfgEntryNodeTotaint.append(taintNode)

                        adjMatrix = getadjMatrix(cfgEntryNodeTotaint)
                        mydeepGraph = MyDeepGraph(len(cfgEntryNodeTotaint))
                        mydeepGraph.setadjMetrix(adjMatrix)
                        cfgAllPath = mydeepGraph.getPathofTwoNode(0, len(cfgEntryNodeTotaint) - 1)

                        cfgAllPath_Node = allPaths_intToNode(cfgAllPath, cfgEntryNodeTotaint)
                        corePath = []
                        for path in cfgAllPath_Node:
                            if any(cfgNode in careEthNode for cfgNode in path[0:len(path)-1]):
                                corePath.append(path)
                        if corePath:
                            ###################################################

                            ########################################
                            for path in corePath[:]:
                                for callee in path[-1].callee:
                                    calleefunctionNode = callGraph.function_Map_node.get(callee)
                                    for callGraphToTaintPath in callGraphToTaintAllPath_Node:
                                        if calleefunctionNode == callGraphToTaintPath[1]:
                                            afterCalleeList = [functionNode.function.full_name for functionNode in callGraphToTaintPath[1:]]
                                            afterCalleeList.insert(0, 'taint')
                                            path.append(afterCalleeList)

                            for tempP in corePath[:]:
                                for tempNode in tempP:
                                    if tempNode in list(careEthNode):
                                        for callee in tempNode.callee:
                                            calleefunctionNode = callGraph.function_Map_node.get(callee)
                                            for callGraphToEthPath in callGraphToEthAllPath_Node:
                                                if calleefunctionNode == callGraphToEthPath[1]:
                                                    afterCalleeList = [functionNode.function.full_name for functionNode in callGraphToEthPath[1:]]
                                                    afterCalleeList.insert(0, 'eth')
                                                    tempP.append(afterCalleeList)
                            ##########################################
                            human_corePath = []
                            for path in corePath:
                                ##############################################
                                tempPath = []
                                needindex = len(path)
                                for i in range(len(path)):
                                    if isinstance(path[i], list):
                                        needindex = i
                                        break
                                #########################
                                for cfgNode in path[0:needindex]:
                                    tempPath.append(str(cfgNode.expression))
                                tempPath.append(path[needindex:])
                                human_corePath.append(tempPath)
                            advanceUpdateFlag = False  # dm.advancedUpdateEth(function)
                            privateVisibility = dm.privateVisibility(function)
                            haveDefenModifier = dm.haveDefenseModifier(function)
                            havePublicCaller = callerVisibilityHavePublic(function, callGraph, dm)
                            haveDefenRequire = dm.requireMsgSender(function)

                            if privateVisibility is True or haveDefenModifier is True or haveDefenRequire is True or function.is_protected() is True:
                                accessPermision = True
                                if havePublicCaller is True:
                                    reentrancyFlag = True
                                    print(
                                        '\t\tcontract: {} | function: {} | accessPermision: {} | publicCaller: {} | 锁/钱提前更新：{}'.format(
                                            function.contract.name, function.full_name, accessPermision,
                                            havePublicCaller, advanceUpdateFlag))
                                    for humanPath in human_corePath:
                                        print('\t\t\tpath：{}'.format(humanPath))
                            else:
                                accessPermision = False
                                reentrancyFlag = True
                                print(
                                    '\t\tcontract: {} | function: {} | accessPermision: {} | 锁/钱提前更新：{}'.format(
                                        function.contract.name, function.full_name, accessPermision,
                                        advanceUpdateFlag))
                                for humanPath in human_corePath:
                                    print('\t\t\tpath：{}'.format(humanPath))
                if reentrancyFlag is True:
                    print('[Icfg_Reentrancy in] contract: {} . function: {} | {}'.format(function.contract.name, function.full_name, function.source_mapping_str))
                    continue


    def getAllEthNode_AllTaintNode(self):
        ethNodeList = []
        taintNodeList = []
        cfgEndNodeList = []
        for function in self.slither.functions:
            for node in function.nodes:
                if len(node.sons) == 0:
                    node.isEND = True
                    function.ENDnodes.append(node)
                    cfgEndNodeList.append(node)
                if self._can_send_eth(node.irs):
                    ethNodeList.append(node)
                    function.ethNodes.append(node)
                if self._node_taint(node):
                    taintNodeList.append(node)
        return ethNodeList, taintNodeList, cfgEndNodeList

    def _can_send_eth(self, irs):
        """
            Detect if the node can send eth
        """
        for ir in irs:
            if isinstance(ir, (HighLevelCall, LowLevelCall, Transfer, Send)):
                if ir.call_value:
                    # print(type(ir.call_value))  # <class 'slither.slithir.variables.constant.Constant'>
                    # print(str(ir.call_value))
                    if str(ir.call_value) == '0':  # isinstance(ir.call_value, Constant) and
                        return False
                    return True
        return False

    def _node_taint(self, node):

        if node.high_level_calls or node.low_level_calls:
            for highLevelCall in node.high_level_calls:
                contract, functionOrVariable = highLevelCall
                if isinstance(functionOrVariable, Function):
                    for ir in node.irs:
                        if hasattr(ir, 'destination'):
                            taintflag = is_tainted(ir.destination, node.function.contract)
                            if taintflag is True:
                                # print(str(node.expression) + '\t' + str(taintflag))
                                return True
        if node.low_level_calls:
            for ir in node.irs:
                if hasattr(ir, 'destination'):
                    taintflag = is_tainted(ir.destination, node.function.contract)
                    if taintflag is True:
                        # print(str(node.expression) + '\t' + str(taintflag))
                        return True
        return False