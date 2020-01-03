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

def callerVisibilityHavePublic(function, callGraph):
    functionNode = callGraph.function_Map_node.get(function)
    for father in functionNode.fathers:
        if father.function.visibility == 'public':
            return True
        if callerVisibilityHavePublic(father, callGraph):
            return True
    return False

def Allnodes(slither):
    allnodes = []
    for function in slither.functions:
        allnodes.extend(function.nodes)
    return allnodes

class ICfgReentrancy(AbstractDetector):
    ARGUMENT = 'ICfgReentrancy'
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
        icfg = ICFG(self.slither)
        icfg.build_ICFG()
        ethNodeList, taintNodeList, cfgEndNodeList = self.getAllEthNode_AllTaintNode()
        callGraph = CallGraph(self.slither)


        for c in self.contracts:
            self.detect_reentrancy(c, ethNodeList, taintNodeList, icfg, callGraph, cfgEndNodeList)
        return []

    def detect_reentrancy(self, contract, ethNodeList, taintNodeList, icfg, callGraph, cfgEndNodeList):
        print('Start Contract {}'.format(contract.name))
        for function in contract.functions:
            if function.is_implemented:
                print('\tTo analyze：{}.{}'.format(function.contract.name, function.full_name))
                dm = DM(function)   # 声明dm防御对象
                reentrancyFlag = False

                functon_taintNodeList = []  # 存储本函数体内的taint
                for node in function.nodes:
                    if node in taintNodeList:
                        functon_taintNodeList.append(node)

                for function_taintNode in functon_taintNodeList:
                    '''
                    startToend = [start, ... ,end]
                    '''
                    cfgEntryNodeTotaint = []
                    cfgEntryNodeTotaint.append(function.entry_point)
                    cfgEntryNodeTotaint.extend(list(set(function.nodes) - set([function.entry_point, function_taintNode])))
                    cfgEntryNodeTotaint.append(function_taintNode)

                    # cfgAllPath = getCfgAllPath(cfgEntryNodeTotaint)
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
                        advanceUpdateFlag = False  # dm.advancedUpdateEth(function)
                        privateVisibility = dm.privateVisibility(function)
                        havePublicCaller = callerVisibilityHavePublic(function, callGraph)
                        if privateVisibility is True:
                            if havePublicCaller is True:
                                reentrancyFlag = True
                                print('\t\tcontract: {} | function: {} | private: {} | publicCaller: {} | 锁/钱提前更新：{}'.format(
                                    function.contract.name, function.full_name, privateVisibility, havePublicCaller, advanceUpdateFlag))
                                for human_cfgCandidatePath_Node in human_cfgCandidateAllPath_Node:
                                    print('\t\t\tpath: {}'.format(human_cfgCandidatePath_Node))
                        else:
                            reentrancyFlag = True
                            print(
                                '\t\tcontract: {} | function: {} | private: {} | 锁/钱提前更新：{}'.format(
                                    function.contract.name, function.full_name, privateVisibility, advanceUpdateFlag))
                            for human_cfgCandidatePath_Node in human_cfgCandidateAllPath_Node:
                                print('\t\t\tpath: {}'.format(human_cfgCandidatePath_Node))
                if reentrancyFlag is True:
                    print('[cfg_Reentrancy in] contract: {} . function: {} | {}'.format(function.contract.name, function.full_name, function.source_mapping_str))
                    continue


                if reentrancyFlag is False:  # 证明cfg本身没找到Reentrancy
                    '''
                    bug修复为了把当前的function的endnode的回调用处的那条路径删除，同时也要删除本函数entryNode的icfgFather
                    '''
                    print('\t\tcfg分析安全，所以开始ICFG的分析'.format(function.full_name))
                    # = function.entry_point.icfgFathers
                    # function.entry_point.set_icfgFather([])
                    '''
                    endnodeMapBackSons = {}
                    # hh = [str(endnode.expression) for endnode in function.ENDnodes]
                    # print('结束点：'.format(hh))
                    for endnode in function.ENDnodes:
                        endnodeMapBackSons[endnode] = []
                        for son in endnode.backIcfgSons:
                            endnodeMapBackSons[endnode].append(son)

                    for endnode in function.ENDnodes:
                        endnode.set_backIcfgSons([])
                    '''
                    # tt = [str(taintNode.expression) for taintNode in taintNodeList]
                    # print('系统中所有的taint：{}, 总共有 {} 个taintNode'.format(tt, len(taintNodeList)))
                    # for endnode in function.ENDnodes:
                    #     print('回到哪里了: {}'.format(endnodeMapBackSons[endnode]))
                    # for endnode in function.ENDnodes:
                    #     print('注意应该是0：{}'.format(len(endnode.backIcfgSons)))
                    for taintNode in taintNodeList:
                        icfgEntryNodeTotaint = []
                        icfgEntryNodeTotaint.append(function.entry_point)
                        icfgEntryNodeTotaint.extend(list(set(icfg.allNodes) - set([function.entry_point, taintNode])))
                        icfgEntryNodeTotaint.append(taintNode)

                        adjMatrix = getICFGadjMatrix(icfgEntryNodeTotaint)

                        mydeepGraph = MyDeepGraph(len(icfgEntryNodeTotaint))
                        mydeepGraph.setadjMetrix(adjMatrix)
                        #mydeepGraph.printMatrix()
                        icfgAllPath = mydeepGraph.getPathofTwoNode(0, len(icfgEntryNodeTotaint) - 1)

                        icfgAllPath_Node = allPaths_intToNode(icfgAllPath, icfgEntryNodeTotaint)

                        #icfgAllPath = getIcfgAllPath(icfgEntryNodeTotaint)
                        # print('函数{}的入口点到taint点{}的路径有{}条：'.format(function.full_name, taintNode.expression, len(icfgAllPath)))
                        #icfgAllPath_Node = allPaths_intToNode(icfgAllPath, icfgEntryNodeTotaint)
                        # print('应该为1：{}'.format(len(icfgAllPath_Node)))
                        # qq = [[str(ww.expression) for ww in yy] for yy in icfgAllPath_Node]
                        # print('路径：{}'.format(qq))
                        icfgCandidateAllPath_Node = []

                        for path in icfgAllPath_Node:
                            if any(iNode in ethNodeList for iNode in path):
                                icfgCandidateAllPath_Node.append(path)

                        # if icfgCandidateAllPaht_Node:
                        #     # 检查icfg路径合法性
                        #     cfgEndNodeList_exp = list(set(cfgEndNodeList) - set(function.ENDnodes))
                        #     for path in icfgCandidateAllPaht_Node:
                        #         new = path[-1]
                        #         for node in path:
                        #             if node in cfgEndNodeList_exp:
                        #                 for entryP in node.icfgSons:
                        #                     for preEndNode in entryP.function.ENDnodes:
                        #                         if preEndNode in path:
                        #                             if (path.index(preEndNode) + 1) <= len(path)-1:
                        #                                 possibleErrNodeIndex = path.index(preEndNode) + 1
                        #                                 possibleErrNode = path[possibleErrNodeIndex]
                        #                                 if possibleErrNode != node:
                        #                                     # path.append('非法路径')
                        #                                     pass
                        #
                        #
                        #             if node in function.ENDnodes:
                        #                 if path[-1] != node:
                        #                     # 非法路径
                        #                     pass
                        if icfgCandidateAllPath_Node:    # 证明icfg本身找到Reentrancy了，准备humanlook, DM

                            # print('证明icfg本身找到Reentrancy了，准备humanlook, DM')
                            '''
                            转变成普通人能看懂的形式，注意reversed
                            '''
                            human_icfgCandidateAllPath_Node = []
                            for path in icfgCandidateAllPath_Node:
                                tempPath = []
                                for everyNode in path:
                                    if everyNode.type == NodeType.ENTRYPOINT:
                                        everyNode.add_expression('entryPoint')
                                    tempPath.append(str(everyNode.expression))
                                human_icfgCandidateAllPath_Node.append(tempPath)
                            etherNodesInPath = []
                            # for path in icfgCandidateAllPaht_Node:
                            #     for itemNode in path:
                            #         if itemNode in ethNodeList:
                            #             etherNodesInPath.append(itemNode)
                            etherNodesInPath = [itemNode for path in icfgCandidateAllPath_Node for itemNode in path if itemNode in ethNodeList]
                            # print('长度：{}'.format(len(etherNodesInPath)))
                            # kkk = [str(etherNodeInPath.expression) for etherNodeInPath in etherNodesInPath]
                            # print('在路径中的转账节点：{}'.format(kkk))
                            realETHfunctionList = [eNode.function for eNode in etherNodesInPath]
                            '''
                            if all(dm.advancedUpdateEth(function) for function in realETHfunctionList):
                                advanceUpdateFlag = True
                            else:
                                advanceUpdateFlag = False
                            '''
                            advanceUpdateFlag = False
                            #advanceUpdateFlag = dm.advancedUpdateEth(function)
                            privateVisibility = dm.privateVisibility(function)
                            havePublicCaller = callerVisibilityHavePublic(function, callGraph)

                            if privateVisibility is True:
                                if havePublicCaller is True:
                                    reentrancyFlag = True
                                    print(
                                        '\t\tcontract: {} | function: {} | private: {} | publicCaller: {} | 锁/钱提前更新：{}'.format(
                                            function.contract.name, function.full_name, privateVisibility, havePublicCaller, advanceUpdateFlag))
                                    for human_icfgCandidatePath_Node in human_icfgCandidateAllPath_Node:
                                        print('\t\t\tpath: {}'.format(human_icfgCandidatePath_Node))
                            else:
                                reentrancyFlag = True
                                print(
                                    '\t\tcontract: {} | function: {} | private: {} | 锁/钱提前更新：{}'.format(
                                        function.contract.name, function.full_name, privateVisibility, advanceUpdateFlag))
                                for human_icfgCandidatePath_Node in human_icfgCandidateAllPath_Node:
                                    print('\t\t\tpath: {}'.format(human_icfgCandidatePath_Node))
                    '''
                    为了把当前的function的endnode的回调用处的那条路径再补上, 和entryNode的icfgFather叶去掉
                    '''
                    # if endnodeMapBackSons:
                    #     for endnode in function.ENDnodes:
                    #         endnode.set_backIcfgSons = endnodeMapBackSons[endnode]
                    #function.entry_point.set_icfgFather = icfgFathersNeedToDuan
                if reentrancyFlag is True:
                    print('[icfg_Reentrancy in] contract: {} . function: {} | {}'.format(function.contract.name, function.name, function.source_mapping_str))



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
                    if isinstance(ir.call_value, Constant) and str(ir.call_value) == '0':
                        return False
                    return True
        return False

    def _node_taint(self, node):
        if node.high_level_calls or node.low_level_calls:
            for ir in node.irs:
                if hasattr(ir, 'destination'):
                    taintflag = is_tainted(ir.destination, node.function.contract)
                    if taintflag is True:
                        return True
        return False