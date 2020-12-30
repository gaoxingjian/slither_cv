from slither.detectors.abstract_detector import (AbstractDetector, DetectorClassification)
from slither.core.cfg.node import NodeType
from slither.slithir.operations import (HighLevelCall, LowLevelCall, LibraryCall, Send, Transfer)
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.slithir.variables.constant import Constant

from slither.core.callGraph.CallGraph import CallGraph
from slither.core.declarations.function import Function
from slither.detectors.callGraph_cfg_Reentrancy.DM import DM, allPaths_intToNode
from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph
from slither.detectors.callGraph_cfg_Reentrancy.getAallPaths import (getIcfgAllPath, getCfgAllPath)

from slither.detectors.ICFG_Reentrancy.icfg.ICFG import ICFG
from slither.detectors.ICFG_Reentrancy.smallUtils import (getadjMatrix, getICFGadjMatrix)
from slither.detectors.ICFG_Reentrancy.testDFS import MyDeepGraph


def caller_visibility_have_public(function, call_graph):
    function_node = call_graph.function_Map_node.get(function)
    for father in function_node.fathers:
        if father.function.visibility == 'public':
            return True
        if caller_visibility_have_public(father.function, call_graph):
            return True
    return False


def is_private(function):
    return function.visibility == 'private'


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
    `callme` contains a reentrancy. The reentrancy is benign because it's exploitation would have the same effect as two consecutive calls.
    '''
    WIKI_RECOMMENDATION = 'Apply the [check-effects-interactions pattern](http://solidity.readthedocs.io/en/v0.4.21/security-considerations.html#re-entrancy).'

    def _detect(self):
        icfg = ICFG(self.slither)
        icfg.build_ICFG()
        eth_node_list, taint_node_list, cfg_end_node_list = self.getAllEthNode_AllTaintNode()
        call_graph = CallGraph(self.slither)
        for c in self.contracts:
            self.detect_reentrancy(c, eth_node_list, taint_node_list, icfg, call_graph, cfg_end_node_list)
        return []

    def detect_reentrancy(self, contract, eth_node_list, taint_node_list, icfg, call_graph, cfg_end_node_list):
        print('Start Contract {}'.format(contract.name))
        for function in contract.functions:
            if function.is_implemented:
                print('\tTo analyze: {}.{}'.format(function.contract.name, function.full_name))
                private_visibility = is_private(function)
                have_public_caller = caller_visibility_have_public(function, call_graph)

                # 存储本函数体内的taint
                function_taint_node_list = []
                function_taint_node_list = [node for node in function.nodes if node in taint_node_list]

                # CFG analysis
                reentrancy_flag = self._have_reentrancy(function, eth_node_list, function_taint_node_list,
                                                        private_visibility, have_public_caller)

                if reentrancy_flag is False:  # 证明cfg本身没找到Reentrancy
                    print('\t\tCFG analysis is safe, so start analyzing XCFG')
                    # XCFG analysis
                    reentrancy_flag = self._have_reentrancy(function, eth_node_list, taint_node_list,
                                                            private_visibility, have_public_caller, icfg)
                    if reentrancy_flag is False:
                        print('\t\tXCFG analysis is safe')

    def _have_reentrancy(self, function, eth_node_list, taint_node_list, private_visibility, have_public_caller,
                         icfg=None):
        reentrancy_flag = False
        for taint_node in taint_node_list:
            '''
            start_to_end = [start, ... ,end]
            '''
            entry_node_to_taint = []
            entry_node_to_taint.append(function.entry_point)
            if icfg is None:
                entry_node_to_taint.extend(list(set(function.nodes) - set([function.entry_point, taint_node])))
            else:
                entry_node_to_taint.extend(list(set(icfg.allNodes) - set([function.entry_point, taint_node])))
            entry_node_to_taint.append(taint_node)
            if icfg is None:
                adj_matrix = getadjMatrix(entry_node_to_taint)
            else:
                adj_matrix = getICFGadjMatrix(entry_node_to_taint)
            my_deep_graph = MyDeepGraph(len(entry_node_to_taint))
            my_deep_graph.setadjMetrix(adj_matrix)
            all_path = my_deep_graph.getPathofTwoNode(0, len(entry_node_to_taint) - 1)
            all_path_node = allPaths_intToNode(all_path, entry_node_to_taint)

            candidate_all_path_node = []
            for path in all_path_node:
                if any(inode in eth_node_list for inode in path):
                    candidate_all_path_node.append(path)
            if candidate_all_path_node:  # 证明找到Reentrancy了，准备human look, 注意reversed, DM
                '''
                转变成普通人能看懂的形式，注意reversed
                '''
                human_candidate_all_path_node = self.get_human_candidate_all_path_node(candidate_all_path_node)
                advance_update_flag = False  # dm.advancedUpdateEth(function)
                txt1 = '\t\tcontract: {} | function: {} | private: {} | publicCaller: {} | Execution Locks and Eth ' \
                       'money balance modification: {} '
                txt2 = '\t\tcontract: {} | function: {} | private: {} | Execution Locks and Eth money balance ' \
                       'modification: {} '
                txt3 = '\t\t\tpath: {}'
                if private_visibility is True:
                    if have_public_caller is True:
                        reentrancy_flag = True
                        print(txt1.format(function.contract.name, function.full_name, private_visibility,
                                          have_public_caller, advance_update_flag))
                        for human_candidate_path_node in human_candidate_all_path_node:
                            print(txt3.format(human_candidate_path_node))
                else:
                    reentrancy_flag = True
                    print(txt2.format(function.contract.name, function.full_name, private_visibility,
                                      advance_update_flag))
                    for human_candidate_path_node in human_candidate_all_path_node:
                        print(txt3.format(human_candidate_path_node))
        if reentrancy_flag is True:
            if icfg is None:
                txt = '[cfg_Reentrancy in] contract: {} . function: {} | {}'
            else:
                txt = '[icfg_Reentrancy in] contract: {} . function: {} | {}'
            print(txt.format(function.contract.name, function.full_name, function.source_mapping_str))
        return reentrancy_flag

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
        for ir in irs:
            if isinstance(ir, (HighLevelCall, LowLevelCall, Transfer, Send)):
                if ir.call_value:
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

    def get_human_candidate_all_path_node(self, candidate_all_path_node):
        human_candidate_all_path_node = []
        for path in candidate_all_path_node:
            temp_path = []
            for every_node in path:
                if every_node.type == NodeType.ENTRYPOINT:
                    every_node.add_expression('entryPoint')
                temp_path.append(str(every_node.expression))
            human_candidate_all_path_node.append(temp_path)
        return human_candidate_all_path_node
