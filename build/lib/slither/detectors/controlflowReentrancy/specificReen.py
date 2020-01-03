"""
1:得到function中所有节点
2:找到包含send或transfer的节点
3:找到每个send或transfer节点的后续节点
4:对这些后续节点分析调用链（先外部调用链，再内部调用链）_analyzerCallLink
5:外部调用链分析注释在 _externalCallLinkparse
6:内部调用链分析注释在 _internalCallLinkparse
"""
from slither.detectors.abstract_detector import (AbstractDetector, DetectorClassification)
from slither.slithir.operations import (HighLevelCall, LowLevelCall, LibraryCall, Send, Transfer)
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.slithir.variables.constant import Constant
class SpcificReen(AbstractDetector):
    ARGUMENT = 'SpcificReen'
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
        """
        """
        # if a node was already visited by another path
        # we will only explore it if the traversal brings
        # new variables written
        # This speedup the exploration through a light fixpoint
        # Its particular useful on 'complex' functions with several loops and conditions
        self.visited_all_paths = {}

        for c in self.contracts:
            self.isTaint(c);
            # self.detect_reentrancy(c)

        return []
    def detect_reentrancy(self, contract):
        for function in contract.functions_and_modifiers_declared:
            if function.is_implemented:

                '''
                if self.KEY in function.context:print(function.high_level_calls)
                print(function.internal_calls)
                    continue
                self._explore(function.entry_point, [])
                function.context[self.KEY] = True
                '''
                callPath = []
                lowlevelCall_eth_Nodes = []  # 用于存储每一个函数中可以传送eth的lowlevelCall节点
                transferORsendNodes = []    # 用于存储每一个函数中transfer和node节点
                fatherFunctionLayerCount = 0  # 回溯调用记录的层数
                eth_nodes = []  # 存储本函数含有转帐功能的钱数
                function_canEth = False  # flag, 用于标记本函数是否含有直接的转钱功能
                isReentrancy = False  # False代表没有检测到reentrance
                after_ethNodeList = []  # 用于存储转账节点的所有后续节点

                # 往 eth_nodes列表中append值
                nodes = self._getAllNodes(function)  # 得到函数中所有的节点
                for node in nodes:
                    if self._can_send_eth(node.irs):    # 如果这个节点可以发送eth
                        function_canEth = True
                        # print("可以传送eth")
                        eth_nodes.append(node)
                        '''
                        if node.low_level_calls:            # 如果是LowLevelCall发送eth
                            lowlevelCall_eth_Nodes.append(node)
                            pass
                        else:
                            for ir in node.irs:
                                if isinstance(ir, (Transfer, Send)):    # 如果是transfer or send发送eth
                                    transferORsendNodes.append(node)
                                    pass
                        '''
                    # for ir in node.irs:
                        # if isinstance(ir, Transfer):
                        #     transferORsendNodes.append(node)
                            # result = self._can_send_eth(node.irs)
                            # if result:
                            #     self._retrospect(node)
                # afterNodeList = []      # 用于存储每一个函数中的transfer或send所有后续节点
                # for transferORsendNode in transferORsendNodes:
                #     self._getAllbehindNode(transferORsendNode, afterNodeList)  #此时afterNodeList中存入了一个函数中的transfer或send所有后续节点
                #
                # for afterNode in afterNodeList:  # 找出后续是internal call的节点
                #     self._analyzerCallLink(afterNode)
                #

                # 得到每一个eth_node的后续节点并进行存储到after_ethNodeList列表中
                if function_canEth == False:
                    print('合约{}.函数{} 不含有直接转张功能,跳过此函数的分析'.format(function.contract.name, function.full_name))
                    continue
                for eth_node in eth_nodes:
                    after_ethNodeList.append(eth_node)  # ！！！在得到传送eth节点的所有后续节点列表之前，先把负责传送eth节点的本身添加进来，因为.call.value()类型的node本身也是外部调用！！！
                    self._getAllbehindNode(eth_node, after_ethNodeList)

                # 从after_ethNodeList列表中取出所有的节点（记为afterEthNode）, 然后进行调用链的分析
                if after_ethNodeList:
                    print('开始分析 合约{}.函数{}'.format(function.contract.name, function.full_name))
                for afterEthNode in after_ethNodeList:
                    result = self._analyzerCallLink(afterEthNode)  # False代表没有检测到reentrance
                    if result == True:
                        isReentrancy = result
                        break           # 如果只从本身分析就得到了reentrance结果, 就不用遍历后续节点了。
                    else:
                        continue
                if isReentrancy == True:   # 到这里这个函数的所有afterEthNode就遍历分析完了，如果为True。输出reentrance,然后分析下一个函数
                    print('还没回溯就已经找到reentrancy')
                    continue  # 直接开始分析下一个函数

                if not isReentrancy and function_canEth:  # 如果说本函数分析后发现不是reentrance 而且本函数canEth.那么就回找本函数的fatherfunciton
                    print(function.full_name, '只可以传送eth,但自身函数体内没reetrance的结构')
                    isReentrancy, suspiciouPathLength, callPath = self.recursion_backTrack(function, fatherFunctionLayerCount, callPath)  # 递归的去回溯它的fatherFunciton(也就是那个函数调用了这个canEthFunction)
                    if isReentrancy == True:
                        print('ReentranceCallChain in {}.{} 可疑路径： {} 可疑路径长度 = {}'.format(function.contract.name, function.full_name, callPath, suspiciouPathLength))
                        print('==========================================================================================================')
                        print('==========================================================================================================')
                    else:
                        print('No ReentranceCallChain in {}.{}'.format(function.contract.name, function.full_name))
                        print('================================================================================')
                        print('================================================================================')
                    '''
                    fatherFunctionList, result = self.backTrackParse(function)

                    for fatherFunction in fatherFunctionList:
                        print(fatherFunction.full_name)
                    if result == False: #上一层的回溯检测为安全,那么进行下一轮的回溯检测
                        pass
                        for fatherFunction in fatherFunctionList:
                            print('开始从fatherFunction往回追比如', fatherFunction)
                            fatherFunctionList, result_for_fatherFunction = self.backTrackParse(fatherFunction)
                            if fatherFunctionList == []:
                                continue
                            else:
                                

                        # for fatherFunction in fatherFunctionList:
                        #     self.backTrackParse(fatherFunction)
                    else:
                        print("通过回溯，此时已经找到了一条组合reentrancy路径")
                        
                    '''


                    '''fatherFunctionList = self.getfatherFunctions(function)  # 得到了所有的fatherfunction
                    node_calling_ethFunctionWithoutReen = []    # 用于存储那些node(node调用了一个ethFuncion但是没有reen)
                    for fatherFunction in fatherFunctionList:
                        nodes = self._getAllNodes(fatherFunction)
                        for node in nodes:
                            for calledFunciton in node.internal_calls + node.high_level_calls + node.low_level_calls:
                                if calledFunciton.signature_str == function.signature_str:
                                    node_calling_ethFunctionWithoutReen.append(node)
                    after_ethNodeList = self._getAfterEthNodes(node_calling_ethFunctionWithoutReen)  # 得到node_calling_ethFunctionWithoutReen的所有后续节点，同上分析调用链
                    for afterEthNode in after_ethNodeList:
                        self._analyzerCallLink(afterEthNode)'''

                    # if afterNode.internal_calls: # 如果后续节点是internal call 节点那么跳入到call graph
                    #     # 进入call graph
                    #     for internal_call in afterNode.internal_calls:
                    #         calledInternalFuntion = internal_call     # 得到called interalFuntion对象
                    #         calledInternalFuntionNodeList = self._getAllNodes(calledInternalFuntion)  # 得到calledInteralFuntion的所有节点列表
                    #         for calledInternalFuntionNode in calledInternalFuntionNodeList: # 遍历节点列表，为了寻找含有high_level_call或low_level_call的节点
                    #             if calledInternalFuntionNode.high_level_calls or calledInternalFuntionNode.low_level_calls: # 如果找到后，进行脏数据分析
                    #                 print('进行脏数据分析')
                    #             elif:   # 如果没找到，找calledFunction中所有的interal call
                    #                 if calledInternalFuntionNode.internal_calls:

    def recursion_backTrack(self, function, fatherFunctionLayerCount, callPath):
        """
            递归的进行回溯分析
            function: 当前函数，准备去找它的fatherFunction
            fatherFunctionLayerCount: 记录fatherFunction到了哪一级
            :return
            True/Fale(是否是reentrance), fatherFunctionLayerCount(总共回溯了几层)
        """
        fatherFunctionList, result = self.backTrackParse(function)  # 进行回溯
        if result == False:  # 上一层的回溯检测为安全,那么准备进行下一层fatherFunction的回溯检测
            if fatherFunctionList:  # 如果存在下一层fatherFunction
                callPath.append(list(function.full_name for function in fatherFunctionList))
                fatherFunctionLayerCount += 1
                for fatherFunction in fatherFunctionList:
                    print('追到了第 {} 层的爸爸函数：{}'.format(fatherFunctionLayerCount, fatherFunction.full_name))
                    res, length, call_path = self.recursion_backTrack(fatherFunction, fatherFunctionLayerCount, callPath)   # 测试注释 teshhh
                    print('爸爸函数程序列表长度 {}'.format(len(fatherFunctionList)))
                    if res == True:
                        return res, length, call_path
                return res, length, call_path
                    # fatherFunctionList.remove(fatherFunction)
                    # print('移除之后爸爸函数程序列表长度 {}'.format(len(fatherFunctionList)))
                    # if len(fatherFunctionList) >= 1:
                    #     continue
                    # else:
                    #     return res, length, call_path
            else:
                print("回溯后发现依然安全")
                # return False, 0
                return False, fatherFunctionLayerCount, callPath
        else:
            callPath.append(list(function.full_name for function in fatherFunctionList))
            fatherFunctionLayerCount += 1
            print("通过回溯，此时已经找到了一条组合reentrancy路径")
            return True, fatherFunctionLayerCount, callPath
        # if result == True:
        #     print("通过回溯，此时已经找到了一条组合reentrancy路径")
        #     return True, fatherFunctionLayerCount
        # else:
        #     if fatherFunctionList:  # 如果存在下一轮fatherFunction
        #         fatherFunctionLayerCount += 1
        #         for fatherFunction in fatherFunctionList:
        #             print('追到了第 {} 层的爸爸函数：{}'.format(fatherFunctionLayerCount, fatherFunction.full_name))
        #             self.recursion_backTrack(fatherFunction, fatherFunctionLayerCount)
        #     else:
        #         print("回溯后发现依然安全")
        #         return False, 0
    def backTrackParse(self, function):
        '''

        :param function: 从哪那个函数开始回溯的
        :return: fatherFunctionList(这次回溯层的爸爸函数们), result_for_fatherFunction(这次回溯的调研结果)
        '''
        result_for_fatherFunction = False
        fatherFunctionList = self.getfatherFunctions(function)  #得到当前函数的所有fatherfuncions
        node_calling_ethFunctionWithoutReen = []    # 用于存储那些node(node调用了一个ethFuncion(但是没有reen))

        for fatherFunction in fatherFunctionList:
            #print(fatherFunction.full_name)
            high_level_calls = []
            nodes = self._getAllNodes(fatherFunction)   # 得到fatherFunction得所有节点
            for node in nodes:
                for high_level_call_tuple in node.high_level_calls:
                    high_level_calls.append(high_level_call_tuple[1])
                for calledFunciton in node.internal_calls + high_level_calls: # node.low_level_calls先不考虑 fatherFunciton 可以外部调这个ethFunction也可以内部调用ethFunction
                    if calledFunciton.signature_str == function.signature_str:
                        node_calling_ethFunctionWithoutReen.append(node)
        after_ethNodeList = self._getAfterEthNodes(node_calling_ethFunctionWithoutReen)  # 得到node_calling_ethFunctionWithoutReen的所有后续节点，同上分析调用链
        for afterEthNode in after_ethNodeList:
            result = self._analyzerCallLink(afterEthNode)
            if result == True:
                result_for_fatherFunction = result
                break
            else:
                continue
        return fatherFunctionList, result_for_fatherFunction

    def _getAfterEthNodes(self, eth_nodes):
        after_ethNodeList = []
        for eth_node in eth_nodes:
            # 注意这里没有append因为进入这里的已经是fatherFunction了，不能再进入sonFuncion
            self._getAllbehindNode(eth_node, after_ethNodeList)
        return after_ethNodeList

    def _getAllbehindNode(self, node, afterNodeList):
        sons = node.sons
        afterNodeList.extend(sons)
        for son in sons:
            self._getAllbehindNode(son, afterNodeList)

    def _analyzerCallLink(self, node):
        """
        :param node: ethNode后面的所有node
        :return: 不论是外部调用链分析还是内部调用链分析，只要有一个分析找到可重入就返回
        先对这些节点做外部调用链的分析，在做内部调用链的分析
        return 1 代表检测出reentrany, return 0 代表没有检测出reentrancy
        """
        resultExternal = self._externalCallLinkparse(node)
        if resultExternal == 1:
            return True
        resultInternal = self._internalCallLinkparse(node)
        if resultInternal == 1:
            return True
        return False

    def _externalCallLinkparse(self, node):
        externalCallLink_parse_Result = 0  # 证明这个调用链的dest不脏
        """
        :param node: 含有外部调用的node（跨合约）
        :return: 如果确实是脏数据则返回1
        遇到外部调用需要进行的分析
        1:先进行外部调用的脏数据分析：
            若确定为脏数据，打印‘reentrance’并返回1
            否则， 进入这个干净外部函数内得到他的所有node,再次分析调用链self._analyzerCallLink(calledExternalFunctionNode)
        """
        print("进入外部调用链分析")
        print('开始分析的节点是', node.type)
        taintflag = False
        if node.high_level_calls or node.low_level_calls:
            # if node.low_level_calls:   # 这块仅仅是模拟没有任何参考价值
            #     taintflag = True
            print('进行脏数据分析...')
            for ir in node.irs:
                if hasattr(ir, 'destination'):
                    taintflag = is_tainted(ir.destination, node.function.contract)
            if taintflag:   # 如果数据脏则打印Reentrance
                print('脏')
                externalCallLink_parse_Result = 1
                return externalCallLink_parse_Result

            else:   # 如果数据干净，跳入external call的Function.
                print('不脏')
                high_level_calls = []
                for high_level_calls_tuple in node.high_level_calls:
                    high_level_calls.append(high_level_calls_tuple[1])
                # for external_calls in high_level_calls:  # node.low_level_calls暂不考虑，因为根据node.low_level_call目前还跳不进去这个called外部调用函数
                    for external_call in high_level_calls:
                        calledExternalFunction = external_call  # 得到called外部调用函数对象实例
                        print('准备跳转到外部调用函数中：', calledExternalFunction.full_name)
                        calledExternalFunctionNodeList = self._getAllNodes(calledExternalFunction)
                        for calledExternalFunctionNode in calledExternalFunctionNodeList:
                            externalCallLink_parse_Result = self._analyzerCallLink(calledExternalFunctionNode)
                            if externalCallLink_parse_Result == 1:
                                return externalCallLink_parse_Result

        return externalCallLink_parse_Result

    def _internalCallLinkparse(self, node):
        internalCallLinkparse_Result = 0
        '''
        :param node: 含有内部调用的node（跨函数）
        :return:
        1：跳入到internal function中，的到它的所有node:
           如果含有external node，调用self._externalCallLinkparse(calledInternalFuntionNode)
           否则，调用自己
        '''
        print('进入内部调用链分析')
        if node.internal_calls:  # 如果后续节点是internal call 节点那么跳入到call graph
            for internal_call in node.internal_calls:  # 进入call graph
                calledInternalFuntion = internal_call  # 得到called interalFuntion对象
                calledInternalFuntionNodeList = self._getAllNodes(calledInternalFuntion)  # 得到calledInteralFuntion的所有节点列表
                for calledInternalFuntionNode in calledInternalFuntionNodeList:  # 遍历节点列表，为了寻找含有high_level_call或low_level_call的节点
                    if calledInternalFuntionNode.high_level_calls or calledInternalFuntionNode.low_level_calls:  # 如果找到含有外部调用节点
                        result = self._externalCallLinkparse(calledInternalFuntionNode)  # ！！
                        if result == 1:
                            internalCallLinkparse_Result = 1
                            return internalCallLinkparse_Result
                    else:
                        if calledInternalFuntionNode.internal_calls:
                            self._internalCallLinkparse(calledInternalFuntionNode)

        return internalCallLinkparse_Result
    def _getAllNodes(self, function):
        return function.nodes



    def getfatherFunctions(self, currentFunction):
        '''

        :param currentFunction: 当前函数
        :return: fatherFunctions（list:当前函数的所有fatherfunction）
        '''
        fatherFunctions = []  # 用于存储当前函数的所有fatherfunction，也就是返回值
        for contract in self.contracts:
            for function in contract.functions_and_modifiers_declared:
                high_level_calls = []  # 存每一个函数的外部（目前highlevel，还缺少lowlevel）调用函数
                print('现在遍历到的函数是: {}.{}'.format(function.contract.name, function.full_name))
                print('外部调用列表：', function.high_level_calls)
                print('内部调用列表：', function.internal_calls)
                for high_level_call_tuple in function.high_level_calls:  # 因为function.high_level_calls返回值为这样的存储形式[(contract, funtion), (contract, function), ...].故需要提取出function
                    high_level_calls.append(high_level_call_tuple[1])
                if currentFunction in list(set(function.internal_calls + high_level_calls)):  # 暂时不考虑function.low_level_calls
                    fatherFunctions.append(function)
                    print('将{}添加到爸爸中'.format(function.full_name))
                # for function in function.internal_calls + high_level_calls:
                #     if (currentFunction._contract.name == function._contract.name and currentFunction.full_name == function.full_name):
                #         fatherFunctions.append(function)
        print('----------fatherFunction层分割线--------  爸爸函数们的个数{}'.format(len(fatherFunctions)))
        for fatherFunction in fatherFunctions:
            print(fatherFunction.full_name)
        return fatherFunctions

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

    def isTaint(self, contract):
        for function in contract.functions_and_modifiers_declared:
           # print('{} -> {}'.format(type(function.visibility), function.visibility))
           #if function.visibility in ['public', 'external']:
           for node in function.nodes:
               taintRes = False
               if node.high_level_calls or node.low_level_calls:
                   for ir in node.irs:
                       if hasattr(ir, 'destination'):
                           taintRes = is_tainted(ir.destination, function.contract)
                           print('Function: {} dest: {}  isTaint {}'.format(function.full_name, ir.destination, taintRes))



         

    # def _explore(self, node, visited, skip_father=None):
    #     """
    #         Explore the CFG and look for re-entrancy
    #         Heuristic: There is a re-entrancy if a state variable is written after an external call
    #
    #         node.context will contains the external calls executed It contains the calls executed in father nodes
    #
    #         if node.context is not empty, and variables are written, a re-entrancy is possible
    #     """
    #     if node in visited:
    #         return
    #
    #     visited = visited + [node]
    #
    #     # First we add the external calls executed in previous nodes
    #     # send_eth returns the list of calls sending value
    #     # calls returns the list of calls that can callback
    #     # read returns the variable read
    #     # read_prior_calls returns the variable read prior a call
    #     fathers_context = {'send_eth':set(), 'calls':set(), 'read':set(), 'read_prior_calls':{}}
    #
    #     for father in node.fathers:
    #         if self.KEY in father.context:
    #             fathers_context['send_eth'] |= set([s for s in father.context[self.KEY]['send_eth'] if s!=skip_father])
    #             fathers_context['calls'] |= set([c for c in father.context[self.KEY]['calls'] if c!=skip_father])
    #             fathers_context['read'] |= set(father.context[self.KEY]['read'])
    #             fathers_context['read_prior_calls'] = union_dict(fathers_context['read_prior_calls'], father.context[self.KEY]['read_prior_calls'])
    #
    #     # Exclude path that dont bring further information
    #     if node in self.visited_all_paths:
    #         if all(call in self.visited_all_paths[node]['calls'] for call in fathers_context['calls']):
    #             if all(send in self.visited_all_paths[node]['send_eth'] for send in fathers_context['send_eth']):
    #                 if all(read in self.visited_all_paths[node]['read'] for read in fathers_context['read']):
    #                     if dict_are_equal(self.visited_all_paths[node]['read_prior_calls'], fathers_context['read_prior_calls']):
    #                         return
    #     else:
    #         self.visited_all_paths[node] = {'send_eth':set(), 'calls':set(), 'read':set(), 'read_prior_calls':{}}
    #
    #     self.visited_all_paths[node]['send_eth'] = set(self.visited_all_paths[node]['send_eth'] | fathers_context['send_eth'])
    #     self.visited_all_paths[node]['calls'] = set(self.visited_all_paths[node]['calls'] | fathers_context['calls'])
    #     self.visited_all_paths[node]['read'] = set(self.visited_all_paths[node]['read'] | fathers_context['read'])
    #     self.visited_all_paths[node]['read_prior_calls'] = union_dict(self.visited_all_paths[node]['read_prior_calls'], fathers_context['read_prior_calls'])
    #
    #     node.context[self.KEY] = fathers_context
    #
    #     state_vars_read = set(node.state_variables_read)
    #
    #     # All the state variables written
    #     state_vars_written = set(node.state_variables_written)
    #     slithir_operations = []
    #     # Add the state variables written in internal calls
    #     for internal_call in node.internal_calls:
    #         # Filter to Function, as internal_call can be a solidity call
    #         if isinstance(internal_call, Function):
    #             state_vars_written |= set(internal_call.all_state_variables_written())
    #             state_vars_read |= set(internal_call.all_state_variables_read())
    #             slithir_operations += internal_call.all_slithir_operations()
    #
    #     contains_call = False
    #     node.context[self.KEY]['written'] = set(state_vars_written)
    #     if self._can_callback(node.irs + slithir_operations):
    #         node.context[self.KEY]['calls'] = set(node.context[self.KEY]['calls'] | {node})
    #         node.context[self.KEY]['read_prior_calls'][node] = set(node.context[self.KEY]['read_prior_calls'].get(node, set()) | node.context[self.KEY]['read'] |state_vars_read)
    #         contains_call = True
    #     if self._can_send_eth(node.irs + slithir_operations):
    #         node.context[self.KEY]['send_eth'] = set(node.context[self.KEY]['send_eth'] | {node})
    #
    #     node.context[self.KEY]['read'] = set(node.context[self.KEY]['read'] | state_vars_read)
    #
    #     sons = node.sons
    #     if contains_call and node.type in [NodeType.IF, NodeType.IFLOOP]:
    #         if self._filter_if(node):
    #             son = sons[0]
    #             self._explore(son, visited, node)
    #             sons = sons[1:]
    #         else:
    #             son = sons[1]
    #             self._explore(son, visited, node)
    #             sons = [sons[0]]
    #
    #
    #     for son in sons:
    #         self._explore(son, visited)