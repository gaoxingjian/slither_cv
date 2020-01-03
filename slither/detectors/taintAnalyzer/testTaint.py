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


class TestTaint(AbstractDetector):
    ARGUMENT = 'testTaint'
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
            #self.detect_reentrancy(c)

        return []

    def detect_reentrancy(self, contract):
        for function in contract.functions_and_modifiers_declared:
            if function.is_implemented:
                pass

    def isTaint(self, contract):
        for function in contract.functions_and_modifiers_declared:
           if function.visibility in ['public', 'external']:
               for node in function.nodes:
                   taintRes = False
                   if node.high_level_calls or node.low_level_calls:
                       for ir in node.irs:
                           if hasattr(ir, 'destination'):
                               taintRes = is_tainted(ir.destination, function.contract)
                               print('Function: {} dest: {}  isTaint {}'.format(function.full_name, ir.destination, taintRes))
