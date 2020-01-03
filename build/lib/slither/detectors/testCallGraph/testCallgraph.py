
from slither.detectors.abstract_detector import (AbstractDetector, DetectorClassification)
from  slither.core.callGraph.CallGraph import CallGraph


class TestCallGraph(AbstractDetector):
    ARGUMENT = 'call_graph_struct'
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
        callGraph = CallGraph(self.slither)
        for function in self.slither.functions:
            callGraph.test(function)
        return []