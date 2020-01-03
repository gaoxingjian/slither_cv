"""
    Compute the data depenency between all the SSA variables
"""
from slither.core.declarations import (Contract, Enum, Function,
                                       SolidityFunction, SolidityVariable,
                                       SolidityVariableComposed, Structure)
from slither.slithir.operations import Index, OperationWithLValue, InternalCall
from slither.slithir.variables import (Constant, LocalIRVariable,
                                       ReferenceVariable, ReferenceVariableSSA,
                                       StateIRVariable, TemporaryVariable,
                                       TemporaryVariableSSA, TupleVariableSSA)
from slither.core.solidity_types.type import Type
from slither.core.variables.local_variable import LocalVariable
from slither.detectors.ICFG_Reentrancy.smallUtils import defenseModifier

###################################################################################
###################################################################################
# region User APIs
###################################################################################
###################################################################################

def is_dependent(variable, source, context, only_unprotected=False):
    '''
    用于判断variable 与 source之间是否有依赖关系
    Args:
        variable (Variable)
        source (Variable)
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    '''
    assert isinstance(context, (Contract, Function))
    if isinstance(variable, Constant):
        return False    # 如果这个变量是常量则没有依赖关系，直接返回false
    if variable == source:
        return True     # 这句意思是自己同自己是有依赖关系的
    context = context.context     # context (Contract|Function) 得到合约或函数的上下文对象

    if only_unprotected:    # only_unprotected == True 说明只考虑为保护的function
        return variable in context[KEY_NON_SSA_UNPROTECTED] and source in context[KEY_NON_SSA_UNPROTECTED][variable]
        # KEY_NON_SSA = "DATA_DEPENDENCY"
    return variable in context[KEY_NON_SSA] and source in context[KEY_NON_SSA][variable] # 意思是{{variable:{source, ..}}, ..}

def is_dependent_ssa(variable, source, context, only_unprotected=False):
    '''
    Args:
        variable (Variable)
        taint (Variable)
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    '''
    assert isinstance(context, (Contract, Function))
    context = context.context
    if isinstance(variable, Constant):
        return False
    if variable == source:
        return True
    if only_unprotected:
        return variable in context[KEY_SSA_UNPROTECTED] and source in context[KEY_SSA_UNPROTECTED][variable]
        # KEY_SSA = "DATA_DEPENDENCY_SSA"
    return variable in context[KEY_SSA] and source in context[KEY_SSA][variable]

GENERIC_TAINT = {SolidityVariableComposed('msg.sender'),
                 SolidityVariableComposed('msg.value'),
                 SolidityVariableComposed('msg.data'),
                 SolidityVariableComposed('tx.origin')}

def is_tainted(variable, context, only_unprotected=False, ignore_generic_taint=False):
    '''
        Args:
        variable
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    '''
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if isinstance(variable, Constant):  # 变量是常量那么not taint
        return False
    slither = context.slither
    taints = slither.context[KEY_INPUT]  # KEY_INPUT = "DATA_DEPENDENCY_INPUT" taints是一个set类型
    taint_in_constructor = set()    # 在构造器里面的taint,后续程序是要减掉的
    for taint in taints:
        if isinstance(taint, LocalVariable):
            if taint.function.is_constructor:
                taint_in_constructor.add(taint)
    taints = taints - taint_in_constructor  # 减掉构造器中的所有taint变量（包括， 构造器中的taintSource或别传播的变量）
    if not ignore_generic_taint:
        taints |= GENERIC_TAINT  # 我们主要关系里面的msg.sender, tx.origin这两个SolidityVariable
    # 有了taints 我们就可以看看待测variable是不是在taints集合中 或 是不是与taints集合中的元素有dependent
    return variable in taints or any(is_dependent(variable, t, context, only_unprotected) for t in taints)

def is_tainted_ssa(variable, context, only_unprotected=False, ignore_generic_taint=False):
    '''
    Args:
        variable
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    '''
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if isinstance(variable, Constant):
        return False
    slither = context.slither
    taints = slither.context[KEY_INPUT_SSA]
    if not ignore_generic_taint:
        taints |= GENERIC_TAINT
    return variable in taints or any(is_dependent_ssa(variable, t, context, only_unprotected) for t in taints)


def get_dependencies(variable, context, only_unprotected=False):
    '''
    Args:
        variable
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        list(Variable)
    '''
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if only_unprotected:
        return context.context[KEY_NON_SSA].get(variable, [])
    return context.context[KEY_NON_SSA_UNPROTECTED].get(variable, [])

# endregion
###################################################################################
###################################################################################
# region Module constants
###################################################################################
###################################################################################

KEY_SSA = "DATA_DEPENDENCY_SSA"
KEY_NON_SSA = "DATA_DEPENDENCY"

# Only for unprotected functions
KEY_SSA_UNPROTECTED = "DATA_DEPENDENCY_SSA_UNPROTECTED"
KEY_NON_SSA_UNPROTECTED = "DATA_DEPENDENCY_UNPROTECTED"

KEY_INPUT = "DATA_DEPENDENCY_INPUT"
KEY_INPUT_SSA = "DATA_DEPENDENCY_INPUT_SSA"


# endregion
###################################################################################
###################################################################################
# region Debug
###################################################################################
###################################################################################

def pprint_dependency(context):
    print('#### SSA ####')
    context = context.context
    for k, values in context[KEY_SSA].items():
        print('{} ({}):'.format(k, id(k)))
        for v in values:
            print('\t- {}'.format(v))

    print('#### NON SSA ####')
    for k, values in context[KEY_NON_SSA].items():
        print('{} ({}):'.format(k, hex(id(k))))
        for v in values:
            print('\t- {} ({})'.format(v, hex(id(v))))

# endregion
###################################################################################
###################################################################################
# region Analyses
###################################################################################
###################################################################################

def compute_dependency(slither):

    slither.context[KEY_INPUT] = set()
    slither.context[KEY_INPUT_SSA] = set()

    for contract in slither.contracts:
        compute_dependency_contract(contract, slither)  # 计算每一个合约的的数据依赖

def compute_dependency_contract(contract, slither): # slither.context['DATA_DEPENDENCY_INPUT'：set()]; slither.context['DATA_DEPENDENCY_INPUT_SSA'：set()]
    if KEY_SSA in contract.context:  #KEY_SSA == 'DATA_DEPENDENCY_SSA'
        return

    contract.context[KEY_SSA] = dict()
    contract.context[KEY_SSA_UNPROTECTED] = dict()

    for function in contract.all_functions_called:  # list(Function): List of functions reachable from the contract
        compute_dependency_function(function)

        propagate_function(contract, function, KEY_SSA, KEY_NON_SSA)
        propagate_function(contract, function, KEY_SSA_UNPROTECTED, KEY_NON_SSA_UNPROTECTED)

        if function.visibility in ['public', 'external']:
            defenseModifiers = defenseModifier()        # 含有可疑modifier的public function parameters不作为taint源头
            if any(modifier.name in defenseModifiers for modifier in function.modifiers):
                continue
            [slither.context[KEY_INPUT].add(p) for p in function.parameters]
            [slither.context[KEY_INPUT_SSA].add(p) for p in function.parameters_ssa]

    propagate_contract(contract, KEY_SSA, KEY_NON_SSA)
    propagate_contract(contract, KEY_SSA_UNPROTECTED, KEY_NON_SSA_UNPROTECTED)

def propagate_function(contract, function, context_key, context_key_non_ssa):
    transitive_close_dependencies(function, context_key, context_key_non_ssa)
    # Propage data dependency
    data_depencencies = function.context[context_key]
    for (key, values) in data_depencencies.items():
        if not key in contract.context[context_key]:
            contract.context[context_key][key] = set(values)
        else:
            contract.context[context_key][key].union(values)

def transitive_close_dependencies(context, context_key, context_key_non_ssa):
    # transitive closure
    changed = True
    while changed:
        changed = False
        # Need to create new set() as its changed during iteration
        data_depencencies = {k: set([v for v in values]) for k, values in context.context[context_key].items()}
        for key, items in data_depencencies.items():
            for item in items:
                if item in data_depencencies:
                    additional_items = context.context[context_key][item]
                    for additional_item in additional_items:
                        if not additional_item in items and additional_item != key:
                            changed = True
                            context.context[context_key][key].add(additional_item)
    context.context[context_key_non_ssa] = convert_to_non_ssa(context.context[context_key])


def propagate_contract(contract, context_key, context_key_non_ssa):
    transitive_close_dependencies(contract, context_key, context_key_non_ssa)

def add_dependency(lvalue, function, ir, is_protected):
    '''

    :param lvalue: => ir.lvalue（或其他,得看一眼caller） 这个左变量类型不能既是LocalIRVariable又是storage
    :param function:
    :param ir: => for ir in node.irs_ssa:
    :param is_protected: 当前的function 是否被保护（require(msg.sender)等）
    :return:
    '''
    if not lvalue in function.context[KEY_SSA]:
        function.context[KEY_SSA][lvalue] = set()
        if not is_protected:
            function.context[KEY_SSA_UNPROTECTED][lvalue] = set()
    # 接下来做的是看ir.lvalue 读了哪些
    if isinstance(ir, Index):  # 情况1：如果ir是Index
        read = [ir.variable_left]
    elif isinstance(ir, InternalCall):  # 情况2：如果ir是InternalCall （这个地方我们可以考虑是否添加ExternalCall）
        read = ir.function.return_values_ssa
    else:   # 其余情况
        read = ir.read
    [function.context[KEY_SSA][lvalue].add(v) for v in read if not isinstance(v, Constant)]
    if not is_protected:
        [function.context[KEY_SSA_UNPROTECTED][lvalue].add(v) for v in read if not isinstance(v, Constant)]


def compute_dependency_function(function):
    if KEY_SSA in function.context:
        return

    function.context[KEY_SSA] = dict()
    function.context[KEY_SSA_UNPROTECTED] = dict()

    is_protected = function.is_protected()
    for node in function.nodes:
        for ir in node.irs_ssa:
            if isinstance(ir, OperationWithLValue) and ir.lvalue:
                if isinstance(ir.lvalue, LocalIRVariable) and ir.lvalue.is_storage:  # 如果左变量既是LocalIRVariable又是storage, 那就跳过
                    continue
                if isinstance(ir.lvalue, ReferenceVariable):
                    lvalue = ir.lvalue.points_to
                    if lvalue:
                        add_dependency(lvalue, function, ir, is_protected)
                add_dependency(ir.lvalue, function, ir, is_protected)

    function.context[KEY_NON_SSA] = convert_to_non_ssa(function.context[KEY_SSA])
    function.context[KEY_NON_SSA_UNPROTECTED] = convert_to_non_ssa(function.context[KEY_SSA_UNPROTECTED])

def convert_variable_to_non_ssa(v):
    if isinstance(v, (LocalIRVariable, StateIRVariable, TemporaryVariableSSA, ReferenceVariableSSA, TupleVariableSSA)):
        return v.non_ssa_version
    assert isinstance(v, (Constant, SolidityVariable, Contract, Enum, SolidityFunction, Structure, Function, Type))
    return v

def convert_to_non_ssa(data_depencies):
    # Need to create new set() as its changed during iteration
    ret = dict()
    for (k, values) in data_depencies.items():
        var = convert_variable_to_non_ssa(k)
        if not var in ret:
            ret[var] = set()
        ret[var] = ret[var].union(set([convert_variable_to_non_ssa(v) for v in
                                       values]))

    return ret
