from slither.core.source_mapping.source_mapping import SourceMapping
from slither.core.children.child_contract import ChildContract





class FunctionNode(SourceMapping, ChildContract):
    def __init__(self, node_id, function):
        super(FunctionNode, self).__init__()
        self._node_id = node_id
        self._sons = []
        self._fathers = []
        self._function = function
        self._taint = False
        self._eth = False
    @property
    def tiant(self):
        return self._taint

    def setTaint(self, taint):
        self._taint = taint
    def setEth(self, eth):
        self._eth = eth
    @property
    def function(self):
        return self._function

    @property
    def slither(self):
        return self._function.slither

    @property
    def node_id(self):
        """Unique node id."""
        return self._node_id

    def add_father(self, father):
        """ Add a father node

        Args:
            father: father to add
        """
        self._fathers.append(father)

    @property
    def fathers(self):
        """ Returns the father nodes

        Returns:
            list(Node): list of fathers
        """
        return list(self._fathers)

    def add_son(self, son):
        """ Add a son node

        Args:
            son: son to add
        """
        self._sons.append(son)

    def set_sons(self, sons):
        """ Set the son nodes

        Args:
            sons: list of fathers to add
        """
        self._sons = sons

    @property
    def sons(self):
        """ Returns the son nodes

        Returns:
            list(Node): list of sons
        """
        return list(self._sons)

