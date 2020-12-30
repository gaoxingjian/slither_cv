class MyDeepGraph:
    def __init__(self, vertexNum):
        self.vertexNum = vertexNum
        self.adjMetrix = [[0] * vertexNum for i in range(vertexNum)]
        self.visitedFlag = [False] * vertexNum
        self.pathStack = []

    def printMatrix(self):
        for everyRow in self.adjMetrix:
            print(everyRow)

    def setadjMetrix(self, real_adjMetrix):
        self.adjMetrix = real_adjMetrix

    def getMatrixValue(self, row, column):
        return self.adjMetrix[row][column]

    def getPathofTwoNode(self, start, end):
        paths = []
        self.visitedFlag[start] = True
        self.pathStack.append(start)
        self.findPath(start, end, paths)
        return paths

    def findPath(self, start, end, paths):
        if start == end:
            temp = list(self.pathStack)
            paths.append(temp)
            self.visitedFlag[self.pathStack[-1]] = False
            self.pathStack.pop()
            return
        else:
            unStackedNum = 0
            for i in range(self.vertexNum):
                if self.adjMetrix[start][i] and self.visitedFlag[i] is False:
                    # if self.adjMetrix[start][i] > 1:    # 如果这条边是icfg入边，把dummyEnter入栈
                    #     self.recordStack.extend(self.historyStack)
                    #     self.recordStack.append([start, self.adjMetrix[start].index(1)])
                    # # print('战神：{}'.format(len(self.recordStack)))
                    unStackedNum += 1
                    self.visitedFlag[i] = True
                    self.pathStack.append(i)
                    self.findPath(i, end, paths)
                # if self.adjMetrix[start][i] % 2 == 0 and self.adjMetrix[start][i] != 0:   # 如果这条边是icfg 返回边， self.pathStack.append(栈顶)
                #     if self.recordStack:
                #         self.pathStack.append(self.recordStack[-1][1])
                #         temp = self.recordStack.pop()
                #         self.historyStack.append(temp)
                #         self.findPath(temp[1], end, paths)
            self.visitedFlag[self.pathStack[-1]] = False
            self.pathStack.pop()
#
# def test():
#     graph = MyDeepGraph(5)
#     adjMetrix = [[0]*5 for i in range(5)]
#     adjMetrix[0][1] = 1
#     adjMetrix[1][2] = 1
#     adjMetrix[2][3] = 1
#     adjMetrix[3][4] = 1
#     #adjMetrix[2][4] = 1
#     # adjMetrix[0][1] = 1
#     # adjMetrix[1][5] = 3
#     # adjMetrix[1][2] = 1
#     # adjMetrix[2][3] = 1
#     # adjMetrix[3][4] = 1
#     # adjMetrix[5][6] = 1
#     # adjMetrix[6][7] = 1
#     # adjMetrix[7][8] = 1
#     # adjMetrix[8][2] = 2
#     # adjMetrix[9][5] = 5
#     # adjMetrix[9][10] = 1
#     # adjMetrix[10][11] = 1
#     # adjMetrix[8][10] = 4
#     # adjMetrix[1][12] = 1
#     # adjMetrix[2][12] = 1
#     # adjMetrix[6][13] = 7
#     # adjMetrix[13][14] = 1
#     # adjMetrix[14][17] = 1
#     # adjMetrix[17][7] = 6
#     # adjMetrix[13][15] = 9
#     # adjMetrix[15][18] = 1
#     # adjMetrix[18][16] = 1
#     # adjMetrix[16][14] = 8
#
#
#     graph.setadjMetrix(adjMetrix)
#     graph.printMatrix()
#     paths = graph.getPathofTwoNode(0, 4)
#     print(paths)
# test()

#
# def temp():
#     c = 'aaa'
#     a = [1]
#
#     print(isinstance(c, list))
# temp()
