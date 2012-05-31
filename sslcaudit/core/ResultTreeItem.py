import PyQt4.QtCore

__author__ = 'abb'

class TreeItem(object):
    '''
    a python object used to return row/column data, and keep note of
    it's parents and/or children
    '''
    def __init__(self, client_server_test_result, header, parentItem):
        self.client_server_test_result = client_server_test_result
        self.parentItem = parentItem
        self.header = header
        self.childItems = []

    def appendChild(self, item):
        self.childItems.append(item)

    def child(self, row):
        return self.childItems[row]

    def childCount(self):
        return len(self.childItems)

    def columnCount(self):
        return 2

    def data(self, column):
        if self.client_server_test_result == None:
            if column == 0:
                return QtCore.QVariant(self.header)
            if column == 1:
                return QtCore.QVariant('')
        else:
            if column == 0:
                return QtCore.QVariant(self.client_server_test_result.test)
            if column == 1:
                return QtCore.QVariant(self.client_server_test_result.result)
        return QtCore.QVariant()

    def parent(self):
        return self.parentItem

    def row(self):
        if self.parentItem:
            return self.parentItem.childItems.index(self)
        return 0