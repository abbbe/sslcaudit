from PyQt4 import QtCore

class BaseTreeItem(object):
    def __init__(self, parentItem):
        self.parentItem = parentItem
        self.childItems = []

    def parent(self):
        return self.parentItem

    def appendChild(self, item):
        self.childItems.append(item)

    def child(self, row):
        return self.childItems[row]

    def childCount(self):
        return len(self.childItems)

    def columnCount(self):
        return 2

    def row(self):
        if self.parentItem:
            return self.parentItem.childItems.index(self)
        return 0

class ClientTreeItem(BaseTreeItem):
    def __init__(self, header, parentItem):
        BaseTreeItem.__init__(self, parentItem)
        self.header = header

    def data(self, column):
            if column == 0:
                return QtCore.QVariant(self.header)
            elif column == 1:
                return QtCore.QVariant('')
            else:
                return QtCore.QVariant()


class ConnectionProfileTreeItem(BaseTreeItem):
    def __init__(self, parentItem):
        BaseTreeItem.__init__(self, parentItem)

    def data(self, column):
            if column == 0:
                return QtCore.QVariant(self.client_server_test_result.test)
            elif column == 1:
                return QtCore.QVariant(self.client_server_test_result.result)
            else:
                return QtCore.QVariant()
