from PyQt4 import QtCore

HORIZONTAL_HEADERS = ('Test', 'Result')

# http://rowinggolfer.blogspot.com/2010/05/qtreeview-and-qabractitemmodel-example.html

class ClientServerTestResult(object):
    '''
    a trivial custom data object
    '''
    def __init__(self, client_server, test, result):
        self.client_server = client_server
        self.test = test
        self.result = result

    def __repr__(self):
        return "ClientServerTestResult - %s %s %s"% (self.client_server, self.test, self.result)


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


class ClientServerTestResultTreeTableModel(QtCore.QAbstractItemModel):
    def __init__(self, parent=None):
        super(ClientServerTestResultTreeTableModel, self).__init__(parent)
        self.cstrs = []

        for client_server, test, result in (('A -> B:C', 'sslcert/selfsigned', 'OK'), ('A -> B:C', 'sslcert/testsigned', 'NOK'),):
            client_server_test_result = ClientServerTestResult(client_server, test, result)
            self.cstrs.append(client_server_test_result)

        self.rootItem = TreeItem(None, 'ALL', None)
        self.parents = {0 : self.rootItem}
        self.setupModelData()

    def columnCount(self, parent=None):
        if parent and parent.isValid():
            return parent.internalPointer().columnCount()
        else:
            return len(HORIZONTAL_HEADERS)

    def data(self, index, role):
        if not index.isValid():
            return QtCore.QVariant()

        item = index.internalPointer()
        if role == QtCore.Qt.DisplayRole:
            return item.data(index.column())
        if role == QtCore.Qt.UserRole:
            if item:
                return item.person
        return QtCore.QVariant()

    def headerData(self, column, orientation, role):
        if (orientation == QtCore.Qt.Horizontal and
            role == QtCore.Qt.DisplayRole):
            try:
                return QtCore.QVariant(HORIZONTAL_HEADERS[column])
            except IndexError:
                pass
        return QtCore.QVariant()

    def index(self, row, column, parent):
        if not self.hasIndex(row, column, parent):
            return QtCore.QModelIndex()

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        childItem = parentItem.child(row)
        if childItem:
            return self.createIndex(row, column, childItem)
        else:
            return QtCore.QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QtCore.QModelIndex()

        childItem = index.internalPointer()
        if not childItem:
            return QtCore.QModelIndex()

        parentItem = childItem.parent()

        if parentItem == self.rootItem:
            return QtCore.QModelIndex()

        return self.createIndex(parentItem.row(), 0, parentItem)

    def rowCount(self, parent=QtCore.QModelIndex()):
        if parent.column() > 0:
            return 0
        if not parent.isValid():
            p_Item = self.rootItem
        else:
            p_Item = parent.internalPointer()
        return p_Item.childCount()

    def setupModelData(self):
        for cstr in self.cstrs:
            sex = cstr.client_server
            if not self.parents.has_key(sex):
                newparent = TreeItem(None, sex, self.rootItem)
                self.rootItem.appendChild(newparent)
                self.parents[sex] = newparent

            parentItem = self.parents[sex]
            newItem = TreeItem(cstr, '', parentItem)
            parentItem.appendChild(newItem)
