# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

from PyQt4 import QtCore
import logging
from sslcaudit.core.ResultTreeItem import ClientTreeItem, ConnectionProfileTreeItem

HORIZONTAL_HEADERS = ('Test', 'Result')
RESULT_PENDING = 'pending'

logger = logging.getLogger('CSTR_TTM')

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
        return "ClientServerTestResult - %s %s %s" % (self.client_server, self.test, self.result)


class ClientServerTestResultTreeTableModel(QtCore.QAbstractItemModel):
    def __init__(self, parent=None):
        super(ClientServerTestResultTreeTableModel, self).__init__(parent)
        self.rootItem = ClientTreeItem('ALL', None)  # XXX wtf
        self.parents = {0: self.rootItem}

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
                return item.result
        return QtCore.QVariant()

    def headerData(self, column, orientation, role):
        if (orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole):
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

    def new_client(self, client_id, profiles):
        '''
        This method is invoked when the main window handles events from the controller (via the bridge).
        Here we create a new subtree for the client and add it to the list of connections.
        '''
        # create the subtree containing profiles
        newClientTreeItem = ClientTreeItem(client_id, self.rootItem)
        for profile in profiles:
            newConnProfileItem = ConnectionProfileTreeItem(newClientTreeItem, profile, RESULT_PENDING)
            newClientTreeItem.appendChild(newConnProfileItem)

        # insert the new node under the parent node
        n = self.rootItem.childCount()
        self.beginInsertRows(QtCore.QModelIndex(), n, n)
        self.rootItem.appendChild(newClientTreeItem)
        self.parents[client_id] = newClientTreeItem
        self.endInsertRows()

    def new_conn_result(self, client_id, profile, result):
        '''
        This method is invoked when the main window handles events from the controller (via the bridge).
        '''
        if client_id in self.parents:
            client = self.parents[client_id]
            
            for profile_id in range(client.childCount()):
                _profile = client.child(profile_id)
                
                if _profile.profile == profile:
                    _profile.result = result
                    # XXX need to call self.dataChanged() here?
                    return
            logger.error('got "new_conn_result" event, but cannot find a row for it')
        else:
            logger.error('received "new_conn_result" event for client id "%s" but there is no subtree for it' % (client_id))


    def client_done(self, client_id, results):
        '''
        This method is when the main window handles events from the controller (via bridge).
        '''
        print '*** client done ***'
