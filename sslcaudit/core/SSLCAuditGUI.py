''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import sys, logging

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from sslcaudit.core.BaseClientAuditController import BaseClientAuditController, HOST_ADDR_ANY
from sslcaudit.core.ClientConnectionAuditEvent import ClientConnectionAuditResult

import SSLCAuditGUIGenerated

class PyQt4Handler(logging.Handler, QObject):
  '''
  This is a custom logging handler that emits PyQt4 signals when it intercepts messages
  '''

  sendLog = pyqtSignal(str)
  sendError = pyqtSignal(str)
  
  def __init__(self, *args, **kwargs):
    logging.Handler.__init__(self, *args, **kwargs)
    QObject.__init__(self, *args, **kwargs)

  def emit(self, record):
    if record.levelname == 'DEBUG':
      self.sendLog.emit(record.getMessage())
    elif record.levelname == 'ERROR':
      self.sendError.emit(record.getMessage())

class SSLCAuditGUI(object):
  def __init__(self, options):
    '''
    Initialize UI. Dictionary 'options' comes from SSLCAuditUI.parse_options().
    '''
    self.options = options

    self.app = QApplication(sys.argv)
    self.window = SSLCAuditGUIWindow(self.options)

  def run(self):
    self.window.show()
    
    return self.app.exec_()


class SSLCAuditThreadedInterface(QObject):
  sendLog = pyqtSignal(str)
  sendError = pyqtSignal(str)
  sendConnection = pyqtSignal(str)

  def __init__(self):
    QObject.__init__(self)
    
    self.is_running = False


  def parseOptions(self, options):
    self.controller = BaseClientAuditController(options, event_handler=self.event_handler)
    self.options = options
    
  def start(self):
    try:
      self.controller.start()
      self.is_running = True
    except:
      self.sendError.emit(str(sys.exc_info()[1]))

  def stop(self):
    self.controller.stop()
    self.is_running = False

  def isRunning(self):
    return self.is_running

  def event_handler(self, response):
    self.sendConnection.emit(response)


class SSLCAuditGUIWindow(QMainWindow):
  def __init__(self, options, parent=None):
    '''
    Initialize UI. Dictionary 'options' comes from SSLCAuditUI.parse_options().
    '''
    QMainWindow.__init__(self, parent)
    
    self.options = options
    self.settings = QSettings('SSLCAudit')
    self.controller = SSLCAuditThreadedInterface()
    
    # Bind connection debugging to the appropriate function
    self.controller.sendConnection.connect(self.controllerSentConnection)
    
    # Setup and bind the logging handler to the appropriate functions
    self.log_handler = PyQt4Handler()
    self.log_handler.sendLog.connect(self.controllerSentLog)
    self.log_handler.sendError.connect(self.controllerSentError)

    ClientAuditorTCPServerLogger = logging.getLogger('ClientAuditorTCPServer')
    ClientAuditorTCPServerLogger.addHandler(self.log_handler)

    BaseClientAuditControllerLogger = logging.getLogger('BaseClientAuditController')
    BaseClientAuditControllerLogger.addHandler(self.log_handler)

    # Initialize the UI and store it within the self.ui variable
    self.ui = SSLCAuditGUIGenerated.Ui_MainWindow()
    self.ui.setupUi(self)
    
    # Remove focus from the input box. We need the placeholder text.
    self.setFocus()
    
    # Gives the "Start" button an icon.
    self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-start'))
    
    # Gives the "Copy to Cliboard" button an icon.
    self.ui.copyToClipboardButton.setIcon(QIcon.fromTheme('edit-copy'))
    
    # Gives each of the "Browse" buttons an icon and set their appropriate actions
    for control in [
      self.ui.certificateBrowse1,
      self.ui.certificateBrowse2,
      self.ui.keyBrowse1,
      self.ui.keyBrowse2
    ]:
      control.setIcon(QIcon.fromTheme('document-open'))
      self.connect(control, SIGNAL('clicked()'), lambda control=control: self.browseButtonClicked(control.objectName()))
    
    # Validates the port box via an integer validator
    port_validator = QIntValidator(self)
    port_validator.setRange(0, 65535)
    self.ui.portLineEdit.setValidator(port_validator)
    
    # Sets the check state of every item in both QListWidgets. This is
    # needed for the checkboxes to appear, so add the ciphers and
    # protocols via Qt Designer.
    for item in self.childIterator(self.ui.protocolList) + self.childIterator(self.ui.cipherList):
      item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
      item.setCheckState(Qt.Checked)

    self.ui.showDebugMessagesCheckBox.stateChanged.connect(self.changeDebugMessageVisibility)
    
  def childIterator(self, element):
    # Used internally, as PyQt4 doesn't let you iterate over QListWidget items in a Pythonic manner
    return [element.item(i) for i in range(element.count())]
  
  def sendError(self, message):
    QMessageBox.critical(self, 'SSLCAudit', message, QMessageBox.Ok, QMessageBox.Ok)
  
  def controllerSentLog(self, message):
    message = QListWidgetItem(message)
    message.setToolTip('Debug message')

    self.ui.testLog.addItem(message)
    
    if self.ui.showDebugMessagesCheckBox.checkState() != Qt.Checked:
      message.setHidden(True)

  def controllerSentError(self, message):
    message = QListWidgetItem(message)
    message.setToolTip('Error message')
    message.setForeground(QBrush(QColor('Red')))

    self.ui.testLog.addItem(message)
  
  def controllerSentConnection(self, connection):
    print '***'
    print connection
    print '***'

  
  def changeDebugMessageVisibility(self):
    for item in self.childIterator(self.ui.testLog):
      if str(item.toolTip()) == 'Debug message':
        item.setHidden(self.ui.showDebugMessagesCheckBox.checkState() != Qt.Checked)
  
  @pyqtSlot(name='on_copyToClipboardButton_clicked')
  def copyReportToClipboard(self):
    QApplication.clipboard().setText(self.ui.reportText.toPlainText())

  @pyqtSlot(name='on_startButton_clicked')
  def startStopAudit(self):
      if self.controller.isRunning():
        self._stopAudit()
      else:
        self._startAudit()

  def _stopAudit(self):
    try:
      self.controller.stop()
      self.ui.startButton.setText('Start')
      self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-start'))
    except:
      self.sendError(str(sys.exc_info()[1]))

  def _startAudit(self):
    self.ui.startButton.setText('Stop')
    self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-stop'))
    
    try:
      port = int(self.ui.portLineEdit.text())
    except:
      port = 8443
    
    self.options.nclients = self.ui.numerOfRoundsSpinBox.value()
    self.options.listen_on = (
      str(self.ui.hostnameLineEdit.text()),
      port
    )
    try:
      self.controller.parseOptions(self.options)
      self.controller.start()
    except:
      self.sendError(str(sys.exc_info()[1]))
      
      self.ui.startButton.setText('Start')
      self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-start'))
      
  
  
  
  def closeEvent(self, event):
    if self.controller and self.controller.isRunning():
      if QMessageBox.question(self, 'SSLCAudit', 'An audit is currently running. Do you really want to exit?', QMessageBox.Yes, QMessageBox.No) == QMessageBox.Yes:
        self.controller.stop()
        event.accept()
      else:
        event.ignore()
    else:
      event.accept()

  def browseButtonClicked(self, name):
    textbox = getattr(self.ui, str(name).replace('Browse', 'Edit'))
    filename = QFileDialog.getOpenFileName(
      self,
      getattr(self.ui, str(name)).statusTip(),
      self.settings.value('startup/{}'.format(name), QDir.homePath()).toString()
    )
    
    if filename:
      self.settings.setValue('startup/{}'.format(name), filename)
      textbox.setText(filename)