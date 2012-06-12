# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------
from os.path import dirname

import sys, logging
import traceback

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from sslcaudit.core.BaseClientAuditController import BaseClientAuditController
from sslcaudit.ui import SSLCAuditGUIGenerated
from sslcaudit.modules.sslcert.ProfileFactory import DEFAULT_CN
from sslcaudit.core.ConnectionAuditEvent import ConnectionAuditResult, SessionStartEvent, ControllerEvent, SessionEndResult
from sslcaudit.ui.ClientServerTestResultTreeTableModel import ClientServerTestResultTreeTableModel

logger = logging.getLogger('SSLCAuditGUI')

INITIAL_DIR_SETTING_NAME = 'startup/certDir'

class SSLCAuditGUI(object):
  def __init__(self, options, file_bag):
    '''
    Initialize UI. Dictionary 'options' comes from SSLCAuditUI.parse_options().
    '''
    self.options = options

    self.app = QApplication(sys.argv)
    self.window = SSLCAuditGUIWindow(self.options, file_bag)

  def run(self):
    self.window.show()
    
    return self.app.exec_()


class SSLCAuditQtBridge(logging.Handler, QThread):
  '''
  This class is a bridge between PyQt GUI and the core of sslcaudit.
  The main window contains an instance of this class and uses it to communicate with the core.
  It invokes start(), stop(), isRunning() methods of the core to control it.
  It uses sendLog, sendError, sendConnection signals to receive events from the core.
  This class does not contain any control rules by itself.
  '''
  sendLog = pyqtSignal(logging.LogRecord)
  sendControllerEvent = pyqtSignal(ControllerEvent)

  def __init__(self, file_bag):
    logging.Handler.__init__(self)
    self.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt='%H:%M:%S'))

    QThread.__init__(self)
    self.file_bag = file_bag
    self.is_running = False

  def emit(self, record):
    '''
    This method overrides logging.Handler.emit()
    '''
    self.sendLog.emit(record)

  def init_controller(self, options):
    self.options = options
    self.controller = BaseClientAuditController(self.options, self.file_bag, event_handler=self.event_handler)

  def start(self):
    self.controller.start()
    self.is_running = True

  def run(self):
    raise NotImplemented('there is no use for this "thread" to run')

  def isRunning(self):
    return self.is_running

  def stop(self):
    self.controller.stop()

    self.is_running = False
    self.exit()

  def event_handler(self, event):
    '''
    This method gets invoked asynchronously by BaseClientAuditController thread
    '''
    self.sendControllerEvent.emit(event)


class SSLCAuditGUIWindow(QMainWindow):
  def __init__(self, options, file_bag, parent=None):
    '''
    Initialize UI. Dictionary 'options' comes from SSLCAuditUI.parse_options().
    '''
    QMainWindow.__init__(self, parent)
    
    self.options = options
    self.file_bag = file_bag
    self.settings = QSettings('SSLCAudit')
    self.bridge = SSLCAuditQtBridge(file_bag)
    self.cstr_ttm = ClientServerTestResultTreeTableModel(self)

    # Bind connection debugging to the appropriate function
    self.bridge.sendControllerEvent.connect(self.controllerSentEvent)
    
    # Setup and bind the logging handler to the appropriate functions
    self.bridge.sendLog.connect(self.controllerSentLog)
    logging.getLogger().addHandler(self.bridge)

    # Initialize the UI and store it within the self.ui variable
    self.ui = SSLCAuditGUIGenerated.Ui_MainWindow()
    self.ui.setupUi(self)

    # Replace placeholder text in checkbox
    self.ui.useDefaultCNCheckbox.setText(str(self.ui.useDefaultCNCheckbox.text()).format(cn=DEFAULT_CN))

    # Hide unimplemented controls
    for control in [
      self.ui.generateButton,
      self.ui.exportPKCS12Button
    ]:
      control.hide()
    
    # Remove focus from the input box. We need the placeholder text.
    self.setFocus()
    
    # Gives the "Start" button an icon.
    self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-start'))

    # Gives the "Clear" button an icon
    self.ui.clearLogButton.setIcon(QIcon.fromTheme('gtk-clear'))
    
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

    self.ui.treeView.setModel(self.cstr_ttm)

  def childIterator(self, element):
    # Used internally, as PyQt4 doesn't let you iterate over QListWidget items in a Pythonic manner
    return [element.item(i) for i in range(element.count())]
  
  def reportError(self, message, debug_info):
    QMessageBox.critical(self, 'Error', message, QMessageBox.Ok, QMessageBox.Ok)
    logger.error(message)
    if debug_info:
      logger.debug(debug_info)

  def show_debug_messages_enabled(self):
    return self.ui.showDebugMessagesCheckBox.checkState() == Qt.Checked

  def controllerSentLog(self, log_record):
    log_record_text = self.bridge.format(log_record)
    message = QListWidgetItem(log_record_text)
    hide = False
    if log_record.levelno <= logging.DEBUG:
      message.setToolTip('Debug message')
      message.setForeground(QBrush(QColor('Grey')))
      if not self.show_debug_messages_enabled():
        hide = True
    elif log_record.levelno == logging.INFO:
      message.setToolTip('Info message')
    else:
      message.setToolTip('Error message')
      message.setForeground(QBrush(QColor('Red')))

    self.ui.testLog.addItem(message)
    message.setHidden(hide)

  def controllerSentEvent(self, event):
    if isinstance(event, SessionStartEvent):
      self.cstr_ttm.new_client(event.session_id, event.profiles)
    elif isinstance(event, ConnectionAuditResult):
      self.cstr_ttm.new_conn_result(event.conn.get_session_id(), event.profile, event.result)
    elif isinstance(event, SessionEndResult):
      self.cstr_ttm.client_done(event.session_id, event.results)
    else:
      raise ValueError('unexpected event: %s' % event)


  def changeDebugMessageVisibility(self):
    hideDebugMessages = not self.show_debug_messages_enabled()
    for item in self.childIterator(self.ui.testLog):
      if str(item.toolTip()) == 'Debug message':
        item.setHidden(hideDebugMessages)
  
  @pyqtSlot(name='on_copyToClipboardButton_clicked')
  def copyReportToClipboard(self):
    QApplication.clipboard().setText(self.ui.reportText.toPlainText())

  @pyqtSlot(name='on_clearLogButton_clicked')
  def clearLog(self):
    self.ui.testLog.clear()

  @pyqtSlot(name='on_startButton_clicked')
  def toggleAudit(self):
    if self.bridge.isRunning():
      self._stopAudit()
    else:
      self._startAudit()

  def _stopAudit(self):
    try:
      self.bridge.stop()
      self.ui.startButton.setText('Start')
      self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-start'))
    except:
      self.reportError(str(sys.exc_info()[1]))

  def _startAudit(self):
    self.ui.startButton.setText('Stop')
    self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-stop'))
    
    port = int(self.ui.portLineEdit.text())

    # -- server tab
    if self.ui.dontFetchCertificateRadioButton.isChecked():
      self.options.server_use_orig_dest = False
      self.options.server = None
    elif self.ui.fetchCertificateRadioButton.isChecked():
      self.options.server_use_orig_dest = True
      self.options.server = None
    elif self.ui.fetchCustomCertificateRadioButton.isChecked():
        self.options.server_use_orig_dest = False
        self.options.server = str(self.ui.customCertificateLineEdit.text()).strip()

    # -- sslcert tab / CN
    self.options.no_default_cn = not self.ui.useDefaultCNCheckbox.isChecked()
    self.options.user_cn = str(self.ui.customCNLineEdit.text()).strip() or None

    # -- sslcert tab / user cert
    if self.ui.useCertificateGroupBox.isChecked():
      self.options.user_cert = str(self.ui.certificateEdit1.text())
      self.options.user_key = str(self.ui.keyEdit1.text())
    else:
      self.options.user_cert = None
      self.options.user_key = None

    # -- sslcert tab / user CA
    if self.ui.useCAGroupBox.isChecked():
      self.options.user_ca_cert_file = str(self.ui.certificateEdit2.text())
      self.options.user_ca_key_file = str(self.ui.keyEdit2.text())
    else:
      self.options.user_ca_cert_file = None
      self.options.user_ca_key_file = None

    # -- sslcert tab / other options
    self.options.no_self_signed = not self.ui.useSelfSignedCertificatesCheckBox.isChecked()
    self.options.no_user_cert_signed = not self.ui.useUserCertificatesToSign.isChecked()

    # -- left panel
    self.options.nclients = self.ui.numerOfRoundsSpinBox.value()
    self.options.self_test = self.ui.selfTestComboBox.currentIndex()
    self.options.listen_on = (
      str(self.ui.hostnameLineEdit.text()),
      port
    )

    try:
      self.bridge.init_controller(self.options)
      self.bridge.start()
    except Exception as ex:
      self.reportError('Failed to start: %s' % ex, traceback.format_exc())

      self.ui.startButton.setText('Start')
      self.ui.startButton.setIcon(QIcon.fromTheme('media-playback-start'))

  def closeEvent(self, event):
    if self.bridge and self.bridge.isRunning():
      if QMessageBox.question(self, 'SSLCAudit', 'An audit is currently running. Do you really want to exit?', QMessageBox.Yes, QMessageBox.No) == QMessageBox.Yes:
        self.bridge.stop()
        event.accept()
      else:
        event.ignore()
    else:
      event.accept()

  def browseButtonClicked(self, name):
    textbox = getattr(self.ui, str(name).replace('Browse', 'Edit'))
    initialDir = self.settings.value(INITIAL_DIR_SETTING_NAME, QDir.homePath()).toString()
    filename = QFileDialog.getOpenFileName(
      self,
      getattr(self.ui, str(name)).statusTip(),
      initialDir
    )
    
    if filename:
      newInitialDir = dirname(str(filename))
      self.settings.setValue(INITIAL_DIR_SETTING_NAME, newInitialDir)
      textbox.setText(filename)
