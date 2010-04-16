from PyQt4 import QtCore
from PyQt4 import QtGui
from . import pending_csrs
from . import CertainForm
from . import DEFAULT_CONFIG_FILE
import sys


class MainWindow(QtGui.QMainWindow):

    class ActionList(QtGui.QComboBox):
        def __init__(self, *args, **kwargs):
            super(ActionList, self).__init__(*args, **kwargs)
            if len(args) > 0:
                self.obj = args[0]

        def act(self):
            if self.currentText() == 'Sign':
                self.obj.store()
            elif self.currentText() == 'Delete':
                self.obj.remove()

    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = CertainForm.Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.csrList.setColumnCount(2)
        self.ui.csrList.setHorizontalHeaderLabels(QtCore.QStringList(
            ['Common Name', 'Action']))

        self.connect(self.ui.resetButton, QtCore.SIGNAL("clicked()"),
            self._reset)
        self._reset()

    def _reset(self):
        for i, csr in enumerate(pending_csrs()):
            self.ui.csrList.setRowCount(i + 1)
            self.ui.csrList.setCellWidget(i, 0,
                QtGui.QLabel(csr.get_subject().CN))

            actionlist = ActionList(csr)
            actionlist.insertItems(0, ['Ignore', 'Sign', 'Delete'])
            self.connect(self.ui.applyButton, QtCore.SIGNAL("clicked()"),
                actionlist.act)
            self.ui.csrList.setCellWidget(i, 1, actionlist)
            self.ui.csrList.resizeColumnToContents(0)
            self.ui.csrList.resizeColumnToContents(1)
        #with open(DEFAULT_CONFIG_FILE) as f:
        #    self.ui.config.insertPlainText(f.read())


def main():
    app = QtGui.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())
