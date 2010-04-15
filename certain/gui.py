#!/usr/bin/python

from PyQt4 import QtCore
from PyQt4 import QtGui
from . import CSRChoice
from . import CertainForm
import sys

class MainWindow(CertainForm.Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()


def main():
    app = QtGui.QApplication(sys.argv)
    window = QtGui.QDialog()
    main = MainWindow()
    main.setupUi(window)
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
