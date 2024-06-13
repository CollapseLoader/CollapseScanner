from PyQt6.QtGui import *
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt

class Label:
    def __init__(self, text: str, size: int = 12, font: str = 'Consolas'):
        self.label = QLabel(text)
        self.label.setFont(QFont(font, size))
        
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.label

class Button:
    def __init__(self, text: str, function, size: tuple = None, text_size: int = 9):
        self.button = QPushButton(text)
        self.button.setStyleSheet('QPushButton { padding: 5px; }')
        self.button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.button.clicked.connect(function)

        if size != None:
            self.button.setMinimumSize(size[0], size[1])
        else:
            self.button.setMinimumSize(self.button.sizeHint())

        self.button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button.setFont(QFont('Arial', text_size))


    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.button
    