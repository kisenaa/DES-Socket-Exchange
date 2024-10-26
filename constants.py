from enum import IntEnum

class DesKeyType(IntEnum):
    STATIC_KEY = 1
    DYNAMIC_KEY = 2

STATIC_KEY = DesKeyType.STATIC_KEY
DYNAMIC_KEY = DesKeyType.DYNAMIC_KEY

class MessageType(IntEnum):
    Key_Exchange = 1
    Encrypted_Text = 2

Key_Exchange = MessageType.Key_Exchange
Encrypted_Text = MessageType.Encrypted_Text