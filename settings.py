# Program settings
## General
GATEWAY_ID = "g1"

# The address of the packet forwarder
# Check these match those in global.config
server_address = ('localhost', 1730)
down_address = ('localhost', 1735)

DEBUG = False
ENCRYPTED_PACKETS = True
IROHA_ACTIVATED = True

## LoRa
ACK_RATIO = 8  # How many packets to send before expecting an ACK
# This will be changed if the UAV requests it in a ACK packet.

# Constants
PREDICTED_PACKET_LENGTH = 400

# For sx_1302 hal communication
PROTOCOL_VERSION = 0x02
PUSH_DATA_ID = 0x00
PUSH_ACK_ID = 0x01
PULL_DATA_ID = 0x02
PULL_ACK_ID = 0x04
PULL_RESP_ID = 0x03
TX_ACK = 0x05
