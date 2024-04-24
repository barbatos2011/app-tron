#!/usr/bin/env python

from ledgerblue.comm import getDongle

# Create APDU message.
# CLA 0xE0
# INS 0x12  SET_EXTERNAL_PLUGIN
# P1 0x00   NO USER CONFIRMATION
# P2 0x00   NO CHAIN CODE
apduMessage = "e01200007211506c7567696e426f696c6572706c617465410e1bce983f78f8913002c3f7e52daf78de6da2cba9059cbb3045022100c6ed1e65f3c1a58fff2348c90e5945ae419e946f71142be6a5210333dd1d8ea7022010cdcf93e2895087194961c360ef24847c5c2c4c1956b02ece931fa4aed174ec"
apdu = bytearray.fromhex(apduMessage)

print("-= Tron Ledger =-")
print("Set external plugin")

dongle = getDongle(True)
result = dongle.exchange(apdu)
