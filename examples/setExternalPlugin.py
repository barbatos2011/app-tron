#!/usr/bin/env python

from ledgerblue.comm import getDongle

# Create APDU message.
# CLA 0xE0
# INS 0x12  SET_EXTERNAL_PLUGIN
# P1 0x00   NO USER CONFIRMATION
# P2 0x00   NO CHAIN CODE
apduMessage = "e01200007211506c7567696e426f696c6572706c617465000102030405060708090a0b0c0d0e0f101112137ff36ab53046022100a106665eaadcd91b2ded9bdb9b797c349962878dc2d3c223b954826fd8e2095702210080062e05f6d58539939f8432bdae220444b74e138ffa2642d8f23d39093680ab"
apdu = bytearray.fromhex(apduMessage)

print("-= Tron Ledger =-")
print("Set external plugin")

dongle = getDongle(True)
result = dongle.exchange(apdu)
