import os
import json
import datetime
from web3 import Web3
from ledger_app_clients.ethereum.utils import get_selector_from_data
from ledger_app_clients.ethereum.keychain import sign_data, Key
from ledger_app_clients.ethereum.command_builder import CommandBuilder
from tron import TronClient
from utils import check_tx_signature

ABIS_FOLDER = "%s/abis" % (os.path.dirname(__file__))


def test1():
    with open("%s/0x000102030405060708090a0b0c0d0e0f10111213.abi.json" % (ABIS_FOLDER)) as file:
        contract = Web3().eth.contract(
            abi=json.load(file),
            # Get address from filename
            address=bytes.fromhex(os.path.basename(file.name).split(".")[0].split("x")[-1])
        )

        data = contract.encodeABI("swapExactETHForTokens", [
            Web3.to_wei(28.5, "ether"),
            [
                bytes.fromhex("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                bytes.fromhex("6B3595068778DD592e39A122f4f5a5cF09C90fE2")
            ],
            bytes.fromhex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            int(datetime.datetime(2023, 12, 25, 0, 0).timestamp())
        ])
        select = get_selector_from_data(data)
        address = contract.address
        print(select.hex())
        print(address.hex())
        print(data)

        cmd_builder = CommandBuilder()
        tmp = cmd_builder.set_external_plugin('PluginBoilerplate', address, select, bytes())
        # skip APDU header & empty sig
        sig = sign_data(Key.CAL, tmp[5:])
        print(sig.hex())

def test2():
    with open("%s/0x0E1BCE983F78F8913002C3F7E52DAF78DE6DA2CB.abi.json" % (ABIS_FOLDER)) as file:
        contract = Web3().eth.contract(
            abi=json.load(file),
            # Get address from filename
            address=bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213")
        )

        data = contract.encodeABI("transfer", [
            bytes.fromhex("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            10000000
        ])
        select = get_selector_from_data(data)
        address = contract.address

        select = bytes.fromhex('a9059cbb')
        address = bytes.fromhex('410e1bce983f78f8913002c3f7e52daf78de6da2cb')
        data = '0xa9059cbb000000000000000000000000573708726db88a32c1b9c828fef508577cfb8483000000000000000000000000000000000000000000000000000000000000000a'
        print(select.hex())
        print(address.hex())
        print(data)

        cmd_builder = CommandBuilder()
        tmp = cmd_builder.set_external_plugin('PluginBoilerplate', address, select, bytes())
        # skip APDU header & empty sig
        sig = sign_data(Key.CAL, tmp[5:])
        print(sig.hex())

test2()