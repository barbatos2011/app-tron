#!/usr/bin/env python3
import sys
import base58
import logging
import struct
from contextlib import contextmanager
from enum import IntEnum
from pathlib import Path
from typing import Tuple, Generator, Union, Dict, cast
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from bip_utils.addr import TrxAddrEncoder
from eth_keys import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.navigator import NavInsID, NavIns
from ragger.bip import pack_derivation_path
from conftest import MNEMONIC
from utils import packed_bip32_path_from_string, write_varint
from speculos.client import ApduException

'''
Tron Protobuf
'''
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/proto")
from core import Tron_pb2 as tron
from google.protobuf.any_pb2 import Any
from google.protobuf.internal.decoder import _DecodeVarint32

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

MAX_APDU_LEN: int = 255

CLA: int = 0xE0

PUBLIC_KEY_LENGTH = 65
BASE58_ADDRESS_SIZE = 34
GET_ADDRESS_RESP_LEN = 101
GET_VERSION_RESP_LEN = 4


class P1(IntEnum):
    # GET_PUBLIC_KEY P1 values
    CONFIRM = 0x01
    NON_CONFIRM = 0x00
    # SIGN P1 values
    SIGN = 0x10
    FIRST = 0x00
    MORE = 0x80
    LAST = 0x90
    TRC10_NAME = 0xA0


class P2(IntEnum):
    # GET_PUBLIC_KEY P2 values
    NO_CHAINCODE = 0x00
    CHAINCODE = 0x01


class InsType(IntEnum):
    GET_PUBLIC_KEY = 0x02
    SIGN = 0x04
    SIGN_TXN_HASH = 0x05  #  Unsafe
    GET_APP_CONFIGURATION = 0x06  # Version and settings
    SIGN_PERSONAL_MESSAGE = 0x08
    GET_ECDH_SECRET = 0x0A
    EXTERNAL_PLUGIN_SETUP     = 0x12
    CLEAR_SIGN =           0xC4

class Errors(IntEnum):
    OK = 0x9000
    # NOTE: The follow codes have alt status messages defined.
    # "Incorrect length"
    INCORRECT_LENGTH = 0x6700
    # "Missing critical parameter"
    MISSING_CRITICAL_PARAMETER = 0x6800
    # "Security not satisfied (dongle locked or have invalid access rights)"
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    # "Condition of use not satisfied (denied by the user?)";
    CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
    # "Invalid data received"
    INCORRECT_DATA = 0x6a80
    # "Invalid parameter received"
    INCORRECT_P2 = 0x6b00
    # TRON defined:
    INCORRECT_BIP32_PATH = 0x6a8a
    MISSING_SETTING_DATA_ALLOWED = 0x6a8b
    MISSING_SETTING_SIGN_BY_HASH = 0x6a8c
    MISSING_SETTING_CUSTOM_CONTRACT = 0x6a8d
    # Official:
    PIN_REMAINING_ATTEMPTS = 0x63c0
    COMMAND_INCOMPATIBLE_FILE_STRUCTURE = 0x6981
    NOT_ENOUGH_MEMORY_SPACE = 0x6a84
    REFERENCED_DATA_NOT_FOUND = 0x6a88
    FILE_ALREADY_EXISTS = 0x6a89
    INS_NOT_SUPPORTED = 0x6d00
    CLA_NOT_SUPPORTED = 0x6e00
    TECHNICAL_PROBLEM = 0x6f00
    MEMORY_PROBLEM = 0x9240
    NO_EF_SELECTED = 0x9400
    INVALID_OFFSET = 0x9402
    FILE_NOT_FOUND = 0x9404
    INCONSISTENT_FILE = 0x9408
    ALGORITHM_NOT_SUPPORTED = 0x9484
    INVALID_KCV = 0x9485
    CODE_NOT_INITIALIZED = 0x9802
    ACCESS_CONDITION_NOT_FULFILLED = 0x9804
    CONTRADICTION_SECRET_CODE_STATUS = 0x9808
    CONTRADICTION_INVALIDATION = 0x9810
    CODE_BLOCKED = 0x9840
    MAX_VALUE_REACHED = 0x9850
    GP_AUTH_FAILED = 0x6300
    LICENSING = 0x6f42
    HALTED = 0x6faa


class APDUOffsets(IntEnum):
    CLA = 0
    INS = 1
    P1 = 2
    P2 = 3
    LC = 4
    CDATA = 5


class TronClient:
    # default APDU TCP server
    HOST, PORT = ('127.0.0.1', 9999)
    CLA = 0xE0

    def __init__(self, client: BackendInterface, firmware, navigator):
        if not isinstance(client, BackendInterface):
            raise TypeError('client must be an instance of BackendInterface')
        self._client = client
        self._firmware = firmware
        self._navigator = navigator
        self.accounts = [None, None]
        self.hardware = True

        # Init account with default address to compare with ledger
        for i in range(2):
            HD = self.getPrivateKey(MNEMONIC, i, 0, 0)
            key = keys.PrivateKey(HD)
            diffieHellman = ec.derive_private_key(int.from_bytes(HD, "big"),
                                                  ec.SECP256K1(),
                                                  default_backend())
            self.accounts[i] = {
                "path": ("m/44'/195'/{}'/0/0".format(i)),
                "privateKeyHex":
                HD.hex(),
                "key":
                key,
                "addressHex":
                "41" + key.public_key.to_checksum_address()[2:].upper(),
                "publicKey":
                key.public_key.to_hex().upper(),
                "dh":
                diffieHellman,
            }

    def address_hex(self, address):
        return base58.b58decode_check(address).hex().upper()

    def getPrivateKey(self, seed, account, change, address_index):
        seed_bytes = Bip39SeedGenerator(seed).Generate()
        bip32_ctx = Bip32Slip10Secp256k1.FromSeedAndPath(
            seed_bytes, f"m/44'/195'/{account}'/{change}/{address_index}")
        return bytes(bip32_ctx.PrivateKey().Raw())

    def getAccount(self, number):
        return self.accounts[number]

    def packContract(self,
                     contractType,
                     newContract,
                     data=None,
                     permission_id=None):
        tx = tron.Transaction()
        tx.raw_data.timestamp = 1575712492061
        tx.raw_data.expiration = 1575712551000
        tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
        tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")
        if data:
            tx.raw_data.custom_data = data

        c = tx.raw_data.contract.add()
        c.type = contractType
        param = Any()
        param.Pack(newContract, deterministic=True)

        c.parameter.CopyFrom(param)

        if permission_id:
            c.Permission_id = permission_id
        return tx.raw_data.SerializeToString()

    def get_next_length(self, tx):
        field, pos = _DecodeVarint32(tx, 0)
        size, newpos = _DecodeVarint32(tx, pos)
        if (field & 0x07 == 0):
            return newpos
        return size + newpos

    def navigate(self,
                 snappath: Path = None,
                 text: str = "",
                 warning_approve: bool = False):
        if self._firmware.is_nano:
            self._navigator.navigate_until_text_and_compare(
                NavIns(NavInsID.RIGHT_CLICK), [NavIns(NavInsID.BOTH_CLICK)],
                text,
                ROOT_SCREENSHOT_PATH,
                snappath,
                screen_change_before_first_instruction=True)
        else:
            path_name = ""
            screen_change_before_first_instruction = True
            if warning_approve:
                # Use custom touch coordinates to account for warning approve
                # button position.
                instructions = [
                    NavIns(
                        NavInsID.TOUCH,
                        (200, 445 if self._firmware.device.startswith("flex")
                         else 545)),
                ]
                self._navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                                     str(snappath) + "/part1",
                                                     instructions)
                path_name = "/part2"
                screen_change_before_first_instruction = False
            self._navigator.navigate_until_text_and_compare(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                text,
                ROOT_SCREENSHOT_PATH,
                str(snappath) + path_name,
                screen_change_before_first_instruction=
                screen_change_before_first_instruction)

    def getVersion(self):
        return self._client.exchange(CLA, InsType.GET_APP_CONFIGURATION, 0x00,
                                     0x00)

    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response

    def compute_address_from_public_key(self, public_key: bytes) -> str:
        return TrxAddrEncoder.EncodeKey(public_key)

    def parse_get_public_key_response(
            self, response: bytes,
            request_chaincode: bool) -> (bytes, str, bytes):
        # response = public_key_len (1) ||
        #            public_key (var) ||
        #            address_len (1) ||
        #            address (var) ||
        #            chain_code (32)
        offset: int = 0

        public_key_len: int = response[offset]
        offset += 1
        public_key: bytes = response[offset:offset + public_key_len]
        offset += public_key_len
        address_len: int = response[offset]
        offset += 1
        address: str = response[offset:offset + address_len].decode("ascii")
        offset += address_len
        if request_chaincode:
            chaincode: bytes = response[offset:offset + 32]
            offset += 32
        else:
            chaincode = None

        assert len(response) == offset
        assert len(public_key) == 65
        assert self.compute_address_from_public_key(public_key) == address

        return public_key, address, chaincode

    def send_get_public_key_non_confirm(self, derivation_path: str,
                                        request_chaincode: bool) -> RAPDU:
        p1 = P1.NON_CONFIRM
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        payload = pack_derivation_path(derivation_path)
        return self._client.exchange(CLA, InsType.GET_PUBLIC_KEY, p1, p2,
                                     payload)

    @contextmanager
    def send_async_get_public_key_confirm(
            self, derivation_path: str,
            request_chaincode: bool) -> Generator[None, None, None]:
        p1 = P1.CONFIRM
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        payload = pack_derivation_path(derivation_path)
        with self._client.exchange_async(CLA, InsType.GET_PUBLIC_KEY, p1, p2,
                                         payload):
            yield

    def unpackGetVersionResponse(self,
                                 response: bytes) -> Tuple[int, int, int]:
        assert (len(response) == GET_VERSION_RESP_LEN)
        major, minor, patch = struct.unpack("BBB", response[1:])
        return major, minor, patch

    def sign(self,
             path: str,
             tx,
             signatures=[],
             snappath: Path = None,
             text: str = "",
             navigate: bool = True,
             warning_approve: bool = False):
        messages = []

        # Split transaction in multiples APDU
        data = pack_derivation_path(path)
        while len(tx) > 0:
            # get next message field
            newpos = self.get_next_length(tx)
            assert (newpos < MAX_APDU_LEN)
            if (len(data) + newpos) < MAX_APDU_LEN:
                # append to data
                data += tx[:newpos]
                tx = tx[newpos:]
            else:
                # add chunk
                messages.append(data)
                data = bytearray()
                continue
        # append last
        messages.append(data)
        token_pos = len(messages)

        for signature in signatures:
            messages.append(bytearray.fromhex(signature))

        # Send all the messages expect the last
        for i, data in enumerate(messages[:-1]):
            if i == 0:
                p1 = P1.FIRST
            else:
                if i < token_pos:
                    p1 = P1.MORE
                else:
                    p1 = P1.TRC10_NAME | P1.FIRST | i - token_pos

            self._client.exchange(CLA, InsType.SIGN, p1, 0x00, data)

        # Send last message
        if len(messages) == 1:
            p1 = P1.SIGN
        elif signatures:
            p1 = P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE | len(
                signatures) - 1
        else:
            p1 = P1.LAST

        if navigate:
            with self._client.exchange_async(CLA, InsType.SIGN, p1, 0x00,
                                             messages[-1]):
                self.navigate(snappath, text, warning_approve)
            return self._client.last_async_response
        else:
            return self._client.exchange(CLA, InsType.SIGN, p1, 0x00,
                                         messages[-1])

    def send_apdu(self, apdu: bytes) -> bytes:
        try:
            self._client.exchange(cla=apdu[0], ins=apdu[1],
                                        p1=apdu[2], p2=apdu[3],
                                        data=apdu[5:])
        except ApduException as error:
            raise DeviceException(error_code=error.sw, ins=InsType.INS_SIGN_TX)

    def clear_sign(self,
             path: str,
             tx,
             signatures=[],
             snappath: Path = None,
             text: str = "",
             navigate: bool = True):
        messages = []

        # Split transaction in multiples APDU
        data = pack_derivation_path(path)
        while len(tx) > 0:
            # get next message field
            newpos = self.get_next_length(tx)
            assert (newpos < MAX_APDU_LEN)
            if (len(data) + newpos) < MAX_APDU_LEN:
                # append to data
                data += tx[:newpos]
                tx = tx[newpos:]
            else:
                # add chunk
                messages.append(data)
                data = bytearray()
                continue
        # append last
        messages.append(data)
        token_pos = len(messages)

        for signature in signatures:
            messages.append(bytearray.fromhex(signature))

        # Send all the messages expect the last
        for i, data in enumerate(messages[:-1]):
            if i == 0:
                p1 = P1.FIRST
            else:
                if i < token_pos:
                    p1 = P1.MORE
                else:
                    p1 = P1.TRC10_NAME | P1.FIRST | i - token_pos

            self._client.exchange(CLA, InsType.CLEAR_SIGN, p1, 0x00, data)

        # Send last message
        if len(messages) == 1:
            p1 = P1.SIGN
        elif signatures:
            p1 = P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE | len(
                signatures) - 1
        else:
            p1 = P1.LAST

        if navigate:
            with self._client.exchange_async(CLA, InsType.CLEAR_SIGN, p1, 0x00,
                                             messages[-1]):
                self.navigate(snappath, text)
            return self._client.last_async_response
        else:
            return self._client.exchange(CLA, InsType.CLEAR_SIGN, p1, 0x00,
                                         messages[-1])

class DeviceException(Exception):  # pylint: disable=too-few-public-methods
    exc: Dict[int, Any] = {
    }

    def __new__(cls,
                error_code: int,
                ins: Union[int, IntEnum, None] = None,
                message: str = ""
                ) -> Any:
        error_message: str = (f"Error in {ins!r} command"
                              if ins else "Error in command")

        if error_code in DeviceException.exc:
            return DeviceException.exc[error_code](hex(error_code),
                                                   error_message,
                                                   message)

        return UnknownDeviceError(hex(error_code), error_message, message)

class UnknownDeviceError(Exception):
    pass


MAX_APDU_LEN: int = 255


def chunked(size, source):
    for i in range(0, len(source), size):
        yield source[i:i+size]

class TronCommandBuilder:
    """APDU command builder for the Boilerplate application.

    Parameters
    ----------
    debug: bool
        Whether you want to see logging or not.

    Attributes
    ----------
    debug: bool
        Whether you want to see logging or not.

    """
    CLA: int = 0xE0

    def __init__(self, debug: bool = False):
        """Init constructor."""
        self.debug = debug

    def _serialize(self,
                   cla: int,
                   ins: InsType,
                   p1: int,
                   p2: int,
                   cdata: bytes = bytes()) -> bytes:
        """Serialize the whole APDU command (header + data).

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter 1: P1 (1 byte).
        p2 : int
            Instruction parameter 2: P2 (1 byte).
        cdata : bytes
            Bytes of command data.

        Returns
        -------
        bytes
            Bytes of a complete APDU command.

        """

        header = bytearray()
        header.append(cla)
        header.append(ins)
        header.append(p1)
        header.append(p2)
        header.append(len(cdata))
        return header + cdata

    def _string_to_bytes(self, string: str) -> bytes:
        data = bytearray()
        for char in string:
            data.append(ord(char))
        return data

    def set_external_plugin(self, plugin_name: str, contract_address: bytes, selector: bytes, sig: bytes) -> bytes:
        data = bytearray()
        data.append(len(plugin_name))
        data += self._string_to_bytes(plugin_name)
        data += contract_address
        data += selector
        data += sig

        return self._serialize(self.CLA, InsType.EXTERNAL_PLUGIN_SETUP,
                               P1.FIRST,
                               0x00,
                               data)

    def personal_sign_tx(self, bip32_path: str, transaction: bytes) -> Tuple[bool,bytes]:
        """Command builder for INS_SIGN_PERSONAL_TX.

        Parameters
        ----------
        bip32_path : str
            String representation of BIP32 path.
        transaction : Transaction
            Representation of the transaction to be signed.

        Yields
        -------
        bytes
            APDU command chunk for INS_SIGN_PERSONAL_TX.

        """

        cdata = packed_bip32_path_from_string(bip32_path)

        tx: bytes = b"".join([
            len(transaction).to_bytes(4, byteorder="big"),
            transaction,
        ])

        cdata = cdata + tx
        last_chunk = len(cdata) // MAX_APDU_LEN

        # The generator allows to send apdu frames because we can't send an apdu > 255
        for i, (chunk) in enumerate(chunked(MAX_APDU_LEN, cdata)):
            if i == 0 and i == last_chunk:
                yield True, self._serialize(cla=self.CLA,
                        ins=InsType.SIGN_PERSONAL_MESSAGE,
                        p1=0x00,
                        p2=0x00,
                        cdata=chunk)
            elif i == 0:
                yield False, self._serialize(cla=self.CLA,
                        ins=InsType.SIGN_PERSONAL_MESSAGE,
                        p1=0x00,
                        p2=0x00,
                        cdata=chunk)
            elif i == last_chunk:
                yield True, self._serialize(cla=self.CLA,
                        ins=InsType.SIGN_PERSONAL_MESSAGE,
                        p1=0x80,
                        p2=0x00,
                        cdata=chunk)
            else:
                yield False, self._serialize(cla=self.CLA,
                        ins=InsType.SIGN_PERSONAL_MESSAGE,
                        p1=0x80,
                        p2=0x00,
                        cdata=chunk)

    def clear_sign_tx(self, bip32_path: str, transaction: bytes) -> Tuple[bool,bytes]:
        cdata = packed_bip32_path_from_string(bip32_path)
        cdata = cdata + transaction
        last_chunk = len(cdata) // MAX_APDU_LEN

        # The generator allows to send apdu frames because we can't send an apdu > 255
        for i, (chunk) in enumerate(chunked(MAX_APDU_LEN, cdata)):
            if i == 0 and i == last_chunk:
                yield True, self._serialize(cla=self.CLA,
                        ins=InsType.CLEAR_SIGN,
                        p1=0x10,
                        p2=0x00,
                        cdata=chunk)
            elif i == 0:
                yield False, self._serialize(cla=self.CLA,
                        ins=InsType.CLEAR_SIGN,
                        p1=0x00,
                        p2=0x00,
                        cdata=chunk)
            elif i == last_chunk:
                yield True, self._serialize(cla=self.CLA,
                        ins=InsType.CLEAR_SIGN,
                        p1=0x90,
                        p2=0x00,
                        cdata=chunk)
            else:
                yield False, self._serialize(cla=self.CLA,
                        ins=InsType.CLEAR_SIGN,
                        p1=0x80,
                        p2=0x00,
                        cdata=chunk)