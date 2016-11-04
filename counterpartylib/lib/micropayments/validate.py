# coding: utf-8
# Copyright (c) 2016 Fabian Barkhau <fabian.barkhau@gmail.com>
# License: MIT (see LICENSE file)


import six
import re
import pycoin
import jsonschema
from pycoin.tx import Tx
from . import exceptions
from micropayment_core import scripts
from micropayment_core import util


_TYPE_HEX = {"type": "string", "pattern": "^[a-f0-9]*$"}

_STATE_SCHEMA = {
    "type": "object",
    "properties": {
        "asset": {"type": "string"},
        "deposit_script": _TYPE_HEX,
        "commits_requested": {"type": "array", "items": _TYPE_HEX},
        "commits_active": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "rawtx": _TYPE_HEX,
                "script": _TYPE_HEX,
            },
            "required": ["rawtx", "script"],
            "additionalProperties": False
        }},
        "commits_revoked": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "script": _TYPE_HEX,
                "revoke_secret": _TYPE_HEX,
            },
            "required": ["script", "revoke_secret"],
            "additionalProperties": False
        }}
    },
    "required": [
        "asset",
        "deposit_script",
        "commits_requested",
        "commits_active",
        "commits_revoked"
    ],
    "additionalProperties": False
}


def is_string(s):
    if not isinstance(s, six.string_types):
        raise exceptions.InvalidString(s)


def is_hex(data):
    is_string(data)
    if not re.match("^[0-9a-f]*$", data):
        raise exceptions.InvalidHexData(data)
    if not (len(data) % 2 == 0):
        raise exceptions.InvalidHexData(data)


def is_asset(dispatcher, asset):
    is_string(asset)
    assets = [e["asset_name"] for e in dispatcher.get("get_assets")()]
    if asset not in assets:
        raise exceptions.AssetDoesNotExist(asset)


def pubkey(pubkey_hex):
    is_hex(pubkey_hex)
    sec = pycoin.serialize.h2b(pubkey_hex)
    if len(sec) != 33:  # compressed only!
        raise exceptions.InvalidPubKey(pubkey_hex)


def hash160(hash_hex):
    is_hex(hash_hex)
    hash_bin = pycoin.serialize.h2b(hash_hex)
    if len(hash_bin) != 20:
        raise exceptions.InvalidHash160(hash_hex)


def is_integer(i):
    if not isinstance(i, six.integer_types):
        raise exceptions.InvalidInteger(i)


def is_list(l):
    if not isinstance(l, list):
        raise exceptions.InvalidList(l)


def is_unsigned(number):
    is_integer(number)
    if number < 0:
        raise exceptions.InvalidUnsigned(number)


def is_sequence(number):
    is_unsigned(number)
    if not (0 <= number <= scripts.MAX_SEQUENCE):
        raise exceptions.InvalidSequence(number)


def is_quantity(number):
    is_integer(number)
    if not (0 < number < 2100000000000000):
        raise exceptions.InvalidQuantity(number)


def deposit_script(deposit_script_hex, expected_payee_pubkey,
                   expected_spend_secret_hash):
    is_hex(deposit_script_hex)
    scripts.validate_deposit_script(deposit_script_hex)

    # deposit spend secret hash matches expected spend secret hash
    found_hash = scripts.get_deposit_spend_secret_hash(deposit_script_hex)
    if found_hash != expected_spend_secret_hash:
        raise exceptions.IncorrectSpendSecretHash(
            found_hash, expected_spend_secret_hash
        )

    # deposit payee pubkey matches expected payee pubkey
    found_pubkey = scripts.get_deposit_payee_pubkey(deposit_script_hex)
    if found_pubkey != expected_payee_pubkey:
        raise exceptions.IncorrectPubKey(found_pubkey, expected_payee_pubkey)


def commit_script(commit_script_hex, deposit_script_hex):
    is_hex(commit_script_hex)
    is_hex(deposit_script_hex)

    scripts.validate_deposit_script(deposit_script_hex)
    scripts.validate_commit_script(commit_script_hex)

    # validate payee pubkey
    deposit_payee_pubkey = scripts.get_deposit_payee_pubkey(deposit_script_hex)
    commit_payee_pubkey = scripts.get_commit_payee_pubkey(commit_script_hex)
    if deposit_payee_pubkey != commit_payee_pubkey:
        raise exceptions.IncorrectPubKey(commit_payee_pubkey,
                                         deposit_payee_pubkey)

    # validate payer pubkey
    deposit_payer_pubkey = scripts.get_deposit_payer_pubkey(deposit_script_hex)
    commit_payer_pubkey = scripts.get_commit_payer_pubkey(commit_script_hex)
    if deposit_payer_pubkey != commit_payer_pubkey:
        raise exceptions.IncorrectPubKey(commit_payer_pubkey,
                                         deposit_payer_pubkey)

    # validate spend secret hash
    deposit_spend_hash = scripts.get_deposit_spend_secret_hash(
        deposit_script_hex
    )
    commit_spend_hash = scripts.get_commit_spend_secret_hash(commit_script_hex)
    if deposit_spend_hash != commit_spend_hash:
        raise exceptions.IncorrectSpendSecretHash(commit_spend_hash,
                                                  deposit_spend_hash)


def is_send_tx(dispatcher, rawtx, expected_asset=None,
               expected_src=None, expected_dest=None,
               validate_signature=False):

    src, dest, btc, fee, data = dispatcher.get("get_tx_info")(tx_hex=rawtx)
    if not data:
        raise ValueError("No data for given transaction!")
    message_type_id, unpacked = dispatcher.get("unpack")(data_hex=data)
    assert(message_type_id == 0)

    if expected_src is not None and expected_src != src:
        raise exceptions.SourceMissmatch(expected_src, src)
    if expected_dest is not None and expected_dest != dest:
        raise exceptions.DestinationMissmatch(expected_dest, dest)
    if expected_asset is not None and expected_asset != unpacked["asset"]:
        raise exceptions.AssetMissmatch(expected_asset, unpacked["asset"])

    if validate_signature:
        def get_rawtx(txid):
            return dispatcher.get("getrawtransaction")(tx_hash=txid)
        tx = util.load_tx(get_rawtx, rawtx)
        if tx.bad_signature_count() != 0:
            raise exceptions.InvalidSignature(rawtx)

    return {
        "src":src, "dest": dest, "btc": btc, "fee": fee, "data": data,
        "message_type_id": message_type_id, "unpacked": unpacked,
    }


def is_commit_rawtx(dispatcher, commit_rawtx, expected_asset,
                    expected_deposit_script_hex, expected_commit_script_hex,
                    netcode, validate_signature=False):

    commit_address = util.script_address(
        expected_commit_script_hex, netcode=netcode
    )
    deposit_address = util.script_address(
        expected_deposit_script_hex, netcode=netcode
    )
    is_send_tx(
        dispatcher, commit_rawtx, expected_asset=expected_asset,
        expected_src=deposit_address, expected_dest=commit_address,
        validate_signature=validate_signature
    )


def is_state(dispatcher, state_data, netcode):
    jsonschema.validate(state_data, _STATE_SCHEMA)

    # commits scripts must be a set
    s_active = [c["script"] for c in state_data["commits_active"]]
    s_revoked = [c["script"] for c in state_data["commits_revoked"]]
    assert(len(s_active + s_revoked) == len(set(s_active + s_revoked)))

    # asset is valid
    is_asset(dispatcher, state_data["asset"])

    # deposit script is valid
    deposit_script = state_data["deposit_script"]
    deposit_address = util.script_address(deposit_script, netcode=netcode)
    deposit_spend_hash = scripts.get_deposit_spend_secret_hash(deposit_script)
    scripts.validate_deposit_script(deposit_script)

    # validate commits revoked
    for revoked in state_data["commits_revoked"]:

        # is commit script
        scripts.validate_commit_script(revoked["script"])

        # spend secret hash matches deposit
        r_spend_hash = scripts.get_commit_spend_secret_hash(revoked["script"])
        assert(r_spend_hash == deposit_spend_hash)

        # revoke secret matches script secret hash
        revoke_hash = scripts.get_commit_revoke_secret_hash(revoked["script"])
        assert(revoke_hash == util.hash160hex(revoked["revoke_secret"]))

    # validate commits active
    for active in state_data["commits_active"]:

        # is commit script
        scripts.validate_commit_script(active["script"])

        # spend secret hash matches deposit
        a_spend_hash = scripts.get_commit_spend_secret_hash(active["script"])
        assert(a_spend_hash == deposit_spend_hash)

        # rawtx and asset match
        is_commit_rawtx(
            dispatcher, active["rawtx"], state_data["asset"],
            deposit_script, active["script"], netcode
        )
