import tempfile
import pytest
# this is require near the top to do setup of the test suite
# from counterpartylib.test import conftest

from counterpartylib.test import util_test
from counterpartylib.lib import util
from counterpartylib.test.util_test import CURR_DIR
from counterpartylib.test.fixtures.params import DP
from micropayment_core.util import hash160hex
from micropayment_core.keys import pubkey_from_wif
from micropayment_core.util import generate_wif


FIXTURE_SQL_FILE = CURR_DIR + '/fixtures/scenarios/unittest_fixture.sql'
FIXTURE_DB = tempfile.gettempdir() + '/fixtures.unittest_fixture.db'


ALICE_WIF = DP["addresses"][0][2]
ALICE_PUBKEY = pubkey_from_wif(ALICE_WIF)
BOB_WIF = "cPs6DTGm4fLYdXB1888Q92VWwty6AJmzkKuvpgcZw96vE8npxFKK"
BOB_PUBKEY = pubkey_from_wif(BOB_WIF)
SPEND_SECRET = (
    "7090c90a55489d3272c6edf46b1d391c971aeea5a8cc6755e6174608752c55a9"
)
SPEND_SECRET_HASH = hash160hex(SPEND_SECRET)
EXPIRE_TIME = 42


@pytest.mark.usefixtures("server_db")
@pytest.mark.usefixtures("api_server")
def test_channel_already_used(server_db):

    quantity = 42
    result = util.api(
        method="mpc_make_deposit",
        params={
            "asset": "XCP",
            "payer_pubkey": ALICE_PUBKEY,
            "payee_pubkey": BOB_PUBKEY,
            "spend_secret_hash": SPEND_SECRET_HASH,
            "expire_time": EXPIRE_TIME,  # in blocks
            "quantity": quantity  # in satoshis
        }
    )

    # insert send, this automatically also creates a block
    util_test.insert_raw_transaction(result["topublish"], server_db)

    try:
        util.api(
            method="mpc_make_deposit",
            params={
                "asset": "XCP",
                "payer_pubkey": ALICE_PUBKEY,
                "payee_pubkey": BOB_PUBKEY,
                "spend_secret_hash": SPEND_SECRET_HASH,
                "expire_time": EXPIRE_TIME,  # in blocks
                "quantity": quantity  # in satoshis
            }
        )
        assert False
    except util.RPCError as e:
        assert "ChannelAlreadyUsed" in str(e)


@pytest.mark.usefixtures("server_db")
@pytest.mark.usefixtures("api_server")
def test_insufficient_funds(server_db):
    alice_pubkey = pubkey_from_wif(generate_wif(netcode="XTN"))
    bob_pubkey = pubkey_from_wif(generate_wif(netcode="XTN"))

    try:
        quantity = 42
        util.api(
            method="mpc_make_deposit",
            params={
                "asset": "XCP",
                "payer_pubkey": alice_pubkey,
                "payee_pubkey": bob_pubkey,
                "spend_secret_hash": SPEND_SECRET_HASH,
                "expire_time": EXPIRE_TIME,  # in blocks
                "quantity": quantity  # in satoshis
            }
        )
        assert False
    except util.RPCError as e:
        assert "InsufficientFunds" in str(e)
