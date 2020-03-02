
from pygost import gost34112012256
from pygost.gost3410 import *
from pygost.utils import hexenc, hexdec

from os import urandom
from time import time
from hashlib import sha256
from configparser import ConfigParser
from contextlib import contextmanager

import ods


class Connection(object):
    """docstring for Connection"""

    def __init__(self, login, passwd, progName, host, dbName, configName):
        super(Connection, self).__init__()
        self.login = login
        self.passwd = passwd
        self.progName = progName
        self.host = host
        self.dbName = dbName
        self.configName = configName

        self.odsInt = ods.OdsInterface.self()
        self.dbMgr = self.odsInt.dbManager()
        cnMgr = self.odsInt.connectionManager()

        ret = cnMgr.connect(login,
                             passwd,
                             progName,
                             host,
                             dbName)

        if not ret:
            raise Exception(ods.LogManager().getLastError().fullTextDesc())

        self.ioMgr = self.odsInt.iobjectManager()

    def __del__(self):
        if self.odsInt != 0:
            self.odsInt.connectionManager().disconnect()

    def logError(self):
        print(ods.LogManager().getLastError().fullTextDesc())

    def checkConnection(self):
        if not self.odsInt.connectionManager().isConnected():
            raise Exception("No connection. " + self.logError())

    def createComponent(self, comp):
        self.checkConnection()

        if not comp.createComponent(self.ioMgr):
            self.logError()
            return None

        return comp

    def updateComponent(self, comp):
        self.checkConnection()

        if comp.ref is None:
            print("No IObject")
            return False

        if not comp.updateComponent(self.ioMgr):
            self.logError()
            return False

        return True

    def deleteComponent(self, comp):
        self.checkConnection()

        if comp.ref is None:
            print("No IObject")
            return False

        if not self.ioMgr.deleteIObject(comp.ref, ods.IObject.DeleteRule.Strict):
            self.logError()
            return False

        comp.ref = None

        return True

    def getComponents(self, compClass, where=""):
        self.checkConnection()

        return compClass.getComponents(self.ioMgr, where)

    def getComponent(self, compClass, where=""):
        self.checkConnection()

        return compClass.getComponent(self.ioMgr, where)

    def getSettings(self):
        config = ConfigParser()
        config.read(self.configName)
        return config

    def setSettings(self, config):
        with open(self.configName, "w") as configfile:
            config.write(configfile)


class GOST(object):
    """docstring for GOST"""

    def __init__(self):
        super(GOST, self).__init__()
        self.curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"])

    def checkSignature(self, data, signature, pubKey):
        dgst = gost34112012256.new(data.encode()).digest()
        return verify(self.curve, pub_unmarshal(hexdec(pubKey), mode=2012), dgst, hexdec(signature), mode=2012)

    def createSignature(self, data, prvKey):
        dgst = gost34112012256.new(data.encode()).digest()
        return hexenc(sign(self.curve, prv_unmarshal(hexdec(prvKey)), dgst, mode=2012))

    def genKeys(self):
        prv_raw = urandom(32)  # temp TODO
        newPrivateKey = prv_unmarshal(prv_raw)
        newPublicKey = public_key(self.curve, newPrivateKey)

        return hexenc(prv_raw), hexenc(pub_marshal(newPublicKey, mode=2012))

    @staticmethod
    def genID():
        return hexenc(sha256(str(time() + time() * time()).encode()).digest())


@contextmanager
def registerThread(connection):
    if connection.odsInt.connectionManager().registerThread():
        yield True
        connection.odsInt.connectionManager().unregisterThread()
    else:
        print("Unable register thread")
        yield False


if __name__ == "__main__":
    gost = GOST()

    # print(gost.checkSignature("cbe5ec2ee50d016f437598841951ded9627ec2cfff66aaa77ebd11b7f4a6b3b1", "0a2b400ed2fdd391e0aef96f8bbe5ccf3f4071d1da4826fd39f0f74cfdc71062d3476c687eb30cd1ed1672be7c17162e2d5d5e2f1bea208a0b4ed2ba9339e9f75851d43a80500cfdd09e68adbc9036a9dcdecb83a21e36f7572a186a3f0c015061daa0022607e6f75a03a91f67ad03f126f4e82a541b390b6670f569a2cac024", "d4265fb657c474e560f4df087a0e54e27aa1e750e02dc8afe1050de4e666f8e4327c1ec3650aa7da8125f4b1ff14c5dacfeaeb5916071023441ac5966b7a22083fff9c71505907505be57814983af9043db5a96d268ef37ee380b6db2434c33fcd4d76fa949bc7041471f8939492832de381eb797bd867a16bb776eb549e7e38"))

    # curve = GOST3410Curve(*CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"])
    # prv_raw = urandom(32)
    # prv = prv_unmarshal(prv_raw)
    # pub = public_key(curve, prv)
    # print("Public key is:" + hexenc(pub_marshal(pub)))
    # data_for_signing = gost.genID().encode()
    # dgst = gost34112012256.new(data_for_signing).digest()
    # signature = sign(curve, prv, dgst, mode=2012)
    # print(verify(curve, pub_unmarshal(hexdec(hexenc(pub_marshal(pub, mode=2012))), mode=2012), dgst, signature, mode=2012))
