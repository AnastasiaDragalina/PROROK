
from abc import ABC, abstractmethod
from json import loads, dumps, JSONDecodeError
from base64 import b64encode, b64decode
from binascii import Error as berr

from ods import CDate
from ods import IObject

from Managers import GOST


class Component(ABC):
    """docstring for Component"""

    def __init__(self, io=None):
        super().__init__()
        self.ref = io

    @abstractmethod
    def create(self, ioMgr):
        pass

    @abstractmethod
    def update(self, IO):
        pass

    @staticmethod
    @abstractmethod
    def getCursor(ioMgr, where):
        pass

    @staticmethod
    @abstractmethod
    def getTypeResult():
        pass

    @staticmethod
    @abstractmethod
    def addComponent(io, to):
        pass

    def createComponent(self, ioMgr):
        IO = self.create(ioMgr)

        if not ioMgr.saveIObject(IO, IObject.SaveRule.NotRecursiveSave):
            return False

        self.ref = IO

        return True

    def updateComponent(self, ioMgr):
        IO = self.ref

        self.update(IO)

        if not ioMgr.updateIObject(IO, IObject.UpdateRule.NotRecursiveUpdate):
            return False

        return True

    @classmethod
    def getComponents(cls, ioMgr, where, limit=None):

        listObjects = cls.getCursor(ioMgr, where)

        if not listObjects.isValid():
            return None

        begin = listObjects.begin()
        end = listObjects.end()

        result = cls.getTypeResult()
        while begin != end:
            io = begin.value()
            cls.addComponent(io, result)

            if limit is not None:
                return result

            begin += 1

        return result

    @classmethod
    def getComponent(cls, ioMgr, where):
        objects = cls.getComponents(ioMgr, where, 1)

        if len(objects) > 0:
            if cls.getTypeResult() == []:
                return objects[0]
            elif cls.getTypeResult() == {}:
                for k, v in objects.items():
                    return v
            else:
                return None
        else:
            return None


class Object(Component):
    """ docstring for Object """

    def __init__(self, IP, name, objType, key=None, working=True, io=None):
        super().__init__(io)

        if key.__class__.__name__ == "IObject":
            self.key = Key(key.getStringAttr("Key"),
                key.getLink("Block"),
                self,
                key.getStringAttr("Hash"),
                key.getStringAttr("HashOld"),
                key.getBoolAttr("Recived"), key)
        else:
            self.key = key

        self.IP = IP
        self.name = name
        self.objType = objType
        self.working = working

        self.connection = None

    def create(self, ioMgr):
        objIO = ioMgr.createIObject("ProROK.Objects")

        if self.key is None:
            objIO.setNullAttr("Key")
        else:
            objIO.setIObjectAttr("Key", self.key.ref)

        objIO.setStringAttr("IP", self.IP)
        objIO.setStringAttr("Name", self.name)
        objIO.setStringAttr("Type", self.objType)
        objIO.setBoolAttr("Working", self.working)

        return objIO

    def update(self, IO):
        IO.setBoolAttr("Working", self.working)

        if self.key is None:
            IO.setNullAttr("Key")
        else:
            IO.setIObjectAttr("Key", self.key.ref)

    def getCursor(ioMgr, where):
        return ioMgr.getIObjectCursor("ProROK.Objects", where)

    def getTypeResult():
        return {}

    def addComponent(io, to):
        key = io.getLink("Key")
        if key == "" or key == 0:
            key = None

        to[io.getStringAttr("Name")] = Object(io.getStringAttr("IP"),
            io.getStringAttr("Name"),
            io.getIntAttr("Type"),
            key,
            io.getBoolAttr("Working"), io)

    def alert(self, msg, msgType, obj=None):
        if obj is None:
            obj = self

        if self.connection is None:
            print("No connection object")
            return

        alert = Alert(msg, obj, msgType)

        self.connection.createComponent(alert)

        print(msg)

        if msgType != 0:
            obj.turn(on=False)

    def createMsg(self, data):
        if self.key is None or self.key.privateKey is None or self.key.privateKey == "":
            raise Exception("No private key")

        gost = GOST()
        datas = dumps(data, sort_keys=True)

        msg = "{" + "\"dt\":{}, \"vy\":\"{}\"".format(datas, gost.createSignature(datas, self.key.privateKey)) + "}"

        return b64encode(msg.encode()).decode()

    def checkMsg(self, msg, pubKey=None):
        if pubKey is None:
            if self.key is None or self.key.publicKey is None or self.key.publicKey == "":
                raise Exception("No public key")
            pubKey = self.key.publicKey

        gost = GOST()
        data = None
        check = None
        try:

            msg = b64decode(msg.encode()).decode()

            data = loads(msg)
            hh = dumps(data["dt"], sort_keys=True)

            check = gost.checkSignature(hh, data["vy"], pubKey)

        except JSONDecodeError:
            return None
        except KeyError:
            return None
        except berr:
            return None

        if not check:
            return None

        return data["dt"]

    def sendBlocks(self, form):
        resp = None
        blocks = None

        try:
            obj = self.connection.getComponent(Object, "\"IP\"=\'{}\'".format(form["other"]))
            resp = obj.checkMsg(form["data"])
            if resp is None:
                self.alert("Request block: unsuccessful. Warning! Attempt treat system!", 8)
                return "Error"

            blocks = self.connection.getComponents(Block, "\"BlockNumber\">{}".format(resp["number"]))
        except KeyError:
            self.alert("Request block: unsuccessful. Warning! Attempt treat system!", 9)
            return "Error"

        msg = []
        # print(blocks)
        for _, block in blocks.items():
            msg.append((block.blockWithKeys(self.connection), block.blockHash))

        return dumps(msg)

    def objectTurned(self, form):
        resp = None
        try:
            obj = self.connection.getComponent(Object, "\"IP\"='{}'".format(form["other"]))
            resp = obj.checkMsg(form["data"])
            if resp is None:
                self.alert("Object turned: unsuccessful. Warning! Attempt treat system!", 8)
                return "Error"

            obj.working = resp["turn"]
            if not self.connection.updateComponent(obj):
                self.alert("Update error while objectTurned", 2)
                return "Error"

        except KeyError:
            self.alert("Object turned: unsuccessful. Warning! Attempt treat system!", 9)
            return "Error"

        return "OK"


class Block(Component):
    """docstring for Block"""

    def __init__(self, blockNumber, ID, blockHash="", current=False, createTime="", io=None):
        super().__init__(io)
        self.blockNumber = blockNumber
        self.createTime = createTime
        self.ID = ID
        self.current = current
        self.blockHash = blockHash

    def create(self, ioMgr):
        blockIO = ioMgr.createIObject("ProROK.Blocks")

        blockIO.setStringAttr("ID", self.ID)
        blockIO.setBoolAttr("Current", self.current)
        blockIO.setStringAttr("Hash", self.blockHash)

        currDateTime = CDate()
        currDateTime.setCurrentDateTime()
        blockIO.setDateTime("CreateTime", currDateTime)
        self.createTime = blockIO.getStringAttr("CreateTime")

        blockIO.setIntAttr("BlockNumber", self.blockNumber)

        return blockIO

    def update(self, IO):
        IO.setBoolAttr("Current", self.current)
        IO.setStringAttr("Hash", self.blockHash)

    def getCursor(ioMgr, where):
        return ioMgr.getIObjectCursor("ProROK.Blocks", where)

    def getTypeResult():
        return {}

    def addComponent(io, to):
        to[io.getStringAttr("ID")] = Block(io.getIntAttr("BlockNumber"),
                                                io.getStringAttr("ID"),
                                                io.getStringAttr("Hash"),
                                                io.getBoolAttr("Current"),
                                                io.getStringAttr("CreateTime"), io)

    def blockWithKeys(self, connection, string=False):
        share = {}
        share["id"] = self.ID
        share["blockNumber"] = self.blockNumber
        share["createTime"] = self.createTime
        share["keys"] = {}

        keys = connection.getComponents(Key, "\"Block\"={}".format(self.ref.id()))
        for key in keys:
            skey = {}
            skey["hash"] = key.keyHash
            skey["key"] = key.publicKey
            skey["oldHash"] = key.hashOld

            share["keys"][key.obj.IP] = skey

        if string:
            return dumps(share, sort_keys=True)
        else:
            return share


class Alert(Component):
    """docstring for Alert"""

    def __init__(self, msg, obj, msgType, io=None):
        super().__init__(io)
        self.msg = msg + " Объект: " + obj.name

        if obj.__class__.__name__ == "IObject":
            self.obj = Object(obj.getStringAttr("IP"),
                              obj.getStringAttr("Name"),
                              obj.getIntAttr("Type"),
                              obj.getLink("Key"),
                              obj.getBoolAttr("Working"), obj)
        else:
            self.obj = obj

        self.msgType = msgType

    def create(self, ioMgr):
        alertIO = ioMgr.createIObject("ProROK.Alerts")

        alertIO.setIObjectAttr("Object", self.obj.ref)
        alertIO.setStringAttr("Message", self.msg)
        alertIO.setIntAttr("Type", self.msgType)

        return alertIO

    def update(self, IO):
        pass

    def getCursor(ioMgr, where):
        return ioMgr.getIObjectCursor("ProROK.Alerts", where)

    def getTypeResult():
        return []

    def addComponent(io, to):
        to.append(Alert(io.getStringAttr("Message"), io.getLink("Object"), io.getIntAttr("Type"), io))


class Key(Component):
    """docstring for Key"""

    def __init__(self, publicKey, block, obj, keyHash, hashOld, recived=False, io=None):
        super().__init__(io)
        self.publicKey = publicKey

        if block.__class__.__name__ == "IObject":
            self.block = Block(block.getIntAttr("BlockNumber"),
                block.getStringAttr("ID"),
                block.getStringAttr("Hash"),
                block.getBoolAttr("Current"),
                block.getStringAttr("CreateTime"), block)
        else:
            self.block = block

        if obj.__class__.__name__ == "IObject":
            self.obj = Object(obj.getStringAttr("IP"),
                obj.getStringAttr("Name"),
                obj.getIntAttr("Type"),
                self,
                obj.getBoolAttr("Working"), obj)
        else:
            self.obj = obj

        self.keyHash = keyHash
        self.hashOld = hashOld
        self.recived = recived

        self.privateKey = None

    def create(self, ioMgr):
        keyIO = ioMgr.createIObject("ProROK.KeysForBlock")

        if self.block is None:
            keyIO.setNullAttr("Block")
        else:
            keyIO.setIObjectAttr("Block", self.block.ref)

        if self.obj is None:
            keyIO.setNullAttr("Object")
        else:
            keyIO.setIObjectAttr("Object", self.obj.ref)

        keyIO.setStringAttr("Key", self.publicKey)
        keyIO.setStringAttr("Hash", self.keyHash)
        keyIO.setStringAttr("HashOld", self.hashOld)
        keyIO.setBoolAttr("Recived", self.recived)

        return keyIO

    def update(self, IO):
        if self.block is None:
            IO.setNullAttr("Block")
        else:
            IO.setIObjectAttr("Block", self.block.ref)

        if self.obj is None:
            IO.setNullAttr("Object")
        else:
            IO.setIObjectAttr("Object", self.obj.ref)

        IO.setBoolAttr("Recived", self.recived)

    def getCursor(ioMgr, where):
        return ioMgr.getIObjectCursor("ProROK.KeysForBlock", where)

    def getTypeResult():
        return []

    def addComponent(io, to):
        to.append(Key(io.getStringAttr("Key"),
                        io.getLink("Block"),
                        io.getLink("Object"),
                        io.getStringAttr("Hash"),
                        io.getStringAttr("HashOld"),
                        io.getBoolAttr("Recived"), io))


if __name__ == "__main__":
    pass
    # key = Key("52cccc7a4fcf4ae664f5cf412310e2f8b95aaa694109cd39781826be79dd9adfd74a4f650e23712afdc9bb892fe9b9d9d87574936af9bf3c7e7d5ce1d39a25308839112afdc8a261de9050531fe46104c664a37303597acd223e4a4114bec9ed686aeecda5ec3e5dfb14bb5b9f13fa0c24c367017f8c5038afd87b5c5a3413ea",
    #     None, None, "")
    # key.privateKey = "ad428e393089326693bd294be94a8a5f2235d1a705d59d1746148c21c2feb926"
    # obj = Object("IP", "name", 0, key)
    #
    # s = obj.createMsg({"dasd":1243142})
    # print(s)
    # print(obj.checkMsg(s))

