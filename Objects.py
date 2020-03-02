
from Components import Object, Key, Block
from Managers import GOST, registerThread

import requests
from threading import Thread, Lock
from json import dumps, loads


def speak(procces_func):
    def wrapper(self, obj, data, where, resp, thread, other, check):
        if other is None:
            data = {"data": self.createMsg(data)}
        else:
            data = {"data": self.createMsg(data), "other": other}

        if thread:
            with registerThread(self.connection):
                response = None
                try:
                    response = requests.post("http://" + obj.IP + "/" + where,
                                        data=data)
                except requests.exceptions.RequestException as e:
                    self.alert("Connection error with object. " + str(e), 5, obj)
                    return
                except requests.exceptions.HTTPError as e:
                    self.alert("Connection error with object. " + str(e), 5, obj)
                    return

                lock = Lock()
                with lock:
                    print(response.text)
                    if response.status_code != 200:
                        self.alert("Status code error: %d" % response.status_code, 6, obj)
                        return

                    if check:
                        resp = obj.checkMsg(response.text)
                    else:
                        resp = response.text

                    return procces_func(self, obj, data, where, resp, thread, other, check)
        else:
            response = None
            try:
                response = requests.post("http://" + obj.IP + "/" + where,
                                         data=data)
            except requests.exceptions.RequestException as e:
                self.alert("Connection error with object. " + str(e), 5, obj)
                return
            except requests.exceptions.HTTPError as e:
                self.alert("Connection error with object. " + str(e), 5, obj)
                return

            print(response.text)
            if response.status_code != 200:
                self.alert("Status code error: %d" % response.status_code, 6, obj)
                return

            if check:
                resp = obj.checkMsg(response.text)
            else:
                resp = response.text

            return procces_func(self, obj, data, where, resp, thread, other, check)

    return wrapper


class Main(Object):
    """docstring for Main"""

    def __init__(self, connection, name):

        obj = connection.getComponent(Object, "\"Name\"='%s'" % name)
        if obj is None:
            raise Exception("No such object " + name)

        super().__init__(obj.IP, name, 0, obj.key, obj.working, obj.ref)

        self.prevBlock = None
        self.lastBlock = None
        self.connection = connection

    def firstInit(self):
        dbMgr = self.connection.dbMgr
        dbMgr.transaction()

        objects = self.connection.getComponents(Object)
        for key, val in objects.items():
            val.key = None
            if not self.connection.updateComponent(val):
                dbMgr.rollback()
                self.alert("Update error while firstInit", 2)
                return {}

        keys = self.connection.getComponents(Key)
        if keys is not None:
            for key in keys:
                key.obj = None
                key.block = None
                if not self.connection.updateComponent(key):
                    dbMgr.rollback()
                    self.alert("Update error while firstInit", 2)
                    return {}

                if not self.connection.deleteComponent(key):
                    dbMgr.rollback()
                    self.alert("Delete error while firstInit", 3)
                    return {}

        blocks = self.connection.getComponents(Block)
        if blocks is not None:
            for bid, val in blocks.items():
                if not self.connection.deleteComponent(val):
                    dbMgr.rollback()
                    self.alert("Delete error while firstInit", 3)
                    return {}

        del blocks
        del keys
        del objects

        gost = GOST()
        keys = gost.genKeys()

        blockID = gost.genID()
        block = Block(1, blockID)

        if self.connection.createComponent(block) is None:
            dbMgr.rollback()
            self.alert("Create error while firstInit", 1)
            return None

        sign = gost.createSignature(keys[1], keys[0])
        key = Key(keys[1], block, self, sign, sign, True)

        if self.connection.createComponent(key) is None:
            dbMgr.rollback()
            self.alert("Create error while firstInit", 1)
            return None

        key.privateKey = keys[0]

        self.lastBlock = block
        self.key = key
        if not self.connection.updateComponent(self):
            dbMgr.rollback()
            self.alert("Update error while firstInit", 2)
            return {}

        objects = self.connection.getComponents(Object, "\"Type\"=1 OR \"Type\"=2")

        result = {}

        for name, obj in objects.items():
            keys = gost.genKeys()

            sign = gost.createSignature(keys[1], keys[0])
            key = Key(keys[1], block, obj, sign, sign)

            if self.connection.createComponent(key) is None:
                dbMgr.rollback()
                self.alert("Create error while firstInit", 1)
                return {}

            obj.working = True
            obj.key = key
            if not self.connection.updateComponent(obj):
                self.alert("Update error while firstInit", 2)
                return {}

            result[name] = keys

        if len(result) == 0:
            dbMgr.rollback()
            self.alert("No objects while firstInit", 4)
            return {}

        dbMgr.commit()

        config = self.connection.getSettings()
        config["params"]["nprvk"] = self.key.privateKey
        config["params"]["prvk"] = self.key.privateKey
        # config["params"]["init"] = '0'
        self.connection.setSettings(config)

        result[self.name] = (self.key.keyHash, self.key.publicKey)

        return result

    def requestNewKeys(self):
        if not self.lastBlock:
            print("No last block")
            return False

        dbMgr = self.connection.dbMgr
        dbMgr.transaction()

        gost = GOST()
        keys = gost.genKeys()

        blockID = gost.genID()
        block = Block(self.lastBlock.blockNumber + 1, blockID)

        if self.connection.createComponent(block) is None:
            dbMgr.rollback()
            self.alert("Create error while requestNewKeys", 1)
            return False

        key = Key(keys[1], block, self, gost.createSignature(keys[1], keys[0]), gost.createSignature(keys[1], self.key.privateKey))
        key.privateKey = keys[0]
        key.recived = True

        if self.connection.createComponent(key) is None:
            dbMgr.rollback()
            self.alert("Create error while requestNewKeys", 1)
            return False

        self.prevBlock = self.lastBlock
        self.lastBlock = block

        objects = self.connection.getComponents(Object, "(\"Type\"=1 OR \"Type\"=2) AND \"Working\"=true")

        # if len(objects) == 0:
        #     dbMgr.rollback()
        #     self.alert("No objects while requestNewKeys", 4)
        #     return False

        threads = []

        for name, obj in objects.items():
            thr = Thread(target=self.__shareRequestForSlavers, args=(obj, {}, "requestNewKey", None, True, None, True))
            threads.append(thr)
            thr.start()

        for thr in threads:
            thr.join()

        block.blockHash = gost.createSignature(block.blockWithKeys(self.connection, True), self.key.privateKey)
        if not self.connection.updateComponent(block):
            self.alert("Update error while requestNewKeys", 2)
            dbMgr.rollback()
            return False

        dbMgr.commit()

        config = self.connection.getSettings()
        config["params"]["nprvk"] = keys[0]
        self.connection.setSettings(config)

        return True

    def shareBlock(self):
        if not self.lastBlock:
            raise Exception("No last block")

        dbMgr = self.connection.dbMgr
        dbMgr.transaction()

        block = self.lastBlock

        objects = self.connection.getComponents(Object, "(\"Type\"=1 OR \"Type\"=2) AND \"Working\"=true")
        # if len(objects) == 0:
        #     dbMgr.rollback()
        #     self.alert("No objects while shareBlock", 4)
        #     return False

        threads = []
        for name, obj in objects.items():
            thr = Thread(target=self.__shareBlockForSlavers, args=(obj, {"block": block.blockWithKeys(self.connection),
                                                                         "hash": block.blockHash}, "updateBlock", None, True, None, True))
            threads.append(thr)
            thr.start()

        for thr in threads:
            thr.join()

        if self.prevBlock is not None:
            self.prevBlock.current = False
            if not self.connection.updateComponent(self.prevBlock):
                dbMgr.rollback()
                self.alert("Update error while shareBlock", 2)
                return False

        block.current = True
        if not self.connection.updateComponent(block):
            dbMgr.rollback()
            self.alert("Update error while shareBlock", 2)
            return False

        dbMgr.commit()

        config = self.connection.getSettings()
        config["params"]["prvk"] = config["params"]["nprvk"]
        config["params"]["nprvk"] = ''
        self.connection.setSettings(config)

        self.key.privateKey = config["params"]["prvk"]

        return True

    @speak
    def __shareBlockForSlavers(self, obj, data, where, resp, thread, other, check):
        if resp is None:
            self.alert("Share block: unsuccessful. Warning! Attempt treat system! Probably MITM", 8, obj)
            return
        elif resp == "Error":
            self.alert("Share block: unsuccessful. Something went wrong.", 7, obj)
            return

        self.alert("Share block: successful.", 0, obj)

        key = self.connection.getComponent(Key, "\"Object\"={} AND \"Block\"={}".format(obj.ref.id(), self.lastBlock.ref.id()))
        key.recived = True
        obj.key = key

        if not self.connection.updateComponent(key) or not self.connection.updateComponent(obj):
            self.alert("Update error while shareBlock", 2)
            return

    @speak
    def __shareRequestForSlavers(self, obj, data, where, resp, thread, other, check):
        if resp is None:
            self.alert("Generation keys: unsuccessful. Warning! Attempt treat system! Probably MITM", 8, obj)
            return
        elif resp == "Error":
            self.alert("Generation keys: unsuccessful. Something went wrong.", 7, obj)
            return

        try:
            gost = GOST()
            if gost.checkSignature(resp["NK"], resp["HH"], resp["NK"]):
                key = Key(resp["NK"], self.lastBlock, obj, resp["HH"], resp["OH"])

                self.connection.createComponent(key)

                self.alert("Generation keys: successful.", 0, obj)
            else:
                self.alert("Generation keys: unsuccessful. Not working key!", 7, obj)
        except KeyError:
            self.alert("Generation keys: unsuccessful. Critical! Key Compromise!", 9, obj)


class Slave(Object):
    """docstring for Slave"""

    def __init__(self, connection, name):
        obj = connection.getComponent(Object, "\"Name\"='%s'" % name)

        if obj is None:
            raise Exception("No such object " + name)

        super().__init__(obj.IP, name, 1, obj.key, obj.working, obj.ref)

        self.connection = connection

    def initKey(self, prvKey, mainKey):
        dbMgr = self.connection.dbMgr
        dbMgr.transaction()

        objects = self.connection.getComponents(Object)
        for key, val in objects.items():
            val.key = None
            if not self.connection.updateComponent(val):
                dbMgr.rollback()
                self.alert("Update error while initKey", 2)
                return False

        keys = self.connection.getComponents(Key)
        if keys is not None:
            for key in keys:
                key.obj = None
                key.block = None
                if not self.connection.updateComponent(key):
                    dbMgr.rollback()
                    self.alert("Update error while initKey", 2)
                    return False
                if not self.connection.deleteComponent(key):
                    dbMgr.rollback()
                    self.alert("Delete error while initKey", 3)
                    return False

        blocks = self.connection.getComponents(Block)
        if blocks is not None:
            for bid, val in blocks.items():
                if not self.connection.deleteComponent(val):
                    dbMgr.rollback()
                    self.alert("Delete error while initKey", 3)
                    return False

        del blocks
        del keys
        del objects

        self.key.privateKey = prvKey

        main = self.mainObject()
        key = Key(mainKey[1], None, main, mainKey[0], mainKey[0], True)

        if self.connection.createComponent(key) is None:
            dbMgr.rollback()
            self.alert("Create error while initKey", 1)
            return False

        main.key = key

        if not self.connection.updateComponent(main):
            dbMgr.rollback()
            self.alert("Update error while initKey", 2)
            return False

        dbMgr.commit()

        config = self.connection.getSettings()
        config["params"]["nprvk"] = prvKey
        config["params"]["prvk"] = prvKey
        # config["params"]["init"] = '0'
        self.connection.setSettings(config)

        return True

    def mainObject(self):
        return self.connection.getComponent(Object, "\"Type\"=0")

    @speak
    def requestBlock(self, obj, data, where, resp, thread, other, check):
        if resp == "Error":
            self.alert("Request block: unsuccessful. Something went wrong.", 7, obj)
            return False

        try:
            gost = GOST()
            main = self.mainObject()
            number = 1
            resp = loads(resp)
            n = len(resp)
            # print(n)
            if n > 0:
                prevBlock = self.connection.getComponent(Block, "\"Current\"=true")
                prevBlock.current = False
                if not self.connection.updateComponent(prevBlock):
                    self.alert("Update error while requestBlock", 2)
                    return False


            dbMgr = self.connection.dbMgr
            dbMgr.transaction()

            for block in resp:
                blockHash = block[1]
                block = block[0]

                blockString = dumps(block, sort_keys=True)
                print(main.key.publicKey)
                if not gost.checkSignature(blockString, blockHash, main.key.publicKey):
                    dbMgr.rollback()
                    self.alert("Request block: unsuccessful. Warning! Attempt treat system! Probably MITM CC", 8)
                    return False

                blockdb = Block(block["blockNumber"], block["id"], blockHash, True if number == n else False, block["createTime"])
                if not self.connection.createComponent(blockdb):
                    dbMgr.rollback()
                    self.alert("Create error while requestBlock", 1)
                    return False

                for ip, key in block["keys"].items():
                    oldObj = self.connection.getComponent(Object, "\"IP\"='{}'".format(ip))
                    if not gost.checkSignature(key["key"], key["oldHash"], oldObj.key.publicKey):
                        dbMgr.rollback()
                        self.alert("Request block: unsuccessful. Check signature", 7)
                        return False

                    newKey = Key(key["key"], blockdb, oldObj, key["hash"], key["oldHash"], True)
                    if not self.connection.createComponent(newKey):
                        dbMgr.rollback()
                        self.alert("Create error while requestBlock", 1)
                        return False

                    oldObj.key = newKey
                    if not self.connection.updateComponent(oldObj):
                        dbMgr.rollback()
                        self.alert("Update error while requestBlock", 2)
                        return False

                    if oldObj.name == main.name:
                        main = oldObj

                number += 1

            dbMgr.commit()
        except KeyError:
            self.alert("Request block: unsuccessful. Warning! Attempt treat system! Probably MITM", 9)

        return True

    def turn(self, on):
        objects = self.connection.getComponents(Object, "\"Working\"=true")

        if len(objects) == 0:
            self.alert("No objects while turn", 4)
            return False

        threads = []
        for name, obj in objects.items():
            if name == self.name:
                continue

            thr = Thread(target=self.__shareSelfState, args=(obj, {"turn": on}, "objectTurned", None, True, self.IP, False))
            threads.append(thr)
            thr.start()

        for thr in threads:
            thr.join()

        self.working = on
        if not self.connection.updateComponent(self):
            self.alert("Update error while turn", 2)
            return False

        return True

    def generateNewKeys(self, form):
        main = self.mainObject()

        try:
            resp = main.checkMsg(form["data"])
            if resp is None:
                self.alert("Generation keys: unsuccessful. Warning! Attempt treat system!", 8)
                return "Error"
        except KeyError:
            self.alert("Generation keys: unsuccessful. Warning! Attempt treat system!", 9)
            return "Error"

        gost = GOST()
        keys = gost.genKeys()
        sign = gost.createSignature(keys[1], keys[0])
        signOld = gost.createSignature(keys[1], self.key.privateKey)

        config = self.connection.getSettings()
        config["params"]["nprvk"] = keys[0]
        self.connection.setSettings(config)

        return self.createMsg({"NK": keys[1], "HH": sign, "OH": signOld})

    def updateBlock(self, form):
        main = self.mainObject()

        resp = None
        gost = GOST()

        try:
            resp = main.checkMsg(form["data"])
            if resp is None:
                self.alert("Update block: unsuccessful. Warning! Attempt treat system! CS", 8)
                return "Error"

            blockHash = resp["hash"]
            resp = resp["block"]

            key = resp["keys"][self.IP]

            if not gost.checkSignature(key["key"], key["hash"], key["key"]):
                self.alert("Update block: unsuccessful. Unable checkSignature! Attempt treat system!", 8)
                return "Error"

            dbMgr = self.connection.dbMgr
            dbMgr.transaction()

            block = Block(resp["blockNumber"], resp["id"], blockHash, True, resp["createTime"])
            if self.connection.createComponent(block) is None:
                dbMgr.rollback()
                self.alert("Create error while updateBlock", 1)
                return

            if int(resp["blockNumber"]) == 1:
                main.key.block = block
                if not self.connection.updateComponent(main.key):
                    dbMgr.rollback()
                    self.alert("Update error while updateBlock", 2)
                    return
            else:
                main.key.block.current = False
                if not self.connection.updateComponent(main.key.block):
                    dbMgr.rollback()
                    self.alert("Update error while updateBlock", 2)
                    return

            for IP, keyPack in resp["keys"].items():
                if IP == self.IP or (IP == main.IP and int(resp["blockNumber"]) == 1):
                    continue

                obj = self.connection.getComponent(Object, "\"IP\"='{}'".format(IP))
                key = Key(keyPack["key"], block, obj, keyPack["hash"], keyPack["oldHash"], True)
                if self.connection.createComponent(key) is None:
                    dbMgr.rollback()
                    self.alert("Create error while updateBlock", 1)
                    return

                obj.key = key
                if not self.connection.updateComponent(obj):
                    dbMgr.rollback()
                    self.alert("Update error while updateBlock", 2)
                    return

            dbMgr.commit()
        except KeyError:
            self.alert("Update block: unsuccessful. Warning! Attempt treat system! KE", 9)
            return "Error"

        msg = self.createMsg("OK")

        config = self.connection.getSettings()
        self.key.privateKey = config["params"]["nprvk"]
        config["params"]["prvk"] = config["params"]["nprvk"]
        config["params"]["nprvk"] = ''
        self.connection.setSettings(config)

        return msg

    @speak
    def __shareSelfState(self, obj, data, where, resp, thread, other, check):
        pass

if __name__ == "__main__":
    pass
