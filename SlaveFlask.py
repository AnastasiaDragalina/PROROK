from flask import Flask, request

from Managers import Connection, registerThread
from Objects import Slave

from configparser import ConfigParser
import pickle

app = Flask(__name__)

config = ConfigParser()
config.read("settings1.ini")

if config["params"]["type"] != '1':
    exit(0)

connection = Connection(config["connection"]["login"],
    config["connection"]["password"],
    config["connection"]["programName"],
    config["connection"]["host"],
    config["connection"]["dbName"],
    "settings1.ini")

slave = Slave(connection, config["params"]["name"])
slave.key.privateKey = config["params"]["prvk"]


@app.route('/init', methods=["GET"])
def init():
    with registerThread(connection):
        with open("top_secret_data.pkl", "rb") as pfile:
            data = pickle.load(pfile)
            if slave.initKey(data[slave.name][0], data[slave.mainObject().name]):
                return "OK"

            return "Error"

# key exchange


@app.route('/updateBlock', methods=["POST"])
def updateBlock():
    with registerThread(connection):
        return slave.updateBlock(request.form)


@app.route('/requestNewKey', methods=["POST"])
def requestNewKey():
    with registerThread(connection):
        return slave.generateNewKeys(request.form)

# block exchange


@app.route('/sendRequestBlock', methods=["GET"])   # TODO
def sendRequestBlock():
    with registerThread(connection):
        main = slave.mainObject()
        if slave.requestBlock(main, {"number": 3}, "requestBlock", None, True, slave.IP, False):
            return "OK"

        return "Error"


@app.route('/requestBlock', methods=["POST"])
def sendBlock():
    with registerThread(connection):
        return slave.sendBlocks(request.form)

# switch object


@app.route('/turnOff', methods=["GET"])
def turnOff():
    with registerThread(connection):
        if slave.turn(on=False):
            return "OK"

        return "Error"


@app.route('/turnOn', methods=["GET"])
def turnOn():
    with registerThread(connection):
        if slave.turn(on=True):
            return "OK"

        return "Error"


@app.route('/objectTurned', methods=["POST"])
def objectTurned():
    with registerThread(connection):
        return slave.objectTurned(request.form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
