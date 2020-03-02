from flask import Flask, request

from Managers import Connection, registerThread
from Objects import Main

from configparser import ConfigParser
import pickle

app = Flask(__name__)

config = ConfigParser()
config.read("settings.ini")

if config["params"]["type"] != '0':
    exit(0)

connection = Connection(config["connection"]["login"],
    config["connection"]["password"],
    config["connection"]["programName"],
    config["connection"]["host"],
    config["connection"]["dbName"],
    "settings.ini")

main = Main(connection, config["params"]["name"])
main.key.privateKey = config["params"]["prvk"]


@app.route('/init', methods=["GET"])
def init():
    with registerThread(connection):
        res = main.firstInit()

        if res == {}:
            return "Error"

        print(res)
        with open("top_secret_data.pkl", "wb") as pfile:
            pickle.dump(res, pfile)
            return "OK"

# key exchange


@app.route('/requestKeys', methods=["GET"])
def requestKeys():
    with registerThread(connection):
        if main.requestNewKeys():
            return "OK"

        return "Error"

# block exchange


@app.route('/shareBlock', methods=["GET"])
def shareBlock():
    with registerThread(connection):
        if main.shareBlock():
            return "OK"

        return "Error"


@app.route('/requestBlock', methods=["POST"])
def sendBlock():
    with registerThread(connection):
        return main.sendBlocks(request.form)

# switch object


@app.route('/objectTurned', methods=["POST"])
def objectTurned():
    with registerThread(connection):
        return main.objectTurned(request.form)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
