from flask import Flask, request, jsonify # type: ignore

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Bienvenue sur le backend Flask !"})

@app.route("/data", methods=["GET"])
def get_data():
    query = request.args.get("query", "No query provided")
    return jsonify({"response": f"Tu as cherche : {query}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
