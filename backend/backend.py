from flask import Flask, request, send_from_directory
import os

app = Flask(__name__, static_folder="../frontend/dist", static_url_path="")

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

@app.route("/data", methods=["GET"])
def get_data():
    query = request.args.get("query", "No query provided")
    return {"response": f"Tu as cherche : {query}"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
