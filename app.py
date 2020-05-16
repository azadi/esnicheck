import os

from flask import (
    abort,
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from esnicheck.check import ESNICheck

app = Flask(__name__)


def most_visited():
    sites = []
    file_path = os.path.join("mostvisited", "esni.txt")
    with app.open_resource(file_path, "r") as f:
        for each in f:
            sites.append(each.strip())
    return sites


def has_esni(hostname):
    esni = ESNICheck(hostname)
    (tls13, tls13_output) = esni.has_tls13()
    (dns, error, dns_output) = esni.has_dns()

    result = dict()

    result["tls13"] = {}
    result["tls13"]["enabled"] = True if tls13 else False
    result["tls13"]["output"] = tls13_output

    result["dns"] = {}
    result["dns"]["enabled"] = True if dns else False
    result["dns"]["output"] = dns_output
    result["dns"]["error"] = error

    result["hostname"] = hostname
    result["has_esni"] = esni.has_esni()
    return result


@app.route('/', methods=["GET", "POST"])
def landing():
    esni_sites = most_visited()
    data = {"websites": esni_sites,
            "percentage": (len(esni_sites) / 250) * 100}
    if request.method == "POST":
        return redirect(url_for('check', q=request.form['hostname']))
    return render_template("index.html", data=data)


@app.route('/check', methods=["GET", "POST"])
def check():
    if request.method == "POST":
        data = request.get_json()
        try:
            result = has_esni(data["q"])
        except KeyError:
            return abort(404)
        return jsonify({"has_esni": result["has_esni"]}), 200
    hostname = request.args.get("q")
    result = has_esni(hostname)
    return render_template("result.html", result=result)


@app.route('/faq', methods=["GET"])
def faq():
    return render_template("faq.html")
