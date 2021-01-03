import os
import json

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
    sites = {}
    file_path = os.path.join("mostvisited", "esni.txt")
    with app.open_resource(file_path, "r") as f:
        sites = json.load(f)
    return sites


def has_esni(hostname):
    esni = ESNICheck(hostname)
    (tls13, tls13_output) = esni.has_tls13()
    (dns, error, dns_output) = esni.has_dns()
    (host_ip, is_host_cf) = esni.is_cloudflare()

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
    result["host_ip"] = host_ip
    result["is_host_cf"] = is_host_cf
    return result


@app.route('/', methods=["GET", "POST"])
def landing():
    esni_sites = most_visited()
    len_esni_sites_cf = len([site for site in esni_sites.keys()
                             if esni_sites[site]['is_cf']])
    len_esni_sites = len(esni_sites)
    data = {"websites": esni_sites,
            "cf_percentage": (len_esni_sites_cf / len_esni_sites) * 100,
            "percentage": (len_esni_sites / 250) * 100}
    if request.method == "POST":
        if not request.form['hostname']:
            return redirect(url_for('landing'))
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
