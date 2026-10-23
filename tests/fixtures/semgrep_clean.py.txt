import os, pickle, subprocess, tempfile, urllib.request, yaml, requests

API_KEY = os.environ.get("API_KEY")


def run(cmd, path, data, url):
    subprocess.run(["ls", "-la"])
    subprocess.run("ls -la", shell=True)
    os.system("ls")
    yaml.safe_load(data)
    requests.get(url, verify=True)
    urllib.request.urlopen(url)
    tempfile.mkstemp()
    open(path).read()
