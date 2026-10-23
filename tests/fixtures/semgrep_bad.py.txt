import os, pickle, subprocess, tempfile, urllib.request, yaml, requests

API_KEY = "sk-live-0123456789abcdef0123"


def run(cmd, prompt_path, data, host):
    subprocess.run(cmd, shell=True)
    os.system(cmd)
    eval(cmd)
    yaml.load(data)
    pickle.loads(data)
    requests.get(host, verify=False)
    urllib.request.urlopen(f"https://{host}/x")
    tempfile.mktemp()
    open(prompt_path).read()
