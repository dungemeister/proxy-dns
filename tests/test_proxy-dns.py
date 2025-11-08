import subprocess
from subprocess import Popen, PIPE, STDOUT
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = SCRIPT_DIR

def start_dig(proxy_ip: str, proxy_port: str, domain) -> str:
    process = Popen(f"dig @{proxy_ip} -p {proxy_port} {domain}", stdout=PIPE, stderr=STDOUT, shell=True)
    stdout, _ = process.communicate()
    return stdout.decode()

def parse_output(output:str, requested: str) -> bool:
    answer: bool = False
    res: bool = False
    for line in output.split("\n"):
        if "Got answer:" in line:
            answer = True
        if "->>HEADER<<-" in line:
            for token in line.split(", "):
                if "status" in token:
                    assert requested == token.split(": ")[1]
    assert answer == True

def start_proxy_dns(config_path: str) -> str:
    if config_path is None or config_path == "":
        assert config_path != ""
    process = Popen(f"{SCRIPT_DIR}/../proxy-dns {config_path}", stdout=PIPE, stderr=STDOUT, shell=True, close_fds=True)

def test_blacklist_refused():
    blacklist = ["google.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test1.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "REFUSED")
    

def test_blacklist_not_found():
    blacklist = ["ya.ru"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test2.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NXDOMAIN")

def test_blacklist_readressing():
    blacklist = ["google.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test3.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")

def test_existed_domain():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test4.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")

def test_not_existed_domain():
    blacklist = ["googlerrob.com.123.123"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test5.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NXDOMAIN")

def test_not_existed_upstream():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test6.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "SERVFAIL")

def test_correct_queries_with_huge_clacklist():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/test7.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")