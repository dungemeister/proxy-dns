import subprocess
from subprocess import Popen, PIPE, STDOUT
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = SCRIPT_DIR

def start_dig(proxy_ip: str, proxy_port: str, domain) -> str:
    process = Popen(f"dig @{proxy_ip} -p {proxy_port} {domain}", stdout=PIPE, stderr=STDOUT, shell=True)
    stdout, _ = process.communicate()
    return stdout.decode()

def parse_output(output:str, requested_str: str, requested_ip: str = "") -> bool:
    got_answer: bool = False
    res: bool = False
    iterator = iter(output.split("\n"))
    for line in iterator:
        if "Got answer:" in line:
            got_answer = True
        if "->>HEADER<<-" in line:
            for token in line.split(", "):
                if "status" in token:
                    assert requested_str == token.split(": ")[1]
        if "ANSWER SECTION:" in line and requested_ip != "":
            answer_section = next(iterator)
            for token in answer_section.split():
                print(token)
            assert requested_ip == answer_section.split()[4]
    
    assert got_answer == True

def start_proxy_dns(config_path: str) -> str:
    if config_path is None or config_path == "":
        assert config_path != ""
    process = Popen(f"{SCRIPT_DIR}/../proxy-dns {config_path}", stdout=PIPE, stderr=STDOUT, shell=True, close_fds=True)

def test_blacklist_refused():
    blacklist = ["google.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_refused.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "REFUSED")
    

def test_blacklist_not_found():
    blacklist = ["ya.ru"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_not_found.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NXDOMAIN")

def test_blacklist_readressing():
    blacklist = [("yandex.ru", "10.10.10.10")]
    for domain, r_ip in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_readressing.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR", r_ip)

def test_existed_domain():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_existed_domain.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")

def test_not_existed_domain():
    blacklist = ["googlerrob.com.123.123"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_not_existed_domain.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NXDOMAIN")

def test_not_existed_upstream():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_not_existed_upstream.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "SERVFAIL")

def test_existed_upstream():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_existed_upstream.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")

def test_correct_queries_with_huge_blacklist():
    blacklist = ["github.com"]
    for domain in blacklist:
        start_proxy_dns(f"{TESTS_DIR}/{test_correct_queries_with_huge_blacklist.__name__}.config")
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")