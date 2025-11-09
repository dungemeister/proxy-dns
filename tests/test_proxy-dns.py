import subprocess, psutil
from subprocess import Popen, PIPE, STDOUT
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = SCRIPT_DIR

PROXY_DNS_NAME = "proxy-dns"
PROXY_DNS_DIR = f"{SCRIPT_DIR}/../build"
PROXY_DNS_APP_PATH = f"{PROXY_DNS_DIR}/{PROXY_DNS_NAME}"

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

def start_proxy_dns(config_path: str) -> Popen:
    if config_path is None or config_path == "":
        assert config_path != ""
    return Popen(f"{PROXY_DNS_APP_PATH} {config_path}", stdout=PIPE, stderr=STDOUT, shell=True)

def kill_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        parent.kill()
    except psutil.NoSuchProcess:
        pass

def test_blacklist_refused():
    blacklist = ["google.com"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_refused.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "REFUSED")
    kill_process_tree(process.pid)

def test_blacklist_not_found():
    blacklist = ["ya.ru"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_not_found.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NXDOMAIN")
    kill_process_tree(process.pid)

def test_blacklist_readressing():
    blacklist = [("yandex.ru", "10.10.10.10")]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_readressing.__name__}.config")
    for domain, r_ip in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR", r_ip)
    kill_process_tree(process.pid)

def test_existed_domain():
    blacklist = ["github.com"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_existed_domain.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")
    kill_process_tree(process.pid)

def test_not_existed_domain():
    blacklist = ["googlerrob.com.123.123"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_not_existed_domain.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NXDOMAIN")
    kill_process_tree(process.pid)

def test_not_existed_upstream():
    blacklist = ["github.com"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_not_existed_upstream.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "SERVFAIL")
    kill_process_tree(process.pid)

def test_existed_upstream():
    blacklist = ["github.com"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_existed_upstream.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")
    kill_process_tree(process.pid)

def test_correct_queries_with_huge_blacklist():
    blacklist = ["github.com"]
    process = start_proxy_dns(f"{TESTS_DIR}/{test_correct_queries_with_huge_blacklist.__name__}.config")
    for domain in blacklist:
        output = start_dig("127.0.0.1", "6969", domain)
        parse_output(output, "NOERROR")
    kill_process_tree(process.pid)


if __name__ == "__main__":
    test_not_existed_upstream()