import subprocess, psutil, pytest
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
    assert process.returncode == 0, "Fail to execute dig"
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
                    assert requested_str == token.split(": ")[1], "Answer section is differs from expected"
        if "ANSWER SECTION:" in line and requested_ip != "":
            answer_section = next(iterator)
            for token in answer_section.split():
                print(token)
            assert requested_ip == answer_section.split()[4], "Answer section is differs from expected"
    
    assert got_answer == True, "Cannot find line with 'Got answer:'"

def start_proxy_dns(config_path: str) -> Popen:
    if config_path is None or config_path == "":
        assert config_path != ""
    process = Popen(f"{PROXY_DNS_APP_PATH} {config_path}", stdout=PIPE, stderr=STDOUT, shell=True)
    
    assert process.returncode == None, "Fail to execute proxy-dns server"

    return process

def kill_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        parent.kill()
    except psutil.NoSuchProcess:
        pass

@pytest.mark.parametrize(
        "domain, result",
        [
            ("google.com",  "REFUSED"),
            ("ya.ru",       "REFUSED"),
            ("yandex.ru",   "REFUSED")
        ]
)
def test_blacklist_refused(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_refused.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result",
        [
            ("google.com",  "NXDOMAIN"),
            ("ya.ru",       "NXDOMAIN"),
            ("yandex.ru",   "NXDOMAIN")
        ]
)
def test_blacklist_not_found(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_not_found.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result, readrr_ip",
        [
            ("google.com",  "NOERROR", "10.10.10.10"),
            ("ya.ru",       "NOERROR", "10.10.10.11"),
            ("yandex.ru",   "NOERROR", "10.10.10.12")
        ]
)
def test_blacklist_readressing(domain, result, readrr_ip):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_blacklist_readressing.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result, readrr_ip)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result",
        [
            ("github.com",  "NOERROR"),
        ]
)
def test_existed_domain(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_existed_domain.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result",
        [
            ("googlerrob.com.123.123",  "NXDOMAIN"),
        ]
)
def test_not_existed_domain(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_not_existed_domain.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result",
        [
            ("github.com",  "SERVFAIL"),
        ]
)
def test_not_existed_upstream(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_not_existed_upstream.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result",
        [
            ("github.com",  "NOERROR"),
        ]
)
def test_existed_upstream(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_existed_upstream.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)

@pytest.mark.parametrize(
        "domain, result",
        [
            ("github.com",  "NOERROR"),
        ]
)
def test_correct_queries_with_huge_blacklist(domain, result):
    process = start_proxy_dns(f"{TESTS_DIR}/{test_correct_queries_with_huge_blacklist.__name__}.config")
    output = start_dig("127.0.0.1", "6969", domain)
    parse_output(output, result)
    kill_process_tree(process.pid)


if __name__ == "__main__":
    pytest.main(["-v"])