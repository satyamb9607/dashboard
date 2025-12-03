# buggy_sample.py
# A deliberately-broken Python file containing many issues for testing static analysis / PR review tools.
# DO NOT RUN THIS IN PRODUCTION — it contains insecure, unsafe, and incorrect code on purpose.

import os, sys, time, json, math
import subprocess
import threading
import pickle
import sqlite3
from typing import List, Dict, Optional

# Unused import (should be flagged)
import hashlib

# Hard-coded secret (security smell)
DB_PASSWORD = "supersecretpassword123"

# Global mutable default (anti-pattern + potential race conditions)
CACHE = {}

# Mutable default argument bug
def append_to_list(value, bucket=[]):
    # This will keep growing across calls
    bucket.append(value)
    return bucket

# Bare except and bad exception handling
def read_json_maybe(path):
    try:
        data = open(path).read()
        return json.loads(data)
    except:
        # Swallowing all exceptions — should at least log/raise
        return {}

# Unsafe use of eval
def evaluate_expression(expr: str):
    # Dangerous: executes arbitrary code
    return eval(expr)  # ok for vulnerability testing

# Unsafe subprocess usage (shell=True)
def run_shell(command: str):
    # Injection-prone
    return subprocess.check_output(command, shell=True)

# SQL injection risk: string formatting user input into query
def get_user_by_username(conn, username: str):
    cursor = conn.cursor()
    q = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(q)  # insecure
    return cursor.fetchall()

# Resource leak: file not closed on some error paths
def write_report(path, content):
    f = open(path, "w")
    f.write(content)
    if os.getenv("RAISE_ERROR"):
        raise RuntimeError("boom")  # file handle left open
    f.close()

# Deprecated or inefficient pattern: reading entire file into memory
def count_lines(path):
    with open(path, "r") as fh:
        data = fh.read().splitlines()
    return len(data)

# Hard-coded path / OS-specific behavior
def get_config():
    return "/etc/myapp/config.json"  # not portable, may not exist

# Wrong equality check for floats
def is_close(a: float, b: float) -> bool:
    # Using == on floats instead of math.isclose
    return a == b

# Wrong use of recursion without base case
def infinite_recursion(n):
    # This will quickly blow the stack
    return infinite_recursion(n + 1)

# Poor concurrency: shared global counter without lock
counter = 0
def increment_counter():
    global counter
    counter += 1

def start_threads(num=10):
    threads = []
    for i in range(num):
        t = threading.Thread(target=increment_counter)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

# Job that swallows exceptions in threads (no logging)
def thread_worker():
    try:
        # some imaginary risky work
        1 / 0
    except Exception:
        pass  # silent failure

def start_silent_threads():
    for _ in range(5):
        threading.Thread(target=thread_worker).start()

# Use of pickle.load on untrusted data (RCE)
def load_data(path):
    with open(path, "rb") as f:
        return pickle.load(f)

# Inefficient algorithm: O(n^2) for large lists
def dedupe(items: List[int]) -> List[int]:
    out = []
    for i in items:
        if i not in out:
            out.append(i)
    return out

# Shadowing builtin name and mutable global
list = [1, 2, 3]  # shadows built-in list type

# Unused variables and dead code
def calculate(x):
    y = x * 2
    z = y + 10
    return x  # returns wrong variable, z unused

# Implicit relative import style that can be problematic in packages
# (left here as a comment to be flagged when in package context)
# from .module import fn

# Using os.system (deprecated-ish) and not checking return code
def do_build():
    rc = os.system("make build")
    if rc != 0:
        print("build failed")  # not raising or handling properly

# Timezone naive timestamp (should use timezone-aware)
def get_timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())

# Potential integer division mismatch in Python3? (here it's fine but flagged often)
def compute_ratio(a, b):
    return a / b

# Duplicate code path and complex conditional that can be simplified
def complicated(x):
    if x is None:
        return None
    if x == 0:
        return 0
    if x < 0:
        return -1
    if x > 0:
        return 1

# Too many arguments, poor naming, no typing, and side effects
def process(a, b, c, d, e, f, g):
    global CACHE
    # modifies global state unpredictably
    CACHE["last"] = (a, b, c, d, e, f, g)
    return len(CACHE["last"])

# Re-raising exceptions incorrectly losing original traceback
def bad_reraise():
    try:
        1 / 0
    except Exception as exc:
        raise Exception("wrapped") from None

# Mixing sync and blocking IO in async style (example: synchronous placeholder)
def pretend_async_read(path):
    # Pretend to be async by returning a thread result; actual blocking call
    return open(path).read()

# Using eval-like dynamic attribute access instead of getattr
def get_field(obj, field_name):
    return eval("obj.%s" % field_name)

# Broken type hints and inconsistent return types
def maybe_int(val: str) -> int:
    if val.isdigit():
        return int(val)
    return None  # violates declared return type

# Unprotected main block that executes dangerous code when imported
if __name__ == "__main__":
    # create a temporary sqlite DB with insecure permissions
    conn = sqlite3.connect("test.db")  # default mode, file created on disk
    c = conn.cursor()
    try:
        # insecure table creation + inserting hard-coded password
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        c.execute("INSERT INTO users (username, password) VALUES ('admin', '%s')" % DB_PASSWORD)
        conn.commit()
    finally:
        # forgetting to close connection on error paths earlier in file code may leave open handles
        conn.close()

    # Do dangerous actions: run shell, eval, and load pickle if found
    try:
        print("Running shell command...")
        out = run_shell("echo hello")
        print(out)
    except Exception as e:
        print("shell failed:", e)

    # Evaluate arbitrary expression (dangerous)
    # Example payload a reviewer should flag immediately
    print("Eval:", evaluate_expression("2 + 2"))

    # Trigger resource leak pattern intentionally
    try:
        write_report("/tmp/report.txt", "report contents")
    except Exception:
        pass

    # Start threads that silently fail or race
    start_threads(50)
    start_silent_threads()

    # Attempt to load pickle if present (insecure)
    if os.path.exists("data.pickle"):
        try:
            data = load_data("data.pickle")
            print("Loaded pickled data:", data)
        except Exception as e:
            print("pickle load failed", e)

    # Demonstrate mutable default bug
    print("append_to_list a:", append_to_list(1))
    print("append_to_list b:", append_to_list(2))

    # Demonstrate recursion bug commented out to avoid crashing automatic runs
    # infinite_recursion(1)

    # Print counter (likely not deterministic due to race)
    print("counter:", counter)

    # Broken equality
    print("is_close(0.1+0.2, 0.3):", is_close(0.1 + 0.2, 0.3))

    # Wrong return variable
    print("calculate(5):", calculate(5))

    # unsafe getattr via eval
    class T: 
        value = 123

    print("get_field:", get_field(T, "value"))

    # demonstrate dedupe inefficiency
    big = list(range(1000)) + list(range(1000))
    result = dedupe(big)
    print("deduped length:", len(result))
