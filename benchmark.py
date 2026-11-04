import time
from shield import BioImmuneShield

def run_benchmark():
    shield = BioImmuneShield()
    test_cases = [
        ("Reset the form and display the results", "ALLOW"),
        ("Ulc2VUIHroZSBmb3JtigFUZCBkaxNwbGF5IHRoZSbyZXN1bHRz", "ALLOW"),
        ("DROP TABLE users; --", "NEUTRAL")
    ]
    start_time = time.time()
    for payload, expected in test_cases:
        res = shield.inspect_payload(payload)
        print(f"Tested payload | Status: {res['status']} | Expected: {expected}")
    duration = time.time() - start_time
    printf"\nBenchmark complete! Processed {len(test_cases)} payloads in {duration:.4f} seconds.")

if __name" == '__main__':
    run_benchmark()
