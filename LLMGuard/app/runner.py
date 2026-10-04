import sys
import argparse
from attack_generator import generate_attacks
from target_client import send_attack, get_target_mode, set_target_mode
from evaluator import evaluate_response, evaluate_response_details

# Ensure UTF-8 output on Windows consoles to prevent charmap encoding errors
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def print_attack_result(attack, response, verdict, detail=None):
    """
    Prints the individual test execution result following the standard format:
    - Attack ID
    - Category
    - Attack name
    - Objective
    - Prompt
    - Target response
    - Security result
    """
    print("\n==================================================")
    print(f"Attack ID: {attack['id']}")
    print(f"Category: {attack['category']}")
    print(f"Attack: {attack['name']}")
    print("\nObjective:")
    print(attack["objective"])
    print("\nPrompt:")
    print(attack["prompt"])
    print("\nResponse:")
    print(response)
    print(f"\nSecurity Result: {verdict}")
    if verdict == "VULNERABLE" and detail:
        print(f"Leakage Detail : {detail}")
    print("==================================================")


def print_security_assessment(total_tests, results_summary):
    """
    Prints the top-level security assessment summary block.
    """
    print("\n============================================================")
    print("                 LLMGuard Security Assessment")
    print("============================================================")
    print("\nTarget:")
    print("TechMart Customer Support AI\n")
    print(f"Total Tests: {total_tests}\n")
    print("Results")
    print("------------------------------------------------------------")
    print(f"SAFE              {results_summary.get('SAFE', 0)}")
    print(f"VULNERABLE        {results_summary.get('VULNERABLE', 0)}")
    print(f"TARGET_ERROR      {results_summary.get('TARGET_ERROR', 0)}")
    print("------------------------------------------------------------\n")
    print(f"Security Findings: {results_summary.get('VULNERABLE', 0)}\n")
    print("============================================================\n")


def print_category_summary(category_stats):
    """
    Prints the category-wise breakdown of executed tests and detected vulnerabilities.
    """
    max_cat_len = max((len(cat) for cat in category_stats.keys()), default=30)
    col_width = max(max_cat_len + 3, 44)
    divider = "-" * (col_width + 21)

    print("Category Summary")
    print(divider)
    for cat, stats in category_stats.items():
        total = stats.get("total", 0)
        vuln = stats.get("VULNERABLE", 0)
        print(f"{cat:<{col_width}} {total:>2} tests    {vuln:>2} vulnerable")
    print(divider)


def print_vulnerability_findings(vulnerable_cases):
    """
    Prints individual vulnerability findings with attack metadata and reason.
    """
    if not vulnerable_cases:
        return

    print("\n============================================================")
    print("                 VULNERABILITY FINDINGS")
    print("============================================================\n")
    for idx, case in enumerate(vulnerable_cases, 1):
        print(f"[{idx}] {case['id']}")
        print(f"Category: {case['category']}")
        print(f"Attack: {case['name']}\n")
        print("Reason:")
        print("Protected information was detected in the target response.")
        if case.get("detail"):
            print(f"Detail: {case['detail']}")
        print()
    print("============================================================")


def run_security_tests(target_mode=None):
    """
    Executes the full suite of adversarial attacks against the TechMart target,
    evaluates responses for canary leakage or security refusal, records in-memory
    results, and produces a complete security assessment report.
    """
    if target_mode:
        set_target_mode(target_mode)

    active_mode = get_target_mode()
    attacks = generate_attacks()

    print("==================================================")
    print("        LLMGuard Adversarial Security Suite       ")
    print(f"        Target Mode: {active_mode:<28} ")
    print("==================================================")

    results_summary = {
        "SAFE": 0,
        "VULNERABLE": 0,
        "TARGET_ERROR": 0
    }

    category_stats = {}
    vulnerable_cases = []

    # Initialize category statistics in the exact order attacks are defined
    for attack in attacks:
        cat = attack["category"]
        if cat not in category_stats:
            category_stats[cat] = {
                "total": 0,
                "SAFE": 0,
                "VULNERABLE": 0,
                "TARGET_ERROR": 0
            }

    # Execute scan across all attacks
    for attack in attacks:
        cat = attack["category"]
        category_stats[cat]["total"] += 1

        response, _latency_ms = send_attack(attack["prompt"])
        verdict, detail = evaluate_response_details(response)

        results_summary[verdict] += 1
        category_stats[cat][verdict] += 1

        # Keep existing individual test output
        print_attack_result(attack, response, verdict, detail)

        if verdict == "VULNERABLE":
            vulnerable_cases.append({
                "id": attack["id"],
                "category": cat,
                "name": attack["name"],
                "detail": detail
            })

    # Print Final Security Assessment and Summaries
    total_tests = len(attacks)
    print_security_assessment(total_tests, results_summary)
    print_category_summary(category_stats)
    print_vulnerability_findings(vulnerable_cases)

    return results_summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLMGuard Security Testing Suite")
    parser.add_argument(
        "--mode",
        choices=["SECURE", "VULNERABLE"],
        help="Optional mode to switch the TechMart target to before testing"
    )
    args = parser.parse_args()

    run_security_tests(target_mode=args.mode)