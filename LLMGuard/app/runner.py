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
    - Attack ID (and Parent ID if generated)
    - Category
    - Attack name
    - Objective
    - Prompt
    - Target response
    - Security result
    """
    print("\n==================================================")
    print(f"Attack ID: {attack['id']}")
    if attack.get("parent_test_id"):
        print(f"Parent Test ID: {attack['parent_test_id']}")
    print(f"Category: {attack['category']}")
    print(f"Attack: {attack['name']}")
    if attack.get("generation_method"):
        print(f"Generation Method: {attack['generation_method']}")
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


def run_security_tests(
    target_mode=None,
    target_id=None,
    include_baseline=True,
    enable_mutations=False,
    max_mutations=10,
    categories=None,
):
    """
    Executes the suite of adversarial attacks (baseline and optional runtime mutations)
    against the active target adapter, evaluates responses for canary leakage or security
    refusal, records in-memory results, and produces a complete security assessment report.
    """
    from target_client import get_active_adapter
    adapter = get_active_adapter(target_id)

    if target_mode and hasattr(adapter, "set_mode"):
        adapter.set_mode(target_mode)

    active_mode = getattr(adapter, "get_mode", lambda: "STANDARD")()

    if enable_mutations:
        from attack_generator import generate_runtime_suite
        attacks = generate_runtime_suite(
            target_id=target_id,
            categories=categories,
            include_baseline=include_baseline,
            enable_mutations=True,
            enable_templates=False,
            enable_llm=False,
            max_candidates=max_mutations,
        )
    else:
        attacks = generate_attacks()
        if categories:
            attacks = [a for a in attacks if a["category"] in categories]

    print("==================================================")
    print("        LLMGuard Adversarial Security Suite       ")
    print(f"  Target: {adapter.name:<32}")
    print(f"  Provider: {adapter.provider.upper():<15} Model: {adapter.model}")
    print(f"  Target Mode: {active_mode:<27}")
    print(f"  Total Attacks: {len(attacks):<25}")
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

        response, _latency_ms = adapter.send_message(attack["prompt"])
        verdict, detail = evaluate_response_details(response, canaries=adapter.canaries)

        results_summary[verdict] += 1
        category_stats[cat][verdict] += 1

        # Keep existing individual test output
        print_attack_result(attack, response, verdict, detail)

        if verdict == "VULNERABLE":
            vulnerable_cases.append({
                "id": attack["id"],
                "parent_test_id": attack.get("parent_test_id"),
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
    parser.add_argument(
        "--target",
        help="Optional target ID to scan (defaults to active target)"
    )
    parser.add_argument(
        "--enable-mutations",
        action="store_true",
        help="Enable deterministic runtime mutation testing"
    )
    parser.add_argument(
        "--max-mutations",
        type=int,
        default=10,
        help="Maximum number of mutated attacks to generate (default: 10)"
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        help="Filter attacks by category"
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run baseline vs runtime-mutation comparison mode"
    )
    args = parser.parse_args()

    if args.compare:
        from comparison import run_comparison
        run_comparison(
            target_mode=args.mode,
            target_id=args.target,
            max_mutations=args.max_mutations,
            categories=args.categories,
        )
    else:
        run_security_tests(
            target_mode=args.mode,
            target_id=args.target,
            enable_mutations=args.enable_mutations,
            max_mutations=args.max_mutations,
            categories=args.categories,
        )