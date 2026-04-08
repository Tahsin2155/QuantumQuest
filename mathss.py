#!/usr/bin/env python3

import argparse
from sympy import symbols, Eq, solve, sympify, SympifyError


def parse_values(pairs):
    values = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"Invalid format '{pair}'. Use var=value")

        key, value = pair.split("=", 1)

        try:
            values[key.strip()] = float(value)
        except ValueError:
            raise ValueError(f"Invalid number for '{key}': {value}")

    return values


def solve_formula(formula, values):
    try:
        if "=" not in formula:
            raise ValueError("Formula must contain '='")

        left, right = formula.split("=", 1)

        left_expr = sympify(left.strip())
        right_expr = sympify(right.strip())

        equation = Eq(left_expr, right_expr)

    except SympifyError:
        raise ValueError("Invalid mathematical expression")

    variables = equation.free_symbols

    if not variables:
        raise ValueError("No variables found in formula")

    # Build substitution dictionary
    subs_dict = {}
    for var in variables:
        name = str(var)
        if name in values:
            subs_dict[var] = values[name]

    missing_vars = [v for v in variables if v not in subs_dict]

    if len(missing_vars) == 0:
        raise ValueError("All variables are already provided")
    elif len(missing_vars) > 1:
        raise ValueError(
            f"Too many unknowns: {', '.join(str(v) for v in missing_vars)}"
        )

    missing = missing_vars[0]

    try:
        solutions = solve(equation, missing)

        if not solutions:
            raise ValueError("No solution found")

        results = [sol.subs(subs_dict) for sol in solutions]

        # Convert to float safely
        results = [float(r) for r in results]

        return missing, results

    except ZeroDivisionError:
        raise ValueError("Division by zero occurred")
    except Exception as e:
        raise ValueError(f"Could not solve equation: {e}")


def interactive_mode():
    print("Entering interactive mode (type 'exit' to quit)\n")

    while True:
        try:
            formula = input("Enter formula: ").strip()
            if formula.lower() in ("exit", "quit"):
                break

            values_input = input("Enter values (e.g., m=10 a=2): ").strip()
            if values_input.lower() in ("exit", "quit"):
                break

            values = parse_values(values_input.split())

            var, results = solve_formula(formula, values)
            if len(results) == 1:
                print(f"{var} = {results[0]}\n")
            else:
                for result in results:
                    print(f"{var} = {result}")
                print()
                

        except ValueError as e:
            print(f"Error: {e}\n")
        except KeyboardInterrupt:
            print("\nExiting...")
            break


def main():
    parser = argparse.ArgumentParser(
        description="Universal Formula Solver CLI"
    )

    parser.add_argument(
        "formula",
        type=str,
        help="Formula (e.g., 'F = m*a')"
    )

    parser.add_argument(
        "values",
        nargs="*",
        help="Values (e.g., m=10 a=2)"
    )

    import sys

    # If no arguments → interactive mode
    if len(sys.argv) == 1:
        interactive_mode()
        return

    args = parser.parse_args()

    try:
        values = parse_values(args.values)
        var, results = solve_formula(args.formula, values)

        if len(results) == 1:
            print(f"{var} = {results[0]}")
        else:
            for result in results:
                print(f"{var} = {result}")

    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()