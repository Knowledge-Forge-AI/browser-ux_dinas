"""Historical native entrypoint retired: the R1 boundary is not qualified.

Exact original source is retained as non-entrypoint .txt provenance under
fixtures/cnt-native/history/r1. Use cnt-native-preflight.py for empty-browser
boundary diagnostics. That tool does not load CNT or claim characterization.
"""


def main():
    raise SystemExit("BLOCKED: R1 native execution refused; corrected browser confinement is unqualified")


if __name__ == '__main__':
    main()
