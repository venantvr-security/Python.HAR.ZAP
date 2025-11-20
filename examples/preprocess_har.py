#!/usr/bin/env python3
"""
Example: HAR Preprocessing
Demonstrates the unified HAR preprocessing workflow
"""
import sys

from modules.har_preprocessor import HARPreprocessor


def main():
    if len(sys.argv) < 2:
        print("Usage: python examples/preprocess_har.py <har_file.har>")
        sys.exit(1)

    har_file = sys.argv[1]

    print("=" * 60)
    print("HAR PREPROCESSING EXAMPLE")
    print("=" * 60)

    # Example 1: Basic preprocessing with default filters
    print("\n1️⃣ Basic preprocessing (exclude static, all methods)...")
    preprocessor = HARPreprocessor(har_path=har_file)

    # Save to single unified file
    preprocessor.save('output/preprocessed.json')

    # Example 2: With custom filters
    print("\n2️⃣ Custom filters (POST only, JSON only, status 200)...")
    preprocessor_filtered = HARPreprocessor(har_path=har_file)
    preprocessor_filtered.set_filters(
        methods=['POST', 'PUT', 'PATCH'],
        content_types=['application/json'],
        status_codes=[200, 201],
        exclude_static=True
    )

    preprocessor_filtered.save('output/preprocessed_filtered.json')

    # Example 3: Domain-specific extraction
    print("\n3️⃣ Domain-specific (api.example.com only)...")
    preprocessor_domain = HARPreprocessor(har_path=har_file)
    preprocessor_domain.set_filters(
        domains=['api.example.com'],
        exclude_static=True
    )

    preprocessor_domain.save('output/preprocessed_api_only.json')

    # Example 4: Save as separate files (granular access)
    print("\n4️⃣ Saving individual extracts...")
    preprocessor.save_extracts('output/extracts')

    # Example 5: Print summary
    print("\n5️⃣ Preprocessing summary:")
    preprocessor.print_summary()

    print("\n" + "=" * 60)
    print("✓ PREPROCESSING COMPLETE")
    print("=" * 60)
    print("\nOutput files:")
    print("  - output/preprocessed.json (unified, for all modules)")
    print("  - output/preprocessed_filtered.json (custom filters)")
    print("  - output/preprocessed_api_only.json (domain-specific)")
    print("  - output/extracts/ (granular components)")
    print("\nNext steps:")
    print("  1. Use preprocessed.json as input for attack modules")
    print("  2. Review statistics.json for insights")
    print("  3. Inspect dictionaries.json for extracted keys")


if __name__ == '__main__':
    main()
