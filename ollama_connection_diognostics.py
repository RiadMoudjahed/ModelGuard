#!/usr/bin/env python3
"""
Ollama Connection Diagnostics Tool
Run this to debug connection issues
"""

import requests
import json
import sys


def test_ollama_connection(base_url="http://localhost:11434", model="auto"):
    """Comprehensive Ollama diagnostics"""

    print("=" * 70)
    print("OLLAMA CONNECTION DIAGNOSTICS")
    print("=" * 70)
    print()

    # Test 1: Basic connectivity
    print("Test 1: Checking if Ollama server is running...")
    print(f"  URL: {base_url}")

    try:
        response = requests.get(f"{base_url}/api/version", timeout=5)
        print(f"  ✓ Server is running")
        print(f"  Status Code: {response.status_code}")
        if response.status_code == 200:
            try:
                version_data = response.json()
                print(f"  Version: {version_data.get('version', 'unknown')}")
            except:
                print(f"  Response: {response.text[:100]}")
    except requests.exceptions.ConnectionError:
        print("  ✗ FAILED: Cannot connect to Ollama server")
        print("  Solution: Make sure Ollama is running with 'ollama serve'")
        return False
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False

    print()

    # Test 2: List available models
    print("Test 2: Checking available models...")
    print(f"  URL: {base_url}/api/tags")

    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        print(f"  Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            models = data.get('models', [])

            if not models:
                print("  ✗ No models found!")
                print(f"  Solution: Pull a model with 'ollama pull qwen2.5' or 'ollama pull llama3.2'")
                return False

            print(f"  ✓ Found {len(models)} model(s):")
            for m in models:
                model_name = m.get('name', 'unknown')
                size = m.get('size', 0) / (1024 ** 3)  # Convert to GB
                print(f"    - {model_name} ({size:.2f} GB)")

            # Auto-select if model is "auto"
            if model == "auto":
                model = models[0].get('name', 'unknown')
                print(f"  ✓ Auto-selected model: {model}")
            else:
                # Check if requested model exists
                model_names = [m.get('name', '').split(':')[0] for m in models]
                model_base = model.split(':')[0]

                if model_base in model_names or any(model in m.get('name', '') for m in models):
                    print(f"  ✓ Requested model '{model}' is available")
                else:
                    print(f"  ✗ Requested model '{model}' NOT found")
                    print(f"  Available: {', '.join(model_names)}")
                    print(f"  Solution: Use one of the available models or pull {model}")
                    print(f"  Tip: Use 'auto' to automatically select first available model")
                    return False
        else:
            print(f"  ✗ FAILED: Status {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            return False

    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False

    print()

    # Test 3: Test actual generation
    print("Test 3: Testing model generation...")
    print(f"  URL: {base_url}/api/generate")
    print(f"  Model: {model}")

    try:
        payload = {
            "model": model,
            "prompt": "Say 'test successful' and nothing else.",
            "stream": False,
            "options": {
                "num_predict": 10
            }
        }

        print(f"  Sending test prompt...")
        response = requests.post(f"{base_url}/api/generate", json=payload, timeout=30)
        print(f"  Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            response_text = data.get('response', '')
            print(f"  ✓ Generation successful!")
            print(f"  Response: {response_text[:100]}")
            return True
        elif response.status_code == 404:
            print(f"  ✗ FAILED: Model not found (404)")
            try:
                error_data = response.json()
                print(f"  Error: {error_data.get('error', 'unknown')}")
            except:
                pass
            print(f"  Solution: ollama pull {model}")
            return False
        else:
            print(f"  ✗ FAILED: Status {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            return False

    except requests.exceptions.Timeout:
        print("  ✗ FAILED: Request timed out (30s)")
        print("  The model might be loading for the first time")
        print("  Try running: ollama run " + model)
        return False
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False

    print()


def main():
    """Run diagnostics"""

    # Check command line arguments
    base_url = "http://localhost:11434"
    model = "auto"  # Changed default to auto

    if len(sys.argv) > 1:
        model = sys.argv[1]
    if len(sys.argv) > 2:
        base_url = sys.argv[2]

    success = test_ollama_connection(base_url, model)

    print()
    print("=" * 70)
    if success:
        print("✓ ALL TESTS PASSED - Ollama is ready!")
        print()
        print("ModelGuard should now work with AI analysis.")
        print("Run: python modelguard_cli.py scan <model_file> --ai-analysis")
    else:
        print("✗ TESTS FAILED - See errors above")
        print()
        print("Common solutions:")
        print("1. Start Ollama: ollama serve")
        print(f"2. Pull model: ollama pull {model}")
        print(f"3. Test model: ollama run {model}")
        print("4. Check firewall/antivirus settings")
        print("5. Try different model: python this_script.py llama3.1")
    print("=" * 70)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())