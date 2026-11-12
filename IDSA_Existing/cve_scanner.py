import json
import os

CVE_DATABASE_PATH = os.path.join(os.path.dirname(__file__), "..", "assets", "cve_database.json")

def load_cve_database(db_path=CVE_DATABASE_PATH):
    """Loads the CVE database from a JSON file."""
    if not os.path.exists(db_path):
        return {"error": f"CVE database not found at {db_path}"}
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        return cve_data
    except json.JSONDecodeError as e:
        return {"error": f"Error decoding CVE database JSON: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred loading CVE database: {e}"}

def search_cve(software_name, version=None, db_path=CVE_DATABASE_PATH):
    """Searches the CVE database for vulnerabilities related to a given software and optional version."""
    db = load_cve_database(db_path)
    if "error" in db:
        return [db] # Return the error message

    results = []
    software_name_lower = software_name.lower()

    for cve_id, cve_details in db.items():
        # Check if software name is in the description or affected software list
        description_lower = cve_details.get("description", "").lower()
        affected_software = cve_details.get("affected_software", [])
        affected_found = False
        for affected in affected_software:
            if software_name_lower in affected.lower():
                # If version is provided, check for version match
                if version:
                    if version.lower() in affected.lower(): # Simple version match
                        affected_found = True
                        break
                else:
                    affected_found = True
                    break

        if software_name_lower in description_lower or affected_found:
            # Filter results to include relevant details
            result_cve = {
                "cve_id": cve_id,
                "description": cve_details.get("description", "N/A"),
                "severity": cve_details.get("severity", "Unknown"),
                "affected_software": cve_details.get("affected_software", []),
                "references": cve_details.get("references", [])
            }
            results.append(result_cve)
    return results

# Example Usage:
if __name__ == "__main__":
    # Create a dummy CVE database if it doesn't exist for testing
    if not os.path.exists(os.path.join(os.path.dirname(__file__), "..", "assets")):
        os.makedirs(os.path.join(os.path.dirname(__file__), "..", "assets"))

    if not os.path.exists(CVE_DATABASE_PATH):
        dummy_cve_data = {
            "CVE-2023-1234": {
                "description": "Vulnerability in Web Server X allowing remote code execution.",
                "severity": "High",
                "affected_software": ["Web Server X 1.0", "Web Server X 1.1"],
                "references": ["http://example.com/cve-2023-1234"]
            },
            "CVE-2023-5678": {
                "description": "Buffer overflow in IoT Device Firmware Y leading to denial of service.",
                "severity": "Medium",
                "affected_software": ["IoT Device Firmware Y 2.0.0", "IoT Device Firmware Y 2.0.1"],
                "references": ["http://example.com/cve-2023-5678"]
            },
            "CVE-2022-9999": {
                "description": "Cross-site scripting (XSS) in Admin Panel Z.",
                "severity": "Low",
                "affected_software": ["Admin Panel Z 1.0.0"],
                "references": ["http://example.com/cve-2022-9999"]
            },
            "CVE-2024-0001": {
                "description": "Authentication bypass in Router OS A version 1.0.0.",
                "severity": "High",
                "affected_software": ["Router OS A 1.0.0"],
                "references": ["http://example.com/cve-2024-0001"]
            }
        }
        with open(CVE_DATABASE_PATH, 'w', encoding='utf-8') as f:
            json.dump(dummy_cve_data, f, indent=4)
        print(f"Created dummy CVE database at {CVE_DATABASE_PATH}")

    print("\n--- Searching for 'Web Server X' ---")
    results = search_cve("Web Server X")
    if results:
        for res in results:
            print(f"  CVE ID: {res['cve_id']}")
            print(f"    Severity: {res['severity']}")
            print(f"    Description: {res['description']}")
            print(f"    Affected Software: {res['affected_software']}")
            print(f"    References: {res['references']}")
    else:
        print("  No CVEs found for 'Web Server X'.")

    print("\n--- Searching for 'IoT Device Firmware Y' version '2.0.0' ---")
    results = search_cve("IoT Device Firmware Y", version="2.0.0")
    if results:
        for res in results:
            print(f"  CVE ID: {res['cve_id']}")
            print(f"    Severity: {res['severity']}")
            print(f"    Description: {res['description']}")
            print(f"    Affected Software: {res['affected_software']}")
            print(f"    References: {res['references']}")
    else:
        print("  No CVEs found for 'IoT Device Firmware Y' version '2.0.0'.")

    print("\n--- Searching for non-existent software ---")
    results = search_cve("NonExistentSoftware")
    if results:
        for res in results:
            print(f"  CVE ID: {res['cve_id']}")
    else:
        print("  No CVEs found for 'NonExistentSoftware'.")
