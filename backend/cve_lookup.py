import requests


def lookup_cves(service, version):

    if not service or not version or version == "-":
        return []

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "keywordSearch": f"{service} {version}",
            "resultsPerPage": 5
        }

        response = requests.get(
            url,
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            print("CVE API ERROR:", response.status_code)
            return []

        data = response.json()

        cves = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get("id", "")

            description = ""

            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            cvss_score = None

            metrics = cve.get("metrics", {})

            # CVSS v3.1
            cvss31 = metrics.get("cvssMetricV31", [])

            if cvss31:
                cvss_score = cvss31[0].get(
                    "cvssData", {}
                ).get("baseScore")

            # CVSS v3.0 fallback
            if cvss_score is None:

                cvss30 = metrics.get("cvssMetricV30", [])

                if cvss30:
                    cvss_score = cvss30[0].get(
                        "cvssData", {}
                    ).get("baseScore")

            cves.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score
            })

        print("CVE results found:", len(cves))

        return cves

    except requests.RequestException as e:

        print("CVE NETWORK ERROR:", e)

        return []

    except Exception as e:

        print("CVE LOOKUP ERROR:", e)

        return []