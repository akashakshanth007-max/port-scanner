import nmap
from cve_lookup import lookup_cves


# ============================================================
# RISK + SECURITY RECOMMENDATION
# ============================================================

def get_risk(port, service):

    service = (service or "").lower()

    # High Risk Ports
    if port in [21, 23, 445, 3389]:

        if port == 21:
            return (
                "High",
                "FTP is open. Use SFTP/FTPS or restrict access if FTP is not required."
            )

        if port == 23:
            return (
                "High",
                "Telnet is insecure. Disable Telnet and use SSH instead."
            )

        if port == 445:
            return (
                "High",
                "SMB is open. Restrict access to trusted networks and disable it if unnecessary."
            )

        if port == 3389:
            return (
                "High",
                "RDP is open. Restrict access to trusted networks and use strong authentication."
            )

    # Medium Risk Ports
    if port in [135, 139, 5000, 8080, 8000, 9080]:

        if port == 135:
            return (
                "Medium",
                "MSRPC is open. Review the service and restrict access if it is not required."
            )

        if port == 139:
            return (
                "Medium",
                "NetBIOS is open. Restrict access and disable it if it is not required."
            )

        if port in [5000, 8080, 8000]:
            return (
                "Medium",
                "A development web service is open. Restrict access if it is not required."
            )

        if port == 9080:
            return (
                "Medium",
                "The gRPC service is open. Review the service and restrict access if it is not required."
            )

    # Low Risk
    if port == 22 or service == "ssh":
        return (
            "Low",
            "SSH is open. Use strong authentication and restrict access to trusted networks."
        )

    if port in [80, 443] or service in ["http", "https"]:
        return (
            "Low",
            "Web service is open. Keep the service updated and restrict access when possible."
        )

    # Default
    return (
        "Low",
        "Review this service and close the port if it is not required."
    )


# ============================================================
# SCAN TARGET
# ============================================================

def scan_target(target):

    scanner = nmap.PortScanner()

    print("=" * 60)
    print("Starting Nmap scan:", target)
    print("=" * 60)

    # Scan all TCP ports + service/version detection
    scanner.scan(
        target,
        arguments="-p- -sV -T4"
    )

    results = []

    # ========================================================
    # PROCESS SCAN RESULTS
    # ========================================================

    for host in scanner.all_hosts():

        print("Host found:", host)

        for protocol in scanner[host].all_protocols():

            print("Protocol:", protocol)

            ports = scanner[host][protocol].keys()

            for port in sorted(ports):

                port_data = scanner[host][protocol][port]

                state = port_data.get(
                    "state",
                    "unknown"
                )

                service = port_data.get(
                    "name",
                    "-"
                )

                product = port_data.get(
                    "product",
                    ""
                )

                version = port_data.get(
                    "version",
                    ""
                )

                # ====================================================
                # BUILD DISPLAY VERSION
                # ====================================================

                if product and version:

                    display_version = f"{product} {version}"

                elif version:

                    display_version = version

                elif product:

                    display_version = product

                else:

                    display_version = "-"

                # ====================================================
                # RISK
                # ====================================================

                risk, recommendation = get_risk(
                    port,
                    service
                )

                # ====================================================
                # CVE LOOKUP
                # ====================================================

                cves = lookup_cves(
                    service,
                    display_version
                )

                # ====================================================
                # RESULT
                # ====================================================

                result = {

                    "port": port,

                    "state": state,

                    "service": service,

                    "version": display_version,

                    "risk": risk,

                    "recommendation": recommendation,

                    "cves": cves

                }

                results.append(result)

                # ====================================================
                # TERMINAL OUTPUT
                # ====================================================

                print(
                    f"Port: {port} | "
                    f"State: {state} | "
                    f"Service: {service} | "
                    f"Version: {display_version} | "
                    f"Risk: {risk}"
                )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    print("=" * 60)
    print("Scan completed.")
    print("Total results:", len(results))
    print("=" * 60)

    return results