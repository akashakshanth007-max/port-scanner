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

    # ========================================================
    # DEBUG LOG
    # ========================================================

    print("================================", flush=True)
    print("SCAN FUNCTION CALLED", flush=True)
    print("Target:", target, flush=True)
    print("================================", flush=True)


    # ========================================================
    # CREATE NMAP SCANNER
    # ========================================================

    try:

        scanner = nmap.PortScanner()

        print(
            "Nmap PortScanner initialized successfully.",
            flush=True
        )

    except Exception as error:

        print(
            "ERROR INITIALIZING NMAP:",
            str(error),
            flush=True
        )

        raise


    # ========================================================
    # START NMAP SCAN
    # ========================================================

    print("================================", flush=True)
    print("Starting Nmap scan:", target, flush=True)

    print(
        "Scan arguments: -p- -sT -sV -T4 -Pn",
        flush=True
    )

    print("================================", flush=True)


    try:

        # Scan all TCP ports
        # Detect service/version
        # Skip host discovery

        scanner.scan(
            target,
            arguments="-p- -sT -sV -T4 -Pn"
        )


        # ====================================================
        # NMAP DEBUG OUTPUT
        # ====================================================

        print(
            "Nmap scan command completed.",
            flush=True
        )

        print("================================", flush=True)

        print(
            "NMAP COMMAND:",
            scanner.command_line(),
            flush=True
        )

        print(
            "NMAP SCAN INFO:",
            scanner.scaninfo(),
            flush=True
        )

        print(
            "NMAP RAW OUTPUT:",
            scanner.get_nmap_last_output(),
            flush=True
        )

        print("================================", flush=True)


    except Exception as error:

        print(
            "NMAP SCAN ERROR:",
            str(error),
            flush=True
        )

        raise


    # ========================================================
    # RESULTS
    # ========================================================

    results = []


    # ========================================================
    # GET HOSTS
    # ========================================================

    hosts = scanner.all_hosts()

    print("================================", flush=True)

    print(
        "Hosts found:",
        hosts,
        flush=True
    )

    print(
        "Total hosts:",
        len(hosts),
        flush=True
    )

    print("================================", flush=True)


    # ========================================================
    # PROCESS HOSTS
    # ========================================================

    for host in hosts:

        print(
            "Host found:",
            host,
            flush=True
        )


        # ====================================================
        # HOST STATE
        # ====================================================

        try:

            host_state = scanner[host].state()

            print(
                "Host state:",
                host_state,
                flush=True
            )

        except Exception as error:

            print(
                "Unable to get host state:",
                str(error),
                flush=True
            )


        # ====================================================
        # GET PROTOCOLS
        # ====================================================

        protocols = scanner[host].all_protocols()

        print(
            "Protocols found:",
            protocols,
            flush=True
        )


        # ====================================================
        # PROCESS PROTOCOLS
        # ====================================================

        for protocol in protocols:

            print(
                "Protocol:",
                protocol,
                flush=True
            )


            ports = scanner[host][protocol].keys()

            print(
                "Ports found:",
                list(ports),
                flush=True
            )


            # ====================================================
            # PROCESS PORTS
            # ====================================================

            for port in sorted(ports):

                port_data = scanner[host][protocol][port]


                # ====================================================
                # PORT INFORMATION
                # ====================================================

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

                    display_version = (
                        f"{product} {version}"
                    )

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

                try:

                    cves = lookup_cves(
                        service,
                        display_version
                    )

                except Exception as error:

                    print(
                        "CVE lookup error:",
                        str(error),
                        flush=True
                    )

                    cves = []


                # ====================================================
                # CREATE RESULT
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
                # LOG PORT RESULT
                # ====================================================

                print(
                    f"Port: {port} | "
                    f"State: {state} | "
                    f"Service: {service} | "
                    f"Version: {display_version} | "
                    f"Risk: {risk}",
                    flush=True
                )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    print("================================", flush=True)

    print(
        "Scan completed.",
        flush=True
    )

    print(
        "Total results:",
        len(results),
        flush=True
    )

    print("================================", flush=True)


    return results
