from dotenv import load_dotenv
import os
load_dotenv()
import scanners.dns as dns
import scanners.tls_certs as tls_certs
import scanners.tls_config as tls_config
import scanners.was as was
import scanners.ports as ports
import scanners.email as email
import re
import ipaddress

def display_banner():
    print("========================================")
    print("                AEGIS            ")
    print("                 v0.7 ")
    print("========================================")

def parse_port(port_str):
    """Validates if the provided string is a valid port number (1-65535)."""
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    return None

def validate_and_identify_target(user_input):
    """Parses input into (host, type, port).

    Supports formats like:
    - google.com
    - google.com:8443
    - 8.8.8.8
    - 8.8.8.8:8080
    """
    clean_input = user_input.strip().lower()

    if clean_input.startswith(("http://", "https://")):
        clean_input = clean_input.split("://", 1)[1]

    if "/" in clean_input:
        clean_input = clean_input.split("/", 1)[0]
    if not clean_input:
        return None, None, None

    host = clean_input
    port = None

    if ":" in clean_input:
        if clean_input.startswith("[") and "]:" in clean_input:
            host_part, port_part = clean_input.rsplit("]:", 1)
            host = host_part.lstrip("[")
        elif clean_input.count(":") == 1:
            host, port_part = clean_input.split(":")
        else:
            port_part = None

        if "port_part" in locals() and port_part:
            port = parse_port(port_part)
            if port is None:
                print(
                    f"[!] Invalid port '{port_part}'. Port must be an integer between 1 and 65535."
                )
                return None, None, None

    try:
        ip_obj = ipaddress.ip_address(host)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            print("[!] Only public IP addresses are allowed.")
            return None, None, None
        return host, "IP Address", port
    except ValueError:
        pass

    domain_pattern = (
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if re.match(domain_pattern, host):
        return host, "Domain", port

    print(
        "[!] Invalid format. Please enter a valid public IP or Domain name (e.g., 8.8.8.8, 8.8.8.8:8080, or google.com:443)."
    )
    return None, None, None


def get_target_input():
    while True:
        print("\n--- Target Input ---")
        user_input = (
            input(
                "Enter Target (Domain / Public IP [optional :port]) or 'q' to exit: "
            )
            .strip()
            .lower()
        )

        if user_input == "q":
            print("\nExiting program. Goodbye!")
            exit()

        target_value, target_type, target_port = validate_and_identify_target(
            user_input
        )
        if target_value:
            print("\n--- Target Selected ---")
            print(f"Type:  {target_type}")
            print(f"Value: {target_value}")
            print(f"Port:  {target_port if target_port else 'Not specified'}")
            print("========================================")
            return target_value, target_type, target_port


def prompt_for_port(default_port=None):
    """Prompts the user to enter a port if none was initially specified."""
    prompt_msg = (
        f"Enter target port [{default_port}]: "
        if default_port
        else "Enter target port: "
    )
    while True:
        val = input(prompt_msg).strip()
        if not val and default_port:
            return default_port
        port = parse_port(val)
        if port:
            return port
        print("[!] Invalid port. Enter a number between 1 and 65535.")


def sub_menu(target_value, target_type, target_port):
    current_port = target_port

    while True:
        port_display = f":{current_port}" if current_port else ""
        print("--- Assessment Menu ---")
        print("1. SSL Certificates - WiP")
        print("2. SSL Configurations")
        print("3. Web Application Security")
        print("4. Open Ports - WiP")
        print("5. SPF / DKIM / DMARC")
        print("6. Graph PDNS")
        print("7. Full Scan - WiP")
        print("0. Change Target (New Domain/IP)")
        print("q. Quit")

        choice = input("Select an option: ").strip().lower()

        if choice == "1":
            port_to_use = current_port or prompt_for_port(default_port=443)
            tls_certs.run(target_value, port=port_to_use)

        elif choice == "2":
            port_to_use = current_port or prompt_for_port(default_port=443)
            tls_config.run(target_value, port=port_to_use)

        elif choice == "3":
            port_to_use = current_port or prompt_for_port(default_port=443)
            was.run(target_value, port=port_to_use)

        elif choice == "4":
            port_to_use = current_port or prompt_for_port(default_port=80)
            ports.run(target_value, port=port_to_use)

        elif choice == "5":
            email.run(target_value, target_type)

        elif choice == "6":
            dns.run(target_value, target_type)

        elif choice == "7":
            print("\n[*] Launching Full Suite Assessment...")
            port_to_use = current_port or prompt_for_port(default_port=443)
            dns.run(target_value, target_type)
            tls_certs.run(target_value, port=port_to_use)
            tls_config.run(target_value, port=port_to_use)
            was.run(target_value, port=port_to_use)
            ports.run(target_value, port=port_to_use)
            email.run(target_value, target_type)

        elif choice == "0":
            break

        elif choice == "q":
            print("\nExiting program. Goodbye!")
            exit()

        else:
            print("\n[!] Invalid choice. Please select a valid option.")
            continue

        print("\n" + "=" * 40)
        print("Scan execution finished.")
        print("1. Run another tool on CURRENT target")
        print("2. Scan a NEW Domain / IP")
        print("q. Quit Aegis")
        print("=" * 40)

        after_action = input("What would you like to do? ").strip().lower()
        if after_action == "q":
            print("\nExiting program. Goodbye!")
            exit()
        elif after_action == "2":
            break
        elif after_action == "1":
            print("\nReloading modules menu...")


def main():
    display_banner()
    while True:
        target_value, target_type, target_port = get_target_input()
        sub_menu(target_value, target_type, target_port)


if __name__ == "__main__":
    main()