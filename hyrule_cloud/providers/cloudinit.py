"""
Cloud-init configuration generator.

Produces a cloud-config YAML that bootstraps a bare VM with:
- Agent SSH key
- UFW firewall with specified ports
- Optional user-supplied setup script

xe-guest-utilities and cloud-init are pre-installed in the VM template.
"""

from __future__ import annotations

import yaml


def render_cloud_init(
    *,
    os_name: str = "debian-13",
    hostname: str,
    ssh_pubkey: str,
    open_ports: list[int],
    setup_script: str | None = None,
) -> str:
    """Render a cloud-init user-data document."""
    if os_name.startswith("openbsd"):
        return _render_openbsd_cloud_init(
            hostname=hostname,
            ssh_pubkey=ssh_pubkey,
            open_ports=open_ports,
            setup_script=setup_script,
        )

    return _render_debian_cloud_init(
        hostname=hostname,
        ssh_pubkey=ssh_pubkey,
        open_ports=open_ports,
        setup_script=setup_script,
    )


def _render_debian_cloud_init(
    *,
    hostname: str,
    ssh_pubkey: str,
    open_ports: list[int],
    setup_script: str | None,
) -> str:
    """Render Debian/Linux user-data."""
    ufw_commands = [
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw allow 22/tcp",
    ]
    for port in open_ports:
        if port != 22:
            ufw_commands.append(f"ufw allow {port}/tcp")
    ufw_commands.append("ufw --force enable")

    ipv6_commands = [
        "sysctl -w net.ipv6.conf.all.accept_ra=1",
        "sysctl -w net.ipv6.conf.eth0.accept_ra=1",
        "echo 'net.ipv6.conf.all.accept_ra=1' >> /etc/sysctl.d/99-ipv6.conf",
        "echo 'net.ipv6.conf.eth0.accept_ra=1' >> /etc/sysctl.d/99-ipv6.conf",
    ]

    runcmd = [
        "apt-get update -q",
        "apt-get install -y -q ufw curl git",
        *ipv6_commands,
        *ufw_commands,
    ]

    if setup_script:
        runcmd.extend([
            (
                "cat > /root/setup.sh << 'HYRULE_SETUP_EOF'\n"
                f"{setup_script}\n"
                "HYRULE_SETUP_EOF"
            ),
            "chmod +x /root/setup.sh",
            "/root/setup.sh > /var/log/hyrule-setup.log 2>&1 || true",
        ])

    cloud_config: dict = {
        "hostname": hostname,
        "manage_etc_hosts": True,
        "ssh_deletekeys": True,
        "ssh_genkeytypes": ["ed25519", "rsa"],
        "users": [
            {
                "name": "root",
                "ssh_authorized_keys": [ssh_pubkey],
            }
        ],
        "package_update": True,
        "packages": ["curl", "git", "ufw"],
        "runcmd": runcmd,
        "final_message": "Hyrule Cloud init complete",
    }

    config_yaml = yaml.dump(
        cloud_config,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )

    return f"#cloud-config\n{config_yaml}"


def _render_openbsd_cloud_init(
    *,
    hostname: str,
    ssh_pubkey: str,
    open_ports: list[int],
    setup_script: str | None,
) -> str:
    """Render OpenBSD user-data.

    OpenBSD does not use UFW. We install a small PF policy that mirrors the
    customer VM default: deny inbound except SSH and requested TCP ports.
    """
    ports = sorted({22, *open_ports})
    port_expr = "{" + ", ".join(str(port) for port in ports) + "}"
    pf_conf = f"""set skip on lo
block return in log all
pass out quick all keep state
pass in quick inet proto icmp keep state
pass in quick inet6 proto ipv6-icmp keep state
pass in quick proto tcp from any to any port {port_expr} flags S/SA keep state
"""

    runcmd = [
        "rcctl enable sshd",
        "rcctl enable pf",
        "pfctl -f /etc/pf.conf",
        "pfctl -e || true",
        "rcctl restart sshd",
    ]

    if setup_script:
        runcmd.extend([
            (
                "cat > /root/setup.sh << 'HYRULE_SETUP_EOF'\n"
                f"{setup_script}\n"
                "HYRULE_SETUP_EOF"
            ),
            "chmod +x /root/setup.sh",
            "sh /root/setup.sh > /var/log/hyrule-setup.log 2>&1 || true",
        ])

    cloud_config: dict = {
        "hostname": hostname,
        "manage_etc_hosts": True,
        "disable_root": False,
        "ssh_pwauth": False,
        "ssh_deletekeys": True,
        "ssh_genkeytypes": ["ed25519", "rsa"],
        "users": [
            {
                "name": "root",
                "ssh_authorized_keys": [ssh_pubkey],
            }
        ],
        "write_files": [
            {
                "path": "/etc/pf.conf",
                "owner": "root:wheel",
                "permissions": "0600",
                "content": pf_conf,
            }
        ],
        "runcmd": runcmd,
        "final_message": "Hyrule Cloud OpenBSD init complete",
    }

    config_yaml = yaml.dump(
        cloud_config,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )

    return f"#cloud-config\n{config_yaml}"
