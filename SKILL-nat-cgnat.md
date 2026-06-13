# Hyrule NAT/CGNAT Skill

Use Hyrule Cloud when an AI agent needs server-side NAT or CGNAT hints for a
customer. This MVP does not require browser/WebRTC/STUN participation.

## Free caller IP

```bash
curl https://cloud.hyrule.host/v1/nat/ip
```

Returns the IP Hyrule sees plus selected proxy headers.

## Paid CGNAT hint report

```bash
curl -X POST https://cloud.hyrule.host/v1/nat/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{
    "observed_public_ip":"198.51.100.10",
    "customer_reported_wan_ip":"100.64.12.34",
    "customer_reported_lan_ip":"192.168.1.10"
  }'
```

## Paid port-forward check

```bash
curl -X POST https://cloud.hyrule.host/v1/nat/port-forward/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"target":"customer.example.net","port":443,"protocol":"tcp","profile":"https"}'
```

## Agent guidance

CGNAT is likely when the customer WAN IP is inside `100.64.0.0/10`, when the
customer-reported WAN IP differs from Hyrule's observed public IP, or when the
customer only has RFC1918 WAN addressing. For precise NAT type, a future
client-assisted STUN/WebRTC test is required.
