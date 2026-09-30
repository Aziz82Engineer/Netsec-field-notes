# Runbook: site-to-site IPsec tunnel down or one selector unreachable

Use this to confirm VPN-001, VPN-002 or VPN-004 on the live FortiGate before changing anything. Replace the values in `<>`.

## 1. Tunnel and SA state

```
get vpn ipsec tunnel summary
diagnose vpn tunnel list name <PHASE1_NAME>
```

For each phase 2, check that an SA exists and compare the `enc` and `dec` counters. `enc` rising while `dec` stays at 0 means the FortiGate sends into an SA the peer no longer has.

## 2. Bring up the phase 2 manually

```
diagnose vpn tunnel up <PHASE2_NAME> <PHASE1_NAME>
```

## 3. Packet sniffer

```
diagnose sniffer packet any 'host <REMOTE_IP> and icmp' 4 0 l
```

Ping from the local server while it runs.

## 4. Debug flow

```
diagnose debug reset
diagnose debug flow filter clear
diagnose debug flow filter addr <REMOTE_IP>
diagnose debug flow filter proto 1
diagnose debug flow show function-name enable
diagnose debug console timestamp enable
diagnose debug flow trace start 50
diagnose debug enable
```

Look for `No matching IPsec selector, drop`. If the policy allows the traffic, check that NAT is not enabled on the outbound VPN policy.

## 5. IKE debug

```
diagnose debug reset
diagnose vpn ike log filter clear
diagnose vpn ike log filter rem-addr4 <PEER_PUBLIC_IP>
diagnose debug application ike -1
diagnose debug console timestamp enable
diagnose debug enable
```

On FortiOS 7.2 and earlier the filter syntax is `diagnose vpn ike log-filter dst-addr4 <PEER_PUBLIC_IP>`.

Look for `no matching proposal`, `TS unacceptable` or `INVALID_ID_INFORMATION`. Any of these means the peer's selectors (for example a Cisco crypto ACL) do not match this phase 2.

## 6. Stop debugging

```
diagnose debug disable
diagnose debug reset
```

## Reference

- Fortinet Community: Troubleshooting IPsec site-to-site tunnel connectivity
  https://community.fortinet.com/fortigate-3/troubleshooting-tip-troubleshooting-ipsec-site-to-site-tunnel-connectivity-97517
