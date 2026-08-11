# beta9 VoLTE/IMS SMS reverse-engineering specification

This document records behavior observed from the supplied `simadmin 1.1.6-beta9`
binary and from the attached UFI001CT device. It is an implementation contract,
not recovered source code.

## Binary evidence

The AArch64 binary contains Rust compilation paths for these relevant modules:

- `src/volte.rs`
- `src/ims_sms.rs`
- `src/ims_uim.rs`
- `src/secondary_qmi.rs`
- `src/secondary_qmi_data.rs`
- `src/managed_mm_data.rs`

Relevant diagnostic families include `volte_data6_*`, `volte_ipsec_*`,
`volte_register_*`, `volte_usim_aka_*`, `secondary_qmi_*`, and
`managed_mm_data_*`. The binary also contains 3GPP IMS SMS content markers,
SIP registration strings, P-CSCF handling, and Linux XFRM/IPsec terminology.

## Observed runtime topology

The device uses two independent data paths:

| Purpose | Control path | Network interface | Address family |
| --- | --- | --- | --- |
| ordinary data | primary QMI `/dev/wwan0qmi0` | `wwan0` | IPv4/IPv6 |
| IMS/VoLTE SMS | secondary DATA6 QMI `/dev/wwan0at2` | `wwan1` | IPv6 |

The primary bearer remains on APN `ctnet`. Enabling VoLTE creates an IMS
bearer on DATA6 and leaves the primary bearer in place.

## IMS registration sequence

Observed beta9 log sequence:

1. Load IMS identity and SMSC for IMSI prefix `46011`.
2. Allocate IMS to DATA6 while reserving primary QMI for ordinary data.
3. Start the secondary QMI IMS WDS bearer and obtain an IPv6 address.
4. Discover two P-CSCF candidates from the active IMS bearer.
5. Read the USIM AID and perform IMS-AKA material preparation.
6. Install Linux XFRM transport policies/states for the P-CSCF endpoint.
7. Send IMS SIP `REGISTER` through the protected channel.
8. Treat a SIP `200 OK` with the associated URI, service route, and path as
   registered.

On the attached device the successful registration used:

- local IMS address on `wwan1`: `240e:55b:698:8cb5:1543:ecfc:ee2a:f2f5`
- P-CSCF: `240e:66:c000:400f::1`
- ESP transport mode
- protected SIP ports negotiated by the runtime

## IMS SMS receive path

The device database records received messages with:

- `transport = volte_ims`
- `status = received`
- `pdu = volte-mt:<dedupe marker>`

ModemManager's SMS object list remains empty, which shows that beta9's native
IMS SMS runtime consumes the message before the regular ModemManager SMS
listener can expose it. The binary contains `src/ims_sms.rs`,
`volte_sms_message_sip_*`, and `application/vnd.3gpp.sms` markers.

The reconstructed receive path is therefore:

```text
IMS bearer -> P-CSCF/IPsec -> SIP IMS SMS payload -> 3GPP SMS PDU decode
           -> deduplicate -> sms_messages (transport=volte_ims)
```

## Compatibility requirements

The implementation must preserve these invariants:

- ordinary data remains on the primary bearer while IMS is enabled;
- IMS uses DATA6 when a secondary endpoint is available;
- IMS registration failure must not tear down the ordinary data bearer;
- SMS deduplication must occur before database insertion;
- ModemManager SMS polling must remain a fallback, not the IMS SMS source;
- all modem state-changing operations must use the repository's serial modem
  operation guard.

## Evidence boundary

The supplied binary is stripped and does not contain recoverable original Rust
function bodies or source-level names beyond compilation paths and diagnostic
strings. SIP/IPsec packet construction and QMI message encoding must therefore
be reimplemented from observed behavior and 3GPP/QMI interfaces, then verified
on the attached device.
