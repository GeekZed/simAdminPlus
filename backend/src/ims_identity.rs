//! IMS identity derivation for native VoLTE registration.

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomePlmn {
    pub mcc: String,
    pub mnc: String,
    pub mnc_length_source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsIdentity {
    pub private_identity: String,
    pub public_identity: String,
    pub home_domain: String,
}

pub fn resolve_home_plmn(
    imsi: &str,
    registered_operator: Option<&str>,
    ef_ad_mnc_length: Option<usize>,
) -> Result<HomePlmn> {
    let matching_operator_length = registered_operator
        .filter(|operator| {
            matches!(operator.len(), 5 | 6)
                && operator.bytes().all(|byte| byte.is_ascii_digit())
                && imsi.starts_with(*operator)
        })
        .map(|operator| operator.len() - 3);

    let (mnc_length, source) = if let Some(length) = matching_operator_length {
        (length, "modemmanager_home_operator")
    } else if let Some(length @ (2 | 3)) = ef_ad_mnc_length {
        (length, "sim_ef_ad")
    } else if imsi.starts_with("460") {
        (2, "china_compatibility_fallback")
    } else {
        (3, "three_digit_fallback")
    };
    let (mcc, mnc) = split_imsi(imsi, mnc_length)?;
    Ok(HomePlmn {
        mcc,
        mnc,
        mnc_length_source: source,
    })
}

pub fn split_imsi(imsi: &str, mnc_length: usize) -> Result<(String, String)> {
    if !matches!(mnc_length, 2 | 3)
        || imsi.len() < 3 + mnc_length
        || !imsi.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(anyhow!("IMS identity requires a valid IMSI and MNC length"));
    }
    Ok((imsi[..3].to_string(), imsi[3..3 + mnc_length].to_string()))
}

pub fn home_domain(mcc: &str, mnc: &str) -> String {
    format!("ims.mnc{:0>3}.mcc{mcc}.3gppnetwork.org", mnc)
}

pub fn derive_identity(imsi: &str, home_plmn: &HomePlmn) -> ImsIdentity {
    let home_domain = home_domain(&home_plmn.mcc, &home_plmn.mnc);
    ImsIdentity {
        private_identity: format!("{imsi}@{home_domain}"),
        public_identity: format!("sip:{imsi}@{home_domain}"),
        home_domain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_china_telecom_two_digit_mnc() {
        let home = resolve_home_plmn("460111234567890", Some("46011"), None).unwrap();
        assert_eq!(home.mcc, "460");
        assert_eq!(home.mnc, "11");
        assert_eq!(home.mnc_length_source, "modemmanager_home_operator");
        assert_eq!(
            derive_identity("460111234567890", &home),
            ImsIdentity {
                private_identity: "460111234567890@ims.mnc011.mcc460.3gppnetwork.org".into(),
                public_identity: "sip:460111234567890@ims.mnc011.mcc460.3gppnetwork.org".into(),
                home_domain: "ims.mnc011.mcc460.3gppnetwork.org".into(),
            }
        );
    }

    #[test]
    fn registered_visited_network_does_not_override_home_plmn() {
        let home = resolve_home_plmn("460111234567890", Some("00101"), None).unwrap();
        assert_eq!(home.mnc, "11");
        assert_eq!(home.mnc_length_source, "china_compatibility_fallback");
    }

    #[test]
    fn ef_ad_supports_three_digit_mnc() {
        let home = resolve_home_plmn("310260123456789", None, Some(3)).unwrap();
        assert_eq!(home.mcc, "310");
        assert_eq!(home.mnc, "260");
        assert_eq!(home.mnc_length_source, "sim_ef_ad");
    }

    #[test]
    fn rejects_invalid_imsi() {
        assert!(resolve_home_plmn("4601x", None, None).is_err());
    }
}
