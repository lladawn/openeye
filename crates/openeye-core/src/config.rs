use crate::filter::ProcessFilter;

#[derive(Clone, Debug)]
pub struct Config {
    pub process_filter: ProcessFilter,
    pub wallet_patterns: Vec<String>,
    pub browser_profile_patterns: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            process_filter: ProcessFilter::default(),
            wallet_patterns: vec![
                "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn".into(),
                "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa".into(),
                "~/Library/Application Support/Ledger Live".into(),
                "~/Library/Application Support/Bitcoin/wallets".into(),
                "~/.ethereum/keystore".into(),
                "~/Library/Ethereum".into(),
                "~/.bitcoin".into(),
            ],
            browser_profile_patterns: vec![
                "~/Library/Application Support/Google/Chrome".into(),
                "~/Library/Application Support/Firefox/Profiles".into(),
                "~/.mozilla/firefox".into(),
            ],
        }
    }
}

