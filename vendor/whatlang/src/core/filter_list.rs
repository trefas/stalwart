use crate::Lang;

#[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default)]
pub enum FilterList {
    #[default]
    All,
    Allow(Vec<Lang>),
    Deny(Vec<Lang>),
}

impl FilterList {
    #[cfg(feature = "dev")]
    pub fn all() -> Self {
        Self::All
    }

    pub fn allow(allowlist: Vec<Lang>) -> Self {
        Self::Allow(allowlist)
    }

    pub fn deny(denylist: Vec<Lang>) -> Self {
        Self::Deny(denylist)
    }

    pub fn is_allowed(&self, lang: Lang) -> bool {
        match self {
            Self::All => true,
            Self::Allow(ref allowlist) => allowlist.contains(&lang),
            Self::Deny(ref denylist) => !denylist.contains(&lang),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "dev")]
    fn test_all() {
        let list = FilterList::all();
        assert!(list.is_allowed(Lang::Epo));
    }

    #[test]
    fn test_only() {
        let list = FilterList::allow(vec![Lang::Rus, Lang::Ukr]);

        assert!(!list.is_allowed(Lang::Epo));
        assert!(!list.is_allowed(Lang::Eng));

        assert!(list.is_allowed(Lang::Rus));
        assert!(list.is_allowed(Lang::Ukr));
    }

    #[test]
    fn test_except() {
        let list = FilterList::deny(vec![Lang::Rus, Lang::Ukr]);

        assert!(list.is_allowed(Lang::Epo));
        assert!(list.is_allowed(Lang::Eng));

        assert!(!list.is_allowed(Lang::Rus));
        assert!(!list.is_allowed(Lang::Ukr));
    }
}
