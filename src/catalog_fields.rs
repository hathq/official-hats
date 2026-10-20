// Hatter downstream 2026: verifier separated from operational catalog and trust defaults.
use crate::LocalizedText;

pub(crate) fn version(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = (0..3).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    valid && parts.next().is_none()
}

pub(crate) fn localized(value: &LocalizedText) -> bool {
    !value.name.trim().is_empty()
        && value.name.len() <= 100
        && !value.summary.trim().is_empty()
        && value.summary.len() <= 300
}

pub(crate) fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

pub(crate) fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn residence_scopes(values: &[String]) -> bool {
    values.len() <= 64
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| {
            let mut parts = value.split('-');
            parts.next().is_some_and(|country| {
                country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())
            }) && parts.next().is_none_or(|area| {
                !area.is_empty()
                    && area.len() <= 3
                    && area
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                    && parts.next().is_none()
            })
        })
}

#[cfg(test)]
mod tests {
    use super::residence_scopes;

    #[test]
    fn residence_scopes_are_sorted_unique_iso_style_codes() {
        assert!(residence_scopes(&["JP".into(), "JP-13".into()]));
        assert!(!residence_scopes(&["JP-13".into(), "JP".into()]));
        assert!(!residence_scopes(&["jp".into()]));
        assert!(!residence_scopes(&["JP-1234".into()]));
    }
}
