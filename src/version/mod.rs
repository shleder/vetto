//! Release engineering, version banners, upgrade detection, and channel management.

pub mod checker;
pub mod config;
pub mod parser;
pub mod upgrade;

pub use checker::{
    check_version, print_banner_if_update_available, resolve_cache_path, UpdateNotice,
    VersionCache, CACHE_TTL_SECS, CHECK_TIMEOUT,
};
pub use config::{auto_update_enabled, load_user_config, UserConfig};
pub use parser::{parse_registry_version, SemVer};
pub use upgrade::{
    apply_pending_staged_update, binary_archive_url, detect_install_method, run_rollback,
    run_upgrade, stage_update, InstallMethod,
};
