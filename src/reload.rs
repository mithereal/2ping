use crate::config::{AppConfigFile, KeyringFile};
use crate::crypto::{AuthDigest, EncryptMethod, SecurityConfig};
use crate::engine::TargetSpec;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Clone)]
pub struct RuntimeControls {
    pub security: Arc<RwLock<SecurityConfig>>,
    pub targets: Arc<RwLock<Vec<TargetSpec>>>,
}

pub struct ReloadSpec {
    pub config_path: Option<PathBuf>,
    pub keyring_path: Option<PathBuf>,
    pub cli_active_key_id: Option<String>,
    pub cli_auth: Option<String>,
    pub cli_encrypt: Option<String>,
    pub digest: AuthDigest,
    pub encrypt_method: EncryptMethod,
    pub default_port: u16,
    pub use_srv: bool,
    pub cli_hosts_override: bool,
    pub quiet: bool,
    pub json_output: bool,
}

pub fn spawn_hot_reloader(controls: RuntimeControls, spec: ReloadSpec) {
    if spec.config_path.is_none() && spec.keyring_path.is_none() {
        return;
    }

    let (tx, mut rx) = mpsc::channel::<()>(8);

    let file_tx = tx.clone();
    let cfg_path = spec.config_path.clone();
    let kr_path = spec.keyring_path.clone();

    std::thread::spawn(move || {
        let mut watcher: RecommendedWatcher = match notify::recommended_watcher(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        let _ = file_tx.blocking_send(());
                    }
                }
            },
        ) {
            Ok(w) => w,
            Err(_) => return,
        };

        if let Some(ref p) = cfg_path {
            let _ = watcher.watch(p, RecursiveMode::NonRecursive);
        }
        if let Some(ref p) = kr_path {
            let _ = watcher.watch(p, RecursiveMode::NonRecursive);
        }

        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });

    #[cfg(unix)]
    {
        let sig_tx = tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                while sighup.recv().await.is_some() {
                    let _ = sig_tx.send(()).await;
                }
            }
        });
    }

    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            while rx.try_recv().is_ok() {}

            if let Err(e) = apply_reload(&controls, &spec).await {
                if !spec.quiet && !spec.json_output {
                    eprintln!("Hot-reload failed (keeping active config): {}", e);
                }
            } else if !spec.quiet && !spec.json_output {
                let active_id = controls.security.read().await.active_key_id.clone();
                let target_count = controls.targets.read().await.len();
                println!(
                    "Reloaded configuration & keyring (active_key_id={}, targets={})",
                    active_id, target_count
                );
            }
        }
    });
}

async fn apply_reload(
    controls: &RuntimeControls,
    spec: &ReloadSpec,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file_cfg = match &spec.config_path {
        Some(p) => AppConfigFile::load(p).map_err(|e| e.to_string())?,
        None => AppConfigFile::default(),
    };

    let new_security = if let Some(kr_path) = &spec.keyring_path {
        let kr = KeyringFile::load(kr_path).map_err(|e| e.to_string())?;
        let active_id = spec
            .cli_active_key_id
            .as_deref()
            .or(kr.active_key_id.as_deref());
        SecurityConfig::from_keyring(&kr.keys, active_id, spec.digest, spec.encrypt_method)
            .map_err(|e| e.to_string())?
    } else if !file_cfg.keys.is_empty() {
        let active_id = spec
            .cli_active_key_id
            .as_deref()
            .or(file_cfg.active_key_id.as_deref());
        SecurityConfig::from_keyring(&file_cfg.keys, active_id, spec.digest, spec.encrypt_method)
            .map_err(|e| e.to_string())?
    } else {
        SecurityConfig::new(
            spec.cli_auth.as_deref(),
            spec.digest,
            spec.cli_encrypt.as_deref(),
            spec.encrypt_method,
        )
    };

    {
        let mut sec_guard = controls.security.write().await;
        *sec_guard = new_security;
    }

    if !spec.cli_hosts_override {
        if let Some(new_hosts) = file_cfg.targets {
            if !new_hosts.is_empty() {
                let port = file_cfg.port.unwrap_or(spec.default_port);
                let resolved = crate::resolve_targets_public(&new_hosts, port, spec.use_srv)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut targets_guard = controls.targets.write().await;
                *targets_guard = resolved;
            }
        }
    }

    Ok(())
}