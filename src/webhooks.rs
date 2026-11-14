use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: Option<String>,
    pub loss_threshold_pct: f64,
    pub rtt_threshold_ms: Option<f64>,
    pub cooldown: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: None,
            loss_threshold_pct: 5.0,
            rtt_threshold_ms: None,
            cooldown: Duration::from_secs(60),
        }
    }
}

#[derive(Serialize)]
struct WebhookPayload<'a> {
    text: String,
    service: &'a str,
    status: &'a str,
    target: &'a str,
    direction: &'a str,
    loss_pct: f64,
    avg_rtt_ms: f64,
    jitter_ms: f64,
    #[cfg(feature = "prometheus")]
    prometheus_alert: bool,
}

pub struct WebhookDispatcher {
    config: WebhookConfig,
    last_alert: Mutex<HashMap<(String, String), Instant>>,
    in_alert_state: Mutex<HashMap<(String, String), bool>>,
    #[cfg(feature = "webhooks")]
    client: Option<reqwest::Client>,
}

impl WebhookDispatcher {
    pub fn new(config: WebhookConfig) -> Self {
        #[cfg(feature = "webhooks")]
        let client = if config.url.is_some() {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .ok()
        } else {
            None
        };

        Self {
            config,
            last_alert: Mutex::new(HashMap::new()),
            in_alert_state: Mutex::new(HashMap::new()),
            #[cfg(feature = "webhooks")]
            client,
        }
    }

    pub async fn evaluate_and_notify(
        &self,
        target: &str,
        direction: &str,
        loss_pct: f64,
        avg_rtt_ms: f64,
        jitter_ms: f64,
    ) {
        #[cfg(not(feature = "webhooks"))]
        {
            let _ = (target, direction, loss_pct, avg_rtt_ms, jitter_ms);
        }

        #[cfg(feature = "webhooks")]
        {
            let Some(ref url) = self.config.url else {
                return;
            };
            let Some(ref client) = self.client else {
                return;
            };

            let rtt_breached = self
                .config
                .rtt_threshold_ms
                .map(|max_rtt| avg_rtt_ms > max_rtt)
                .unwrap_or(false);
            let loss_breached = loss_pct > self.config.loss_threshold_pct;
            let is_degraded = loss_breached || rtt_breached;

            let key = (target.to_string(), direction.to_string());
            let mut active_map = self.in_alert_state.lock().await;
            let was_degraded = *active_map.get(&key).unwrap_or(&false);

            if is_degraded {
                let mut cooldown_map = self.last_alert.lock().await;
                let now = Instant::now();
                if let Some(&last_sent) = cooldown_map.get(&key) {
                    if now.duration_since(last_sent) < self.config.cooldown {
                        return;
                    }
                }
                cooldown_map.insert(key.clone(), now);
                active_map.insert(key, true);

                let payload = WebhookPayload {
                    text: format!(
                        "[2PING ALERT] Target `{}` {} degraded: loss={:.1}%, avg_rtt={:.2}ms, jitter={:.2}ms",
                        target, direction, loss_pct, avg_rtt_ms, jitter_ms
                    ),
                    service: "2ping",
                    status: "firing",
                    target,
                    direction,
                    loss_pct,
                    avg_rtt_ms,
                    jitter_ms,
                    #[cfg(feature = "prometheus")]
                    prometheus_alert: true,
                };
                let _ = client.post(url).json(&payload).send().await;
            } else if was_degraded {
                active_map.insert(key, false);
                let payload = WebhookPayload {
                    text: format!(
                        "[2PING RESOLVED] Target `{}` {} recovered: loss={:.1}%, avg_rtt={:.2}ms",
                        target, direction, loss_pct, avg_rtt_ms
                    ),
                    service: "2ping",
                    status: "resolved",
                    target,
                    direction,
                    loss_pct,
                    avg_rtt_ms,
                    jitter_ms,
                    #[cfg(feature = "prometheus")]
                    prometheus_alert: false,
                };
                let _ = client.post(url).json(&payload).send().await;
            }
        }
    }
}