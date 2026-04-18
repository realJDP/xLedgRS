use super::*;

impl Node {
    pub(super) async fn run_resource_manager_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.is_shutting_down() {
                info!("resource manager loop: shutdown");
                return;
            }

            {
                let mut state = self.state.write().await;
                state
                    .services
                    .resource_manager
                    .periodic_activity(std::time::Instant::now());
            }

            self.update_rpc_snapshot().await;
        }
    }
}
