use super::PublishMode;

#[allow(dead_code)]
pub enum StreamState {
    Created,

    Publishing {
        stream_key: String,
        mode: PublishMode,
    },

    Playing {
        stream_key: String,
    },

    Completed,
}

pub struct ActiveStream {
    pub current_state: StreamState,
}
