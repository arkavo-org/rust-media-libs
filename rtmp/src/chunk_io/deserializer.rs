use super::chunk_header::{ChunkHeader, ChunkHeaderFormat};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use chunk_io::ChunkDeserializationError;
use messages::MessagePayload;
use std::cmp::min;
use std::collections::HashMap;
use std::io::Cursor;
use std::mem;

const INITIAL_MAX_CHUNK_SIZE: usize = 128;
const MAX_INITIAL_TIMESTAMP: u32 = 16777215;

/// Allows deserializing bytes representing RTMP chunks into RTMP message payloads.
///
/// Due to the nature of the RTMP chunk protocol it is required that every byte going through the
/// wire is sent to the same `ChunkDeserializer` instance, as future chunks can rely on previous
/// chunks, so any chunks missing from the stream may cause deserialization errors.
pub struct ChunkDeserializer {
    max_chunk_size: usize,
    current_header_format: ChunkHeaderFormat,
    current_header: ChunkHeader,
    current_stage: ParseStage,
    current_payload: MessagePayload,
    /// Per-csid payload buffers to handle interleaved chunks correctly.
    /// RTMP allows chunks from different streams to be interleaved, so we need
    /// separate buffers for each chunk stream ID.
    csid_payload_data: HashMap<u32, BytesMut>,
    buffer: BytesMut,
    previous_headers: HashMap<u32, ChunkHeader>,
    /// Count of consecutive parse errors (for error threshold)
    consecutive_errors: u32,
}

/// Maximum consecutive errors before giving up
const MAX_CONSECUTIVE_ERRORS: u32 = 5;

enum ParsedValue<T> {
    NotEnoughBytes,
    Value { val: T, next_index: u32 },
}

enum ParseStage {
    Csid,
    InitialTimestamp,
    MessageLength,
    MessageTypeId,
    MessageStreamId,
    MessagePayload,
    ExtendedTimestamp,
}

#[derive(Eq, PartialEq, Debug)]
enum ParseStageResult {
    Success,
    NotEnoughBytes,
}

impl ChunkDeserializer {
    /// Create a new `ChunkDeserializer` with its initial properties.
    ///
    /// Per the RTMP specification an initial `ChunkDeserializer` is expecting RTMP chunks with
    /// a max size of 128 bytes.
    pub fn new() -> ChunkDeserializer {
        ChunkDeserializer {
            max_chunk_size: INITIAL_MAX_CHUNK_SIZE,
            current_header_format: ChunkHeaderFormat::Full,
            current_header: ChunkHeader::new(),
            current_stage: ParseStage::Csid,
            buffer: BytesMut::with_capacity(4096),
            previous_headers: HashMap::new(),
            current_payload: MessagePayload::new(),
            csid_payload_data: HashMap::new(),
            consecutive_errors: 0,
        }
    }

    /// Attempts to read a complete RTMP message from the passed in bytes.
    ///
    /// It is normal that one set of bytes will not form a complete RTMP message (or even a
    /// complete RTMP chunk).  Therefore it can be assumed that the deserializer will store all
    /// partial message bytes passed into it and the same bytes should not be passed in repeatedly,
    /// otherwise deserialization errors will most likely occur.
    ///
    /// If the bytes that were passed in did not form a complete RTMP message, then the bytes are
    /// added to an internal buffer for storage and `Ok(None)` is returned while it waits for
    /// the next `get_next_message()` call to complete the message.
    ///
    /// If the bytes that were passed in formed multiple RTMP messages than only the first message
    /// is deserialized and any subsequent messages are not read until the next `get_next_message()`
    /// call.
    ///
    /// This is important because if the peer sends a `SendChunkSize` message (meaning it will
    /// change the maximum size of RTMP chunks it sends) you must process that message and call
    /// the `set_max_chunk_size()` method prior to the next `get_next_message()` call.   Otherwise
    /// if the peer sends a chunk larger than the previous max chunk size the message will not be
    /// deserialized properly (and most likely errors will occur).
    ///
    /// It is expected that consumers will call `get_next_message()` in a loop until `None` is
    /// returned.  Since it is important not to keep sending it the same bytes over and over again
    /// an empty slice must be passed in for subsequent calls.
    ///
    /// ## Examples
    ///
    /// ```
    /// # extern crate bytes;
    /// # extern crate rml_rtmp;
    /// # use bytes::Bytes;
    /// # use rml_rtmp::time::RtmpTimestamp;
    /// # use rml_rtmp::chunk_io::{ChunkSerializer, ChunkDeserializer};
    /// # use rml_rtmp::messages::MessagePayload;
    /// # fn main() {
    /// let input1 = MessagePayload {
    ///     timestamp: RtmpTimestamp::new(55),
    ///     message_stream_id: 1,
    ///     type_id: 15,
    ///     data: Bytes::from(vec![1, 2, 3, 4, 5, 6]),
    /// };
    ///
    /// let input2 = MessagePayload {
    ///     timestamp: RtmpTimestamp::new(65),
    ///     message_stream_id: 1,
    ///     type_id: 15,
    ///     data: Bytes::from(vec![8, 9, 10]),
    /// };
    ///
    /// let input3 = MessagePayload {
    ///     timestamp: RtmpTimestamp::new(75),
    ///     message_stream_id: 1,
    ///     type_id: 15,
    ///     data: Bytes::from(vec![1, 2, 3]),
    /// };
    ///
    /// let mut serializer = ChunkSerializer::new();
    /// let mut packet1 = serializer.serialize(&input1, false, false).unwrap();
    /// let mut packet2 = serializer.serialize(&input2, false, false).unwrap();
    /// let mut packet3 = serializer.serialize(&input3, false, false).unwrap();
    ///
    /// let mut all_bytes = Vec::new();
    /// all_bytes.append(&mut packet1.bytes);
    /// all_bytes.append(&mut packet2.bytes);
    /// all_bytes.append(&mut packet3.bytes);
    ///
    /// let mut deserializer = ChunkDeserializer::new();
    /// let message1 = deserializer.get_next_message(&all_bytes[..]).unwrap();
    /// let message2 = deserializer.get_next_message(&[]).unwrap();
    /// let message3 = deserializer.get_next_message(&[]).unwrap();
    /// let message4 = deserializer.get_next_message(&[]).unwrap();
    ///
    /// assert_eq!(message1, Some(input1));
    /// assert_eq!(message2, Some(input2));
    /// assert_eq!(message3, Some(input3));
    /// assert_eq!(message4, None);
    /// # }
    /// ```
    pub fn get_next_message(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<MessagePayload>, ChunkDeserializationError> {
        self.buffer.extend_from_slice(bytes);

        loop {
            let mut complete_message = None;
            let result = match self.current_stage {
                ParseStage::Csid => self.form_header()?,
                ParseStage::InitialTimestamp => self.get_initial_timestamp()?,
                ParseStage::MessageLength => self.get_message_length()?,
                ParseStage::MessageTypeId => self.get_message_type_id()?,
                ParseStage::MessageStreamId => self.get_message_stream_id()?,
                ParseStage::ExtendedTimestamp => self.get_extended_timestamp()?,
                ParseStage::MessagePayload => self.get_message_data(&mut complete_message)?,
            };

            if result == ParseStageResult::NotEnoughBytes || complete_message.is_some() {
                return Ok(complete_message);
            }
        }
    }

    /// Tells the deserializer that the peer will start sending RTMP chunks with a different
    /// max chunk size.
    ///
    /// When an RTMP message is larger than the current max chunk size the serializer
    /// will split the message across multiple RTMP chunks, with each chunk only containing the number
    /// of bytes that fit into the max chunk size value.  Therefore, the sender and the receiver
    /// must be exactly in tune as to what max chunk size they are utilizing.  Any mismatch will
    /// cause errors in the deserialization process, as it will expect split chunks where there
    /// are noone, or encounter a split chunk where it wasn't expecting one.
    ///
    /// This method should almost always be called only in reaction to receiving a `SetChunkSize`
    /// message from the other end.
    pub fn set_max_chunk_size(&mut self, new_size: usize) -> Result<(), ChunkDeserializationError> {
        if new_size > 2147483647 {
            return Err(ChunkDeserializationError::InvalidMaxChunkSize {
                chunk_size: new_size,
            });
        }

        self.max_chunk_size = new_size;
        Ok(())
    }

    /// Returns the maximum size of any RTMP chunks that should be received
    pub fn get_max_chunk_size(&self) -> usize {
        self.max_chunk_size
    }

    fn form_header(&mut self) -> Result<ParseStageResult, ChunkDeserializationError> {
        if self.buffer.len() < 1 {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        self.current_header_format = get_format(&self.buffer[0]);
        let (csid, next_index) = match get_csid(&self.buffer[..]) {
            ParsedValue::NotEnoughBytes => return Ok(ParseStageResult::NotEnoughBytes),
            ParsedValue::Value { val, next_index } => (val, next_index),
        };

        self.current_header = match self.current_header_format {
            ChunkHeaderFormat::Full => {
                let mut new_header = ChunkHeader::new();
                new_header.chunk_stream_id = csid;
                // Log new chunk streams being registered (first Type 0 header)
                if !self.previous_headers.contains_key(&csid) {
                    log::debug!("RTMP: New chunk stream registered: csid={}", csid);
                }
                new_header
            }

            _ => match self.previous_headers.remove(&csid) {
                None => {
                    // Log which chunk streams ARE known when we get an unknown one
                    let known_csids: Vec<u32> = self.previous_headers.keys().copied().collect();
                    self.consecutive_errors += 1;

                    if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        log::error!(
                            "RTMP: Too many consecutive errors ({}), failing. Unknown csid {} (fmt={:?}), known csids: {:?}",
                            self.consecutive_errors,
                            csid,
                            self.current_header_format,
                            known_csids
                        );
                        return Err(ChunkDeserializationError::NoPreviousChunkOnStream { csid });
                    }

                    log::warn!(
                        "RTMP: Unknown csid {} (fmt={:?}), known csids: {:?}, error {}/{} - creating default header",
                        csid,
                        self.current_header_format,
                        known_csids,
                        self.consecutive_errors,
                        MAX_CONSECUTIVE_ERRORS
                    );

                    // Create a default header to try to continue
                    // This is a recovery attempt - the data may be corrupt but we'll try
                    let mut new_header = ChunkHeader::new();
                    new_header.chunk_stream_id = csid;
                    new_header
                }
                Some(header) => {
                    // Reset error count on successful header lookup
                    self.consecutive_errors = 0;
                    header
                }
            },
        };

        let _ = self.buffer.split_to(next_index as usize);
        self.current_stage = ParseStage::InitialTimestamp;
        Ok(ParseStageResult::Success)
    }

    fn get_initial_timestamp(&mut self) -> Result<ParseStageResult, ChunkDeserializationError> {
        if self.current_header_format == ChunkHeaderFormat::Empty {
            // Some encoders send an empty header after a type 1 header due to a message split
            // across multiple chunks.  We need to be careful *NOT* to apply the delta to each
            // type 3 chunk that's trying to serve a single message, otherwise timestamps will
            // get out of control.
            let csid = self.current_header.chunk_stream_id;
            let payload_len = self.csid_payload_data.get(&csid).map_or(0, |b| b.len());
            if payload_len == 0 {
                // Since we don't have any payload data yet, that means this is the first
                // chunk of the message.  As it's the first chunk this is the only time we should
                // apply the previous header's delta to the timestamp
                self.current_header.timestamp =
                    self.current_header.timestamp + self.current_header.timestamp_field;
            }

            self.current_stage = ParseStage::MessageLength;
            return Ok(ParseStageResult::Success);
        }

        if self.buffer.len() < 3 {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        let timestamp;
        {
            let bytes = self.buffer.split_to(3);
            let mut cursor = Cursor::new(bytes);
            timestamp = cursor.read_u24::<BigEndian>()?;
        }

        if self.current_header_format == ChunkHeaderFormat::Full {
            self.current_header.timestamp.set(timestamp);
        } else {
            // Non full headers are deltas only
            self.current_header.timestamp = self.current_header.timestamp + timestamp;
        }

        //apply the timestamp field
        self.current_header.timestamp_field = timestamp;

        self.current_stage = ParseStage::MessageLength;
        Ok(ParseStageResult::Success)
    }

    fn get_message_length(&mut self) -> Result<ParseStageResult, ChunkDeserializationError> {
        if self.current_header_format == ChunkHeaderFormat::TimeDeltaOnly
            || self.current_header_format == ChunkHeaderFormat::Empty
        {
            self.current_stage = ParseStage::MessageTypeId;
            return Ok(ParseStageResult::Success);
        }

        if self.buffer.len() < 3 {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        let length;
        {
            let bytes = self.buffer.split_to(3);
            let mut cursor = Cursor::new(bytes);
            length = cursor.read_u24::<BigEndian>()?;
        }

        self.current_header.message_length = length;
        self.current_stage = ParseStage::MessageTypeId;
        Ok(ParseStageResult::Success)
    }

    fn get_message_type_id(&mut self) -> Result<ParseStageResult, ChunkDeserializationError> {
        if self.current_header_format == ChunkHeaderFormat::TimeDeltaOnly
            || self.current_header_format == ChunkHeaderFormat::Empty
        {
            self.current_stage = ParseStage::MessageStreamId;
            return Ok(ParseStageResult::Success);
        }

        if self.buffer.len() < 1 {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        self.current_header.message_type_id = self.buffer[0];
        let _ = self.buffer.split_to(1);
        self.current_stage = ParseStage::MessageStreamId;
        Ok(ParseStageResult::Success)
    }

    fn get_message_stream_id(&mut self) -> Result<ParseStageResult, ChunkDeserializationError> {
        if self.current_header_format != ChunkHeaderFormat::Full {
            self.current_stage = ParseStage::ExtendedTimestamp;
            return Ok(ParseStageResult::Success);
        }

        if self.buffer.len() < 4 {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        let stream_id;
        {
            let bytes = self.buffer.split_to(4);
            let mut cursor = Cursor::new(bytes);
            stream_id = cursor.read_u32::<LittleEndian>()?;
        }

        self.current_header.message_stream_id = stream_id;
        self.current_stage = ParseStage::ExtendedTimestamp;
        Ok(ParseStageResult::Success)
    }

    fn get_extended_timestamp(&mut self) -> Result<ParseStageResult, ChunkDeserializationError> {
        if self.current_header.timestamp_field < MAX_INITIAL_TIMESTAMP {
            self.current_stage = ParseStage::MessagePayload;
            return Ok(ParseStageResult::Success);
        }

        if self.buffer.len() < 4 {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        let timestamp;
        {
            let bytes = self.buffer.split_to(4);
            let mut cursor = Cursor::new(bytes);
            timestamp = cursor.read_u32::<BigEndian>()?;
        }

        // If the type 3 chunk is not the first chunk of a message, we just ignore it's extended timestamp because the timestamp of this message was already deserialized.
        let csid = self.current_header.chunk_stream_id;
        let payload_len = self.csid_payload_data.get(&csid).map_or(0, |b| b.len());
        if self.current_header_format == ChunkHeaderFormat::Full {
            self.current_header.timestamp.set(timestamp);
        } else if payload_len == 0 {
            // Since we already added the MAX_INITIAL_TIMESTAMP to the timestamp, only add the delta difference
            self.current_header.timestamp =
                self.current_header.timestamp + (timestamp - MAX_INITIAL_TIMESTAMP);
        }

        self.current_stage = ParseStage::MessagePayload;
        Ok(ParseStageResult::Success)
    }

    fn get_message_data(
        &mut self,
        message_to_return: &mut Option<MessagePayload>,
    ) -> Result<ParseStageResult, ChunkDeserializationError> {
        let csid = self.current_header.chunk_stream_id;
        let message_length = self.current_header.message_length as usize;

        // Get current payload length for this csid
        let current_payload_length = self.csid_payload_data.get(&csid).map_or(0, |b| b.len());

        // Use saturating_sub to prevent underflow panic when payload exceeds expected length
        let remaining_bytes = message_length.saturating_sub(current_payload_length);

        // Debug: Log unusual state that might indicate desync
        if current_payload_length > message_length {
            log::error!(
                "RTMP DESYNC: payload_len ({}) > message_len ({}), csid={}, type_id={}, buffer_len={}",
                current_payload_length,
                message_length,
                csid,
                self.current_header.message_type_id,
                self.buffer.len()
            );
            // Clear the corrupted buffer and start fresh for this csid
            self.csid_payload_data.remove(&csid);
        }

        // Calculate how many bytes to read in this chunk
        let bytes_to_read = min(remaining_bytes, self.max_chunk_size);

        if self.buffer.len() < bytes_to_read {
            return Ok(ParseStageResult::NotEnoughBytes);
        }

        self.current_payload.timestamp = self.current_header.timestamp;
        self.current_payload.type_id = self.current_header.message_type_id;
        self.current_payload.message_stream_id = self.current_header.message_stream_id;

        // Get or create the per-csid payload buffer and ensure capacity
        let current_payload_data = self.csid_payload_data.entry(csid).or_insert_with(BytesMut::new);

        // Make sure we have enough capacity for the whole message data.  This
        // helps with performance when there are smaller chunk sizes.
        if remaining_bytes > current_payload_data.remaining_mut() {
            let capacity_needed = remaining_bytes - current_payload_data.remaining_mut();
            current_payload_data.reserve(capacity_needed);
        }

        let bytes = self.buffer.split_to(bytes_to_read);
        current_payload_data.extend_from_slice(&bytes[..]);

        let new_payload_length = current_payload_data.len();

        // Check if this completes the message
        if new_payload_length == message_length {
            log::trace!(
                "RTMP: Message complete csid={}, type_id={}, len={}",
                csid,
                self.current_header.message_type_id,
                message_length
            );
            // Remove the buffer from the map and use it
            let data = self.csid_payload_data.remove(&csid).unwrap_or_else(BytesMut::new);
            self.current_payload.data = data.freeze();

            let payload = mem::replace(&mut self.current_payload, MessagePayload::new());
            *message_to_return = Some(payload)
        } else {
            log::trace!(
                "RTMP: Chunk received csid={}, progress={}/{}, max_chunk={}",
                csid,
                new_payload_length,
                message_length,
                self.max_chunk_size
            );
        }

        // This completes the current chunk, so cycle the header into the map and start a new one
        let current_header = mem::replace(&mut self.current_header, ChunkHeader::new());
        self.previous_headers
            .insert(current_header.chunk_stream_id, current_header);
        self.current_stage = ParseStage::Csid;
        Ok(ParseStageResult::Success)
    }
}

fn get_format(byte: &u8) -> ChunkHeaderFormat {
    const TYPE_0_MASK: u8 = 0b00000000;
    const TYPE_1_MASK: u8 = 0b01000000;
    const TYPE_2_MASK: u8 = 0b10000000;
    const FORMAT_MASK: u8 = 0b11000000;

    let format_id = *byte & FORMAT_MASK;

    match format_id {
        TYPE_0_MASK => ChunkHeaderFormat::Full,
        TYPE_1_MASK => ChunkHeaderFormat::TimeDeltaWithoutMessageStreamId,
        TYPE_2_MASK => ChunkHeaderFormat::TimeDeltaOnly,
        _ => ChunkHeaderFormat::Empty,
    }
}

fn get_csid(buffer: &[u8]) -> ParsedValue<u32> {
    const CSID_MASK: u8 = 0b00111111;

    if buffer.len() < 1 {
        return ParsedValue::NotEnoughBytes;
    }

    match buffer[0] & CSID_MASK {
        0 => {
            if buffer.len() < 2 {
                ParsedValue::NotEnoughBytes
            } else {
                ParsedValue::Value {
                    val: buffer[1] as u32 + 64,
                    next_index: 2,
                }
            }
        }

        1 => {
            if buffer.len() < 3 {
                ParsedValue::NotEnoughBytes
            } else {
                ParsedValue::Value {
                    val: (buffer[2] as u32 * 256) + buffer[1] as u32 + 64,
                    next_index: 3,
                }
            }
        }

        x => ParsedValue::Value {
            val: x as u32,
            next_index: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
    use std::io::{Cursor, Write};
    use time::RtmpTimestamp;

    #[test]
    fn can_read_type_0_chunk_with_small_chunk_stream_id_and_small_timestamp() {
        let csid = 50;
        let timestamp = 25u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let mut deserializer = ChunkDeserializer::new();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_0_chunk_with_medium_chunk_stream_id_and_small_timestamp() {
        let csid = 500;
        let timestamp = 25u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let mut deserializer = ChunkDeserializer::new();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_0_chunk_with_large_chunk_stream_id_and_small_timestamp() {
        let csid = 50000;
        let timestamp = 25u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let mut deserializer = ChunkDeserializer::new();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_0_chunk_with_small_chunk_stream_id_and_large_timestamp() {
        let csid = 50;
        let timestamp = 16777216u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let mut deserializer = ChunkDeserializer::new();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_0_chunk_with_medium_chunk_stream_id_and_large_timestamp() {
        let csid = 500;
        let timestamp = 16777216u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let mut deserializer = ChunkDeserializer::new();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_0_chunk_with_large_chunk_stream_id_and_large_timestamp() {
        let csid = 50000;
        let timestamp = 16777216u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let mut deserializer = ChunkDeserializer::new();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_1_chunk_with_small_chunk_stream_id_and_small_timestamp() {
        let csid = 50;
        let timestamp = 25u32;
        let delta = 10_u32;
        let message_stream_id = 5u32;
        let type_id1 = 3;
        let type_id2 = 4;
        let payload = [1_u8, 2_u8, 3_u8];

        let chunk_0_bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id1,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let chunk_1_bytes = form_type_1_chunk(csid, delta, type_id2, &payload);
        let mut deserializer = ChunkDeserializer::new();
        let _ = deserializer
            .get_next_message(&chunk_0_bytes)
            .unwrap()
            .unwrap();
        let result = deserializer
            .get_next_message(&chunk_1_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(result.type_id, type_id2, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp + delta),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_2_chunk_with_small_chunk_stream_id_and_small_timestamp() {
        let csid = 50;
        let timestamp = 25u32;
        let delta1 = 10_u32;
        let delta2 = 11_u32;
        let message_stream_id = 5u32;
        let type_id1 = 3;
        let type_id2 = 4;
        let payload = [1_u8, 2_u8, 3_u8];

        let chunk_0_bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id1,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let chunk_1_bytes = form_type_1_chunk(csid, delta1, type_id2, &payload);
        let chunk_2_bytes = form_type_2_chunk(csid, delta2, &payload);
        let mut deserializer = ChunkDeserializer::new();
        let _ = deserializer
            .get_next_message(&chunk_0_bytes)
            .unwrap()
            .unwrap();
        let _ = deserializer
            .get_next_message(&chunk_1_bytes)
            .unwrap()
            .unwrap();
        let result = deserializer
            .get_next_message(&chunk_2_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(result.type_id, type_id2, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp + delta1 + delta2),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_2_chunk_with_small_chunk_stream_id_and_large_timestamp() {
        let csid = 50;
        let timestamp = 25u32;
        let delta1 = 10_u32;
        let delta2 = 16777216_u32;
        let message_stream_id = 5u32;
        let type_id1 = 3;
        let type_id2 = 4;
        let payload = [1_u8, 2_u8, 3_u8];

        let chunk_0_bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id1,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let chunk_1_bytes = form_type_1_chunk(csid, delta1, type_id2, &payload);
        let chunk_2_bytes = form_type_2_chunk(csid, delta2, &payload);
        let mut deserializer = ChunkDeserializer::new();
        let _ = deserializer
            .get_next_message(&chunk_0_bytes)
            .unwrap()
            .unwrap();
        let _ = deserializer
            .get_next_message(&chunk_1_bytes)
            .unwrap()
            .unwrap();
        let result = deserializer
            .get_next_message(&chunk_2_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(result.type_id, type_id2, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp + delta1 + delta2),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_3_chunk_with_small_chunk_stream_id_and_small_timestamp() {
        let csid = 50;
        let timestamp = 25u32;
        let delta1 = 10_u32;
        let delta2 = 11_u32;
        let message_stream_id = 5u32;
        let type_id1 = 3;
        let type_id2 = 4;
        let payload = [1_u8, 2_u8, 3_u8];

        let chunk_0_bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id1,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let chunk_1_bytes = form_type_1_chunk(csid, delta1, type_id2, &payload);
        let chunk_2_bytes = form_type_2_chunk(csid, delta2, &payload);
        let chunk_3_bytes = form_type_3_chunk(csid, &payload, INITIAL_MAX_CHUNK_SIZE, None);
        let mut deserializer = ChunkDeserializer::new();
        let _ = deserializer
            .get_next_message(&chunk_0_bytes)
            .unwrap()
            .unwrap();
        let _ = deserializer
            .get_next_message(&chunk_1_bytes)
            .unwrap()
            .unwrap();
        let _ = deserializer
            .get_next_message(&chunk_2_bytes)
            .unwrap()
            .unwrap();
        let result = deserializer
            .get_next_message(&chunk_3_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(result.type_id, type_id2, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp + delta1 + delta2 + delta2),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_type_3_chunk_with_small_chunk_stream_id_and_large_timestamp() {
        let csid = 50;
        let timestamp = 10_u32;
        let delta1 = 10_u32;
        let delta2 = 16777216_u32;
        let message_stream_id = 5u32;
        let type_id1 = 3;
        let type_id2 = 4;
        let payload = [1_u8, 2_u8, 3_u8];

        let chunk_0_bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id1,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let chunk_1_bytes = form_type_1_chunk(csid, delta1, type_id2, &payload);
        let chunk_2_bytes = form_type_2_chunk(csid, delta2, &payload);
        let chunk_3_bytes = form_type_3_chunk(csid, &payload, INITIAL_MAX_CHUNK_SIZE, Some(delta2));
        let mut deserializer = ChunkDeserializer::new();
        let _ = deserializer
            .get_next_message(&chunk_0_bytes)
            .unwrap()
            .unwrap();
        let _ = deserializer
            .get_next_message(&chunk_1_bytes)
            .unwrap()
            .unwrap();
        let _ = deserializer
            .get_next_message(&chunk_2_bytes)
            .unwrap()
            .unwrap();
        let result = deserializer
            .get_next_message(&chunk_3_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(result.type_id, type_id2, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp + delta1 + delta2 + delta2),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_message_spread_across_multiple_deserialization_calls() {
        let csid = 50;
        let timestamp = 25u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [1_u8, 2_u8, 3_u8];

        let all_bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            INITIAL_MAX_CHUNK_SIZE,
        );
        let (first, second) = all_bytes.split_at(all_bytes.len() / 2);
        let mut deserializer = ChunkDeserializer::new();
        match deserializer.get_next_message(first).unwrap() {
            Some(x) => panic!("Expected None but received {:?}", x),
            None => (),
        };

        let result = deserializer.get_next_message(second).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn can_read_message_exceeding_maximum_chunk_size() {
        let csid = 50;
        let timestamp = 25u32;
        let message_stream_id = 5u32;
        let type_id = 3;
        let payload = [100_u8; 500];
        let max_chunk_size = 100;

        let bytes = form_type_0_chunk(
            csid,
            timestamp,
            message_stream_id,
            type_id,
            &payload,
            max_chunk_size,
        );
        let mut deserializer = ChunkDeserializer::new();
        deserializer.set_max_chunk_size(max_chunk_size).unwrap();
        let result = deserializer.get_next_message(&bytes).unwrap().unwrap();

        assert_eq!(result.type_id, 3, "Incorrect type id");
        assert_eq!(
            result.timestamp,
            RtmpTimestamp::new(timestamp),
            "Incorrect timestamp"
        );
        assert_eq!(&result.data[..], &payload[..], "Incorrect data");
    }

    #[test]
    fn error_when_setting_chunk_size_too_large() {
        const CHUNK_SIZE_VALUE: usize = 2147483648;
        let mut deserializer = ChunkDeserializer::new();
        match deserializer.set_max_chunk_size(CHUNK_SIZE_VALUE) {
            Err(ChunkDeserializationError::InvalidMaxChunkSize {
                chunk_size: CHUNK_SIZE_VALUE,
            }) => {} // success
            x => panic!("Unexpected set max chunk size result of {:?}", x),
        }
    }

    #[test]
    fn type_2_chunk_that_exceeds_max_chunk_size_does_not_keep_applying_delta_to_timestamp() {
        // It was noticed that OBS does not totally conform to the RTMP specification.  It will
        // send a type 1 chunk with a time delta for a video packet, but will send the remaining
        // parts of that chunk with a type 3 header (even though the delta should not be applied).
        // this test verifies we can handle that.

        let chunk1 = [
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x09, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let chunk2 = [
            0x44, 0x00, 0x00, 0x21, 0x00, 0x00, 0x05, 0x09, 0x01, 0x02, 0x03, 0x04, 0xc4, 0x05,
        ];

        let mut deserializer = ChunkDeserializer::new();
        deserializer.set_max_chunk_size(4).unwrap();

        let payload1 = deserializer.get_next_message(&chunk1).unwrap().unwrap();
        assert_eq!(payload1.type_id, 0x09, "Incorrect payload 1 type");
        assert_eq!(
            payload1.timestamp,
            RtmpTimestamp::new(0),
            "Incorrect payload 1 timestamp"
        );
        assert_eq!(&payload1.data[..], &[0x01], "Incorrect payload 1 data");

        let payload2 = deserializer.get_next_message(&chunk2).unwrap().unwrap();
        assert_eq!(payload2.type_id, 0x09, "Incorrect payload 2 type");
        assert_eq!(
            payload2.timestamp,
            RtmpTimestamp::new(33),
            "Incorrect payload 2 timestamp"
        );
        assert_eq!(
            &payload2.data[..],
            &[0x01, 0x02, 0x03, 0x04, 0x05],
            "Incorrect payload 2 data"
        );
    }

    #[test]
    fn can_read_type_3_chunk_that_follows_type_0_has_extended_timestamp() {
        let chunk1 = [
            0x06, 0xff, 0xff, 0xff, 0x00, 0x00, 0x07, 0x09, 0x01, 0x00, 0x00, 0x00, 0x01, 0xff,
            0xff, 0xff, 0x01, 0x02, 0x03, 0x04,
        ];
        let chunk2 = [0xc6, 0x01, 0xff, 0xff, 0xff, 0x05, 0x06, 0x07];
        let mut deserializer = ChunkDeserializer::new();
        deserializer.set_max_chunk_size(4).unwrap();
        let _ = deserializer.get_next_message(&chunk1).unwrap();
        let payload = deserializer.get_next_message(&chunk2).unwrap().unwrap();
        assert_eq!(payload.type_id, 0x09, "Incorrect payload type");
        assert_eq!(
            payload.timestamp,
            RtmpTimestamp::new(0x1ffffff),
            "Incorrect payload timestamp"
        );
        assert_eq!(
            &payload.data[..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            "Incorrect payload data"
        );
    }

    #[test]
    fn can_handle_interleaved_chunks_from_different_csids() {
        // This test verifies that interleaved chunks from different chunk streams
        // don't corrupt each other's payload data. This is the root cause fix for
        // the RTMP desync issue where audio (csid 4) and video (csid 6) chunks
        // would get their payloads mixed when interleaved.
        let type_id_audio = 8u8;
        let type_id_video = 9u8;
        let audio_payload = [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]; // 8 bytes
        let video_payload = [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]; // 8 bytes
        let max_chunk_size = 4usize;

        // Build chunks manually:
        // Type 0 header: 1 byte basic header + 3 timestamp + 3 msg_len + 1 type_id + 4 stream_id = 12 bytes

        // csid 4 first chunk (type 0, first 4 bytes of audio)
        let csid4_chunk1: Vec<u8> = vec![
            0x04,                   // fmt=0, csid=4
            0x00, 0x00, 0x64,       // timestamp=100
            0x00, 0x00, 0x08,       // message_length=8
            type_id_audio,          // type_id=8
            0x01, 0x00, 0x00, 0x00, // message_stream_id=1 (little endian)
            0xAA, 0xAA, 0xAA, 0xAA, // first 4 bytes of payload
        ];

        // csid 6 first chunk (type 0, first 4 bytes of video) - INTERLEAVED
        let csid6_chunk1: Vec<u8> = vec![
            0x06,                   // fmt=0, csid=6
            0x00, 0x00, 0x64,       // timestamp=100
            0x00, 0x00, 0x08,       // message_length=8
            type_id_video,          // type_id=9
            0x01, 0x00, 0x00, 0x00, // message_stream_id=1 (little endian)
            0xBB, 0xBB, 0xBB, 0xBB, // first 4 bytes of payload
        ];

        // csid 4 continuation chunk (type 3, remaining 4 bytes of audio)
        let csid4_chunk2: Vec<u8> = vec![
            0xC4,                   // fmt=3, csid=4
            0xAA, 0xAA, 0xAA, 0xAA, // remaining 4 bytes of payload
        ];

        // csid 6 continuation chunk (type 3, remaining 4 bytes of video)
        let csid6_chunk2: Vec<u8> = vec![
            0xC6,                   // fmt=3, csid=6
            0xBB, 0xBB, 0xBB, 0xBB, // remaining 4 bytes of payload
        ];

        let mut deserializer = ChunkDeserializer::new();
        deserializer.set_max_chunk_size(max_chunk_size).unwrap();

        // Feed interleaved chunks: audio1 -> video1 -> audio2 -> video2
        // This is the pattern that caused the bug - payloads would get mixed

        // Process csid 4 first chunk - should return None (incomplete)
        let result1 = deserializer.get_next_message(&csid4_chunk1).unwrap();
        assert!(result1.is_none(), "Audio chunk 1 should not complete message");

        // Process csid 6 first chunk (interleaved) - should return None (incomplete)
        let result2 = deserializer.get_next_message(&csid6_chunk1).unwrap();
        assert!(result2.is_none(), "Video chunk 1 should not complete message");

        // Process csid 4 continuation - should complete audio message
        let audio_msg = deserializer.get_next_message(&csid4_chunk2).unwrap();
        assert!(audio_msg.is_some(), "Audio message should be complete");
        let audio_msg = audio_msg.unwrap();
        assert_eq!(audio_msg.type_id, type_id_audio, "Audio type_id mismatch");
        assert_eq!(&audio_msg.data[..], &audio_payload[..], "Audio payload corrupted by interleaving");

        // Process csid 6 continuation - should complete video message
        let video_msg = deserializer.get_next_message(&csid6_chunk2).unwrap();
        assert!(video_msg.is_some(), "Video message should be complete");
        let video_msg = video_msg.unwrap();
        assert_eq!(video_msg.type_id, type_id_video, "Video type_id mismatch");
        assert_eq!(&video_msg.data[..], &video_payload[..], "Video payload corrupted by interleaving");
    }

    fn form_type_0_chunk(
        csid: u32,
        timestamp: u32,
        message_stream_id: u32,
        type_id: u8,
        payload: &[u8],
        max_chunk_length: usize,
    ) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        if csid < 64 {
            cursor.write_u8(csid as u8).unwrap();
        } else if csid < 319 {
            cursor.write_u8(0_u8).unwrap();
            cursor.write_u8((csid - 64) as u8).unwrap();
        } else {
            cursor.write_u8(1_u8).unwrap();
            cursor.write_u16::<BigEndian>((csid - 64) as u16).unwrap();
        }

        let standard_timestamp = if timestamp >= 16777215 {
            16777215
        } else {
            timestamp
        };
        cursor.write_u24::<BigEndian>(standard_timestamp).unwrap();
        cursor.write_u24::<BigEndian>(payload.len() as u32).unwrap();
        cursor.write_u8(type_id).unwrap();
        cursor.write_u32::<LittleEndian>(message_stream_id).unwrap();

        let mut option_extended_timestamp = None;
        if timestamp > 16777215 {
            cursor.write_u32::<BigEndian>(timestamp).unwrap();
            option_extended_timestamp = Some(timestamp);
        }

        // If the payload is over max_chunk_length, assume we want to form a split message
        // and therefore need to only write the max chunk amount of the payload in this request
        // and append a type 3 chunk with the rest
        if payload.len() > max_chunk_length {
            cursor.write(&payload[..max_chunk_length]).unwrap();

            let next_chunk = form_type_3_chunk(
                csid,
                &payload[max_chunk_length..],
                max_chunk_length,
                option_extended_timestamp,
            );
            cursor.write(&next_chunk).unwrap();
        } else {
            cursor.write(payload).unwrap();
        }

        cursor.into_inner()
    }

    fn form_type_1_chunk(csid: u32, delta: u32, type_id: u8, payload: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        if csid < 64 {
            cursor.write_u8((csid as u8) | 0b01000000).unwrap();
        } else if csid < 319 {
            cursor.write_u8(0_u8 | 0b01000000).unwrap();
            cursor.write_u8((csid - 64) as u8).unwrap();
        } else {
            cursor.write_u8(1_u8 | 0b01000000).unwrap();
            cursor.write_u16::<BigEndian>((csid - 64) as u16).unwrap();
        }

        let standard_timestamp = if delta >= 16777215 { 16777215 } else { delta };
        cursor.write_u24::<BigEndian>(standard_timestamp).unwrap();
        cursor.write_u24::<BigEndian>(payload.len() as u32).unwrap();
        cursor.write_u8(type_id).unwrap();

        if delta > 16777215 {
            cursor.write_u32::<BigEndian>(delta).unwrap();
        }

        cursor.write(payload).unwrap();

        cursor.into_inner()
    }

    fn form_type_2_chunk(csid: u32, delta: u32, payload: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        if csid < 64 {
            cursor.write_u8((csid as u8) | 0b10000000).unwrap();
        } else if csid < 319 {
            cursor.write_u8(0_u8 | 0b10000000).unwrap();
            cursor.write_u8((csid - 64) as u8).unwrap();
        } else {
            cursor.write_u8(1_u8 | 0b10000000).unwrap();
            cursor.write_u16::<BigEndian>((csid - 64) as u16).unwrap();
        }

        let standard_timestamp = if delta >= 16777215 { 16777215 } else { delta };
        cursor.write_u24::<BigEndian>(standard_timestamp).unwrap();

        if delta > 16777215 {
            cursor.write_u32::<BigEndian>(delta).unwrap();
        }

        cursor.write(payload).unwrap();

        cursor.into_inner()
    }

    fn form_type_3_chunk(
        csid: u32,
        payload: &[u8],
        max_chunk_length: usize,
        option_extended_timestamp: Option<u32>,
    ) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        if csid < 64 {
            cursor.write_u8((csid as u8) | 0b11000000).unwrap();
        } else if csid < 319 {
            cursor.write_u8(0_u8 | 0b11000000).unwrap();
            cursor.write_u8((csid - 64) as u8).unwrap();
        } else {
            cursor.write_u8(1_u8 | 0b11000000).unwrap();
            cursor.write_u16::<BigEndian>((csid - 64) as u16).unwrap();
        }

        if option_extended_timestamp != None {
            assert_eq!(
                option_extended_timestamp.unwrap() >= MAX_INITIAL_TIMESTAMP,
                true,
                "timestamp was less than 0xffffff"
            );
            cursor
                .write_u32::<BigEndian>(option_extended_timestamp.unwrap())
                .unwrap();
        }

        // If the payload is over max_chunk_length, assume we want to form a split message
        // and therefore need to only write the max chunk amount of the payload in this request
        // and append a type 3 chunk with the rest
        if payload.len() > max_chunk_length {
            cursor.write(&payload[..max_chunk_length]).unwrap();

            let next_chunk = form_type_3_chunk(
                csid,
                &payload[max_chunk_length..],
                max_chunk_length,
                option_extended_timestamp,
            );
            cursor.write(&next_chunk).unwrap();
        } else {
            cursor.write(payload).unwrap();
        }

        cursor.into_inner()
    }
}
