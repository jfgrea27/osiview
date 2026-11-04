/// One OSI layer's decoder.
///
/// Only layer 2 talks to the network (see `level2::Capture`); every layer above
/// it just decodes bytes handed up by the layer below. So the shared interface
/// is decoding alone: `render` is pure, which makes every layer testable with
/// byte arrays and usable on pcap files.
pub trait Operate {
    /// Decode `data` at this layer and return it as human-readable text: summary
    /// lines, field tables and a hexdump.
    fn render(&self, data: &[u8]) -> String;
}
