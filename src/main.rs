use pcap_file::pcapng::PcapNgWriter;
use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::InterfaceDescriptionBlock,
            section_header::SectionHeaderBlock,
        },
        Block,
    },
    DataLink, Endianness,
};
use std::fs::File;
use std::{borrow::Cow, time::SystemTime};

fn main() {
    let header = SectionHeaderBlock {
        endianness: Endianness::native(),
        major_version: 1,
        minor_version: 0,
        // Length unknown
        section_length: -1i64,
        options: vec![],
    };

    let file_out = File::create("generated.pcapng").expect("Error opening file");
    let mut pcapng_writer = PcapNgWriter::with_section_header(file_out, header).unwrap();

    pcapng_writer
        .write_block(&Block::InterfaceDescription(InterfaceDescriptionBlock {
            linktype: DataLink::WIRESHARK_UPPER_PDU,
            snaplen: 0,
            options: vec![],
        }))
        .unwrap();

    let mut data: Vec<u8> = vec![];

    // PDU content dissector name
    let disector_name = "nmea0183";
    data.push(0x00);
    data.push(0x0C);
    data.push(0x00);
    data.push(disector_name.len().try_into().unwrap());
    data.append(&mut disector_name.as_bytes().to_vec());

    // End of options
    data.push(0x00);
    data.push(0x00);
    data.push(0x00);
    data.push(0x00);

    let now = SystemTime::now();
    let payload = "$GPGSV,3,1,09,3,,,,6,73,209,28,10,,,,13,,,*41";

    data.append(&mut payload.as_bytes().to_vec());

    let interface = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: now.duration_since(SystemTime::UNIX_EPOCH).unwrap(),
        original_len: data.len() as u32,
        data: Cow::Borrowed(&data),
        // Flags: Outbound
        options: vec![EnhancedPacketOption::Flags(2)],
    };

    pcapng_writer
        .write_block(&Block::EnhancedPacket(interface))
        .unwrap();

    let mut data: Vec<u8> = vec![];

    // PDU content dissector name
    let disector_name = "nmea0183";
    data.push(0x00);
    data.push(0x0C);
    data.push(0x00);
    data.push(disector_name.len().try_into().unwrap());
    data.append(&mut disector_name.as_bytes().to_vec());

    // End of options
    data.push(0x00);
    data.push(0x00);
    data.push(0x00);
    data.push(0x00);

    let now = SystemTime::now();
    let payload = "$GPAAM,A,A,0.10,N,WPTNME*32";

    data.append(&mut payload.as_bytes().to_vec());

    let interface = EnhancedPacketBlock {
        interface_id: 0,
        timestamp: now.duration_since(SystemTime::UNIX_EPOCH).unwrap(),
        original_len: data.len() as u32,
        data: Cow::Borrowed(&data),
        // Flags: Inbound
        options: vec![EnhancedPacketOption::Flags(1)],
    };

    pcapng_writer
        .write_block(&Block::EnhancedPacket(interface))
        .unwrap();
}
