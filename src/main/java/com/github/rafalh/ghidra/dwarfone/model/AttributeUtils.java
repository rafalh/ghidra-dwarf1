package com.github.rafalh.ghidra.dwarfone.model;

import java.io.IOException;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;

public class AttributeUtils {
	public static Map.Entry<Integer, AttributeValue> readAttribute(BinaryReader reader) throws IOException {
		int rawNameForm = reader.readNextUnsignedShort();
		int rawName = rawNameForm & AttributeName.MASK;
		int rawForm = rawNameForm & Form.MASK;
		Form form = Form.decode(rawForm);
		AttributeValue value = readAttributeValue(reader, form);
		return Map.entry(rawName, value);
	}
	
	private static AttributeValue readAttributeValue(BinaryReader reader, Form form) throws IOException {
		int blockLength;
		switch (form) {
		case ADDR:
			// FIXME: is it always 32-bit?
			return new AddrAttributeValue(reader.readNextUnsignedInt());
		case REF:
			return new RefAttributeValue(reader.readNextUnsignedInt());
		case DATA2:
			return new ConstAttributeValue(reader.readNextUnsignedShort());
		case DATA4:
			return new ConstAttributeValue(reader.readNextUnsignedInt());
		case DATA8:
			return new ConstAttributeValue(reader.readNextLong());
		case BLOCK2:
			blockLength = reader.readNextUnsignedShort();
			return new BlockAttributeValue(reader.readNextByteArray(blockLength));
		case BLOCK4:
			blockLength = reader.readNextInt();
			return new BlockAttributeValue(reader.readNextByteArray(blockLength));
		case STRING:
			return new StringAttributeValue(reader.readNextAsciiString());
		default:
			throw new IllegalArgumentException("unknown form");
		}
	}
}
