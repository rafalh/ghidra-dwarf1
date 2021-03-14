package com.github.rafalh.ghidra.dwarfone.model;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.app.util.bin.BinaryReader;

public class DebugInfoEntry {
	
	private final int rawTag;
	private final Tag tag;
	private final Map<AttributeName, AttributeValue> attributes = new HashMap<>();
	private final Map<Integer, AttributeValue> userAttributes = new HashMap<>();
	
	public DebugInfoEntry(BinaryReader reader) throws IOException {
		long length = reader.readNextUnsignedInt();
		long endIndex = reader.getPointerIndex() + length - 4;
		if (length < 8) {
			rawTag = -1;
			tag = Tag.NULL;
			reader.setPointerIndex(endIndex);
		} else {
			rawTag = reader.readNextUnsignedShort();
			tag = Tag.decode(rawTag);
		}
		while (reader.getPointerIndex() < endIndex) {
			Map.Entry<Integer, AttributeValue> at = readAttribute(reader);
			AttributeName attributeName = AttributeName.decode(at.getKey());
			if (attributeName != AttributeName.USER) {
				attributes.put(attributeName, at.getValue());
			} else {
				userAttributes.put(at.getKey(), at.getValue());
			}
		}
	}
	
	private Map.Entry<Integer, AttributeValue> readAttribute(BinaryReader reader) throws IOException {
		int rawNameForm = reader.readNextUnsignedShort();
		int rawName = rawNameForm & AttributeName.MASK;
		int rawForm = rawNameForm & Form.MASK;
		Form form = Form.decode(rawForm);
		AttributeValue value = readAttributeValue(reader, form);
		return Map.entry(rawName, value);
	}
	
	private AttributeValue readAttributeValue(BinaryReader reader, Form form) throws IOException {
		int blockLength;
		switch (form) {
		case ADDR:
			// FIXME: is it always 32-bit?
			return new AddrAttributeValue(reader.readNextUnsignedInt());
		case REF:
			return new RefAttributeValue(reader.readNextUnsignedInt());
		case DATA2:
			return new ConstAttributeValue(reader.readNextShort());
		case DATA4:
			return new ConstAttributeValue(reader.readNextInt());
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
	
	@Override
	public String toString() {
		return Objects.toString(tag) + attributes.toString();
	}
	
	public Tag getTag() {
		return tag;
	}
	
	@SuppressWarnings("unchecked")
	public <T extends AttributeValue> Optional<T> getAttribute(AttributeName name) {
		return Optional.ofNullable((T) attributes.get(name));
	}
}
