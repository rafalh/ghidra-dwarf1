package com.github.rafalh.ghidra.dwarfone.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import ghidra.app.util.bin.BinaryReader;

public class DebugInfoEntry {
	
	private final long ref;
	private final int rawTag;
	private final Tag tag;
	private final Map<AttributeName, AttributeValue> attributes = new HashMap<>();
	private final Map<Integer, AttributeValue> userAttributes = new HashMap<>();
	private final DebugInfoEntry parent;
	private final List<DebugInfoEntry> children = new ArrayList<>();
	
	public DebugInfoEntry(BinaryReader reader, DebugInfoEntry parent) throws IOException {
		ref = reader.getPointerIndex();
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
			Map.Entry<Integer, AttributeValue> at = AttributeUtils.readAttribute(reader);
			AttributeName attributeName = AttributeName.decode(at.getKey());
			if (attributeName != AttributeName.USER) {
				attributes.put(attributeName, at.getValue());
			} else {
				userAttributes.put(at.getKey(), at.getValue());
			}
		}
		this.parent = parent;
		if (parent != null && tag != Tag.NULL) {
			parent.children.add(this);
		}
	}
	
	@Override
	public String toString() {
		return Long.toHexString(ref) + ":" + Objects.toString(tag) + attributes.toString();
	}
	
	public long getRef() {
		return ref;
	}
	
	public Tag getTag() {
		return tag;
	}
	
	@SuppressWarnings("unchecked")
	public <T extends AttributeValue> Optional<T> getAttribute(AttributeName name) {
		return Optional.ofNullable((T) attributes.get(name));
	}
	
	public DebugInfoEntry getParent() {
		return parent;
	}
	
	public List<DebugInfoEntry> getChildren() {
		return children;
	}
}
