package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Form {
	ADDR(0x1),
	REF(0x2),
	BLOCK2(0x3),
	BLOCK4(0x4),
	DATA2(0x5),
	DATA4(0x6),
	DATA8(0x7),
	STRING(0x8);
	
	public static final int MASK = 0x000F;
	private static final Map<Integer, Form> VALUE_MAP;
	
	private int value;
	
	static {
		VALUE_MAP = Stream.of(Form.values())
				.collect(Collectors.toUnmodifiableMap(form -> form.value, Function.identity()));
	}
	
	Form(int value) {
		this.value = value;
	}
	
	public static Form decode(int value) {
		Form form = VALUE_MAP.get(value);
		if (form == null) {
			throw new IllegalArgumentException("invalid form value " + value);
		}
		return form;
	}
}
