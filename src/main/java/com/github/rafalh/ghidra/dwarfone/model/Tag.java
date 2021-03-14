package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Tag {
	NULL(null),
	PADDING(0x0000),
	ARRAY_TYPE(0x0001),
	CLASS_TYPE(0x0002),
	ENTRY_POINT(0x0003),
	ENUMERATION_TYPE(0x0004),
	FORMAL_PARAMETER(0x0005),
	GLOBAL_SUBROUTINE(0x0006),
	GLOBAL_VARIABLE(0x0007),
	LABEL(0x000A),
	LEXICAL_BLOCK(0x000B),
	LOCAL_VARIABLE(0x000C),
	MEMBER(0x000D),
	POINTER_TYPE(0x000F),
	REFERENCE_TYPE(0x0010),
	COMPILE_UNIT(0x0011),
	// SOURCE_FILE(0x0011), // reserved - synonym for COMPILE_UNIT
	STRING_TYPE(0x0012),
	STRUCTURE_TYPE(0x0013),
	SUBROUTINE(0x0014),
	SUBROUTINE_TYPE(0x0015),
	TYPEDEF(0x0016),
	UNION_TYPE(0x0017),
	UNSPECIFIED_PARAMETERS(0x0018),
	VARIANT(0x0019),
	COMMON_BLOCK(0x001A),
	COMMON_INCLUSION(0x001B),
	INHERITANCE(0x001C),
	INLINED_SUBROUTINE(0x001D),
	MODULE(0x001E),
	PTR_TO_MEMBER_TYPE(0x001F),
	SET_TYPE(0x0020),
	SUBRANGE_TYPE(0x0021),
	WITH_STMT(0x0022),
	USER(null);
	
	private Integer value;

	private static final int LO_USER = 0x4080;
	private static final int HI_USER = 0xFFFF;
	private static final Map<Integer, Tag> VALUE_MAP;
	
	static {
		VALUE_MAP = Stream.of(Tag.values())
				.filter(tag -> tag.value != null)
				.collect(Collectors.toUnmodifiableMap(tag -> tag.value, Function.identity()));
	}
	
	Tag(Integer value) {
		this.value = value;
	}
	
	public static Tag decode(int value) {
		if (value >= LO_USER && value <= HI_USER) {
			return USER;
		}
		Tag tag = VALUE_MAP.get(value);
		if (tag == null) {
			throw new IllegalArgumentException("invalid tag value " + value);
		}
		return tag;
	}
}
