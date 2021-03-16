package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.AttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.BlockAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.ConstAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.FundamentalType;
import com.github.rafalh.ghidra.dwarfone.model.RefAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.TypeModifier;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;

public class DWARF1TypeExtractor {

	private final MessageLog log;
	private final DWARF1Program program;
	private final DWARF1TypeManager dwarfTypeManager;
	
	public DWARF1TypeExtractor(DWARF1Program program, MessageLog log, DWARF1TypeManager dwarfTypeManager) {
		this.program = program;
		this.log = log;
		this.dwarfTypeManager = dwarfTypeManager;
	}
	
	DataType extractDataType(DebugInfoEntry die) {
		Optional<FundamentalType> fundTypeOpt = die.<ConstAttributeValue>getAttribute(AttributeName.FUND_TYPE)
				.map(ConstAttributeValue::get)
				.map(Number::intValue)
				.map(FundamentalType::fromValue);
		Optional<RefAttributeValue> userDefTypeOpt = die.<RefAttributeValue>getAttribute(AttributeName.USER_DEF_TYPE);
		Optional<byte[]> modFundTypeOpt = die.<BlockAttributeValue>getAttribute(AttributeName.MOD_FUND_TYPE)
				.map(av -> av.get());
		Optional<byte[]> modUserDefTypeOpt = die.<BlockAttributeValue>getAttribute(AttributeName.MOD_U_D_TYPE)
				.map(av -> av.get());
		if (fundTypeOpt.isPresent()) {
			var ftDt = dwarfTypeManager.convertFundamentalTypeToDataType(fundTypeOpt.get());
			if (ftDt == null) {
				log.appendMsg("failed to map ft to dt: " + fundTypeOpt.get());
			}
			return Optional.ofNullable(ftDt).orElse(DataType.DEFAULT);
		}
		if (modFundTypeOpt.isPresent()) {
			return decodeModFundType(modFundTypeOpt.get());
		}
		if (userDefTypeOpt.isPresent()) {
			return dwarfTypeManager.getUserDataType(userDefTypeOpt.get().get());
		}
		if (modUserDefTypeOpt.isPresent()) {
			return decodeModUserDefType(modUserDefTypeOpt.get());
		}
		log.appendMsg("Unknown type " + die);
		return DataType.DEFAULT;
	}
	
	DataType extractDataType(AttributeName at, AttributeValue av) {
		switch (at) {
		case FUND_TYPE:
			FundamentalType ft = FundamentalType.fromValue(((ConstAttributeValue) av).get().intValue());
			return dwarfTypeManager.convertFundamentalTypeToDataType(ft);
		case USER_DEF_TYPE:
			return dwarfTypeManager.getUserDataType(((RefAttributeValue) av).get());
		case MOD_FUND_TYPE:
			return decodeModFundType(((BlockAttributeValue) av).get());
		case MOD_U_D_TYPE:
			return decodeModUserDefType(((BlockAttributeValue) av).get());
		default:
			throw new IllegalArgumentException("Unsupported type attribute " + at);
		}
	}
	
	private DataType decodeModFundType(byte[] data) {
		var bp = new ByteArrayProvider(data);
		BinaryReader br = new BinaryReader(bp, program.isLittleEndian());
		FundamentalType ft;
		List<TypeModifier> mods = new ArrayList<>();
		long maxOffset = bp.length() - 2;
		try {
			while (br.getPointerIndex() < maxOffset) {
				mods.add(TypeModifier.fromValue(br.readNextUnsignedByte()));
			}
			ft = FundamentalType.fromValue(br.readNextUnsignedShort());
		} catch (IOException e) {
			throw new IllegalStateException("Failed to decode mod fund type", e);
		}
		DataType baseDt = dwarfTypeManager.convertFundamentalTypeToDataType(ft);
		return applyTypeModifiers(mods, baseDt);
	}
	
	private DataType decodeModUserDefType(byte[] data) {
		var bp = new ByteArrayProvider(data);
		BinaryReader br = new BinaryReader(bp, program.isLittleEndian());
		Long udtRef;
		List<TypeModifier> mods = new ArrayList<>();
		long maxOffset = bp.length() - 4;
		try {
			while (br.getPointerIndex() < maxOffset) {
				mods.add(TypeModifier.fromValue(br.readNextUnsignedByte()));
			}
			udtRef = br.readNextUnsignedInt();
		} catch (IOException e) {
			throw new IllegalStateException("Failed to decode mod ud type", e);
		}
		DataType baseDt = dwarfTypeManager.getUserDataType(udtRef);
		return applyTypeModifiers(mods, baseDt);
	}
	
	private DataType applyTypeModifiers(List<TypeModifier> mods, DataType dt) {
		// apply modifiers in reverse order
		ListIterator<TypeModifier> it = mods.listIterator(mods.size());
		while (it.hasPrevious()) {
			TypeModifier mod = it.previous();
			if (mod == TypeModifier.POINTER_TO || mod == TypeModifier.REFERENCE_TO) {
				dt = new PointerDataType(dt);
			}
		}
		return dt;
	}
	
	
}
