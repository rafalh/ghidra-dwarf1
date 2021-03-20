package com.github.rafalh.ghidra.dwarfone;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AddrAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.RefAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.Tag;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DWARF1FunctionImporter {
	
	private static final Map<String, String> OPERATORS = Map.ofEntries(
			Map.entry("__pl", "+"),
			Map.entry("__apl", "+="),
			Map.entry("__mi", "-"),
			Map.entry("__ami", "-="),
			Map.entry("__ml", "*"),
			Map.entry("__amu", "*="),
			Map.entry("__dv", "/"),
			Map.entry("__adv", "/="),
			Map.entry("__as", "="),
			Map.entry("__pp", "++"),
			Map.entry("__lt", "<"),
			Map.entry("__gt", ">"),
			Map.entry("__le", "<="),
			Map.entry("__ge", ">="),
			Map.entry("__eq", "=="),
			Map.entry("__ne", "!="),
			Map.entry("__ls", "<<"),
			Map.entry("__als", "<<="),
			Map.entry("__rs", ">>"),
			Map.entry("__ars", ">>="),
			Map.entry("__er", "^"),
			Map.entry("__aer", "^="),
			Map.entry("__vc", "[]"),
			Map.entry("__cl", "()"),
			Map.entry("__nw", "new"),
			Map.entry("__nwa", "new[]"),
			Map.entry("__dl", "delete"),
			Map.entry("__dla", "delete[]")
	);
	private static final String CONSTRUCTOR = "__ct";
	private static final String DESTRUCTOR = "__dt";
	
	private final DWARF1Program dwarfProgram;
	private final MessageLog log;
	private final DWARF1TypeManager dwarfTypeManager;
	private final DWARF1TypeExtractor typeExtractor;
	private final FunctionManager functionManager;
	
	DWARF1FunctionImporter(DWARF1Program dwarfProgram, MessageLog log, DWARF1TypeManager dwarfTypeManager, DWARF1TypeExtractor typeExtractor) {
		this.dwarfProgram = dwarfProgram;
		this.log = log;
		this.dwarfTypeManager = dwarfTypeManager;
		this.typeExtractor = typeExtractor;
		functionManager = dwarfProgram.getProgram().getFunctionManager();
	}
	
	void processSubrountine(DebugInfoEntry die) {
		Optional<String> nameOptional = DWARF1ImportUtils.extractName(die);
		Optional<AddrAttributeValue> lowPcAttributeOptional = die.getAttribute(AttributeName.LOW_PC);
		Optional<AddrAttributeValue> highPcAttributeOptional = die.getAttribute(AttributeName.HIGH_PC);
		
		if (nameOptional.isEmpty() || lowPcAttributeOptional.isEmpty() || highPcAttributeOptional.isEmpty()) {
			return;
		}
		
		String name = nameOptional.get();
		long lowPc = lowPcAttributeOptional.get().get();
		long highPc = highPcAttributeOptional.get().get();
		//log.appendMsg(name + " " + Long.toHexString(lowPc.longValue()));
		DataType returnDt = typeExtractor.extractDataType(die);

		String op = OPERATORS.get(name);
		if (op != null) {
			// Note: symbol name cannot contain spaces
			String sep = Character.isLetter(op.charAt(0)) ? "_" : "";
			name = "operator" + sep + op;
		}
		if (name.startsWith("__op")) {
			// Cast operator
			name = "operator_" + returnDt.toString().replace(' ', '_');
		}
		
		// Prefix name with the class name if this is a member function
		Optional<DataType> classDtOpt = determineMemberClassType(die);
		if (classDtOpt.isPresent() && !name.contains(classDtOpt.get().getName())) {
			String className = classDtOpt.get().getName();
			if (name.equals(CONSTRUCTOR)) {
				name = className;
			} else if (name.equals(DESTRUCTOR)) {
				name = "~" + className;
			}
			name = className + "::" + name;
		}
		
		Address minAddr = dwarfProgram.toAddr(lowPc);
		Address maxAddr = dwarfProgram.toAddr(highPc - 1);
		AddressSetView funBody = dwarfProgram.getProgram().getAddressFactory().getAddressSet(minAddr, maxAddr);
		Iterator<Function> overlappingFunIt = functionManager.getFunctionsOverlapping(funBody);
		while (overlappingFunIt.hasNext()) {
			Function overlappingFun = overlappingFunIt.next();
			if (!overlappingFun.getEntryPoint().equals(minAddr)) {
				log.appendMsg("Removing overlapping function: " + overlappingFun.getName());
				functionManager.removeFunction(overlappingFun.getEntryPoint());
			}
		}
		Function fun = functionManager.getFunctionAt(minAddr);
		try {
			if (fun == null) {
				fun = functionManager.createFunction(name, minAddr, funBody, SourceType.IMPORTED);
			} else {
				fun.setName(name, SourceType.IMPORTED);
				fun.setBody(funBody);
			}
			
			Variable returnParam = new ReturnParameterImpl(returnDt, dwarfProgram.getProgram());
			List<Variable> params = new ArrayList<>();
			for (DebugInfoEntry childDie : die.getChildren()) {
				if (childDie.getTag() == Tag.FORMAL_PARAMETER) {
					String paramName = DWARF1ImportUtils.extractName(childDie).orElse(null);
					DataType dt = typeExtractor.extractDataType(childDie);
					params.add(new ParameterImpl(paramName, dt, dwarfProgram.getProgram()));
				}
			}
		
			fun.updateFunction(null, returnParam, params, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED);
		} catch (DuplicateNameException | InvalidInputException | OverlappingFunctionException e) {
			log.appendException(e);
		}
	}
	
	private Optional<DataType> determineMemberClassType(DebugInfoEntry die) {
		// Function defined in class body
		if (die.getParent().getTag() == Tag.CLASS_TYPE) {
			return Optional.of(dwarfTypeManager.getUserDataType(die.getParent().getRef()));
		}
		// Function defined outside of the class body should have AT_member attribute
		Optional<RefAttributeValue> memberAttributeOptional = die.getAttribute(AttributeName.MEMBER);
		if (memberAttributeOptional.isPresent()) {
			return Optional.of(dwarfTypeManager.getUserDataType(memberAttributeOptional.get().get()));
		}
		// Determine the class based on the "this" parameter because for some compilers (e.g. PS2) normal
		// ways does not work...
		for (DebugInfoEntry childDie : die.getChildren()) {
			if (childDie.getTag() == Tag.FORMAL_PARAMETER && Optional.of("this").equals(DWARF1ImportUtils.extractName(childDie))) {
				DataType dt = typeExtractor.extractDataType(childDie);
				if (dt instanceof Pointer) {
					dt = ((Pointer) dt).getDataType();
				}
				return Optional.of(dt);
			}
		}
		return Optional.empty();
	}
}
