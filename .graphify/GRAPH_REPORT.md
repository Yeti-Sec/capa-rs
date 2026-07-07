# Graph Report - Desktop/capa-rs  (2026-07-01)

## Corpus Check
- Large corpus: 704 files · ~1,080,335 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder, or use --no-semantic to run AST-only.

## Summary
- 8549 nodes · 14413 edges · 623 communities detected
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output
- Edge kinds: calls: 6762 · contains: 4186 · method: 3465


## Input Scope
- Requested: all
- Resolved: all (source: cli)
- Included files: 704 · Candidates: recursive
- Excluded: 0 untracked · 0 ignored · 4 sensitive · 0 missing committed

## Graph Freshness
- Built from Git commit: `ade7435`
- Compare this hash to `git rev-parse HEAD` before trusting freshness-sensitive graph output.
## God Nodes (most connected - your core abstractions)
1. `InstructionAssembler` - 118 edges
2. `LayoutPlanner<'a>` - 70 edges
3. `CilPrimitive` - 40 edges
4. `BuilderContext` - 39 edges
5. `CilAssembly` - 39 edges
6. `File` - 39 edges
7. `CilType` - 39 edges
8. `CilObject` - 38 edges
9. `TypeRegistry` - 35 edges
10. `MethodBuilder` - 32 edges

## Surprising Connections (you probably didn't know these)
- `write_errors()` --calls--> `write_be()`  [EXTRACTED]
  crates/dotscope/src/utils/io.rs → crates/dotscope/src/utils/io.rs  _Bridges community 219 → community 236_
- `round_trip_consistency()` --calls--> `write_le()`  [EXTRACTED]
  crates/dotscope/src/utils/io.rs → crates/dotscope/src/utils/io.rs  _Bridges community 488 → community 219_
- `round_trip_consistency()` --calls--> `write_be()`  [EXTRACTED]
  crates/dotscope/src/utils/io.rs → crates/dotscope/src/utils/io.rs  _Bridges community 488 → community 236_

## Communities

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (42): AssemblyIdentity, AssemblyVersion, ProcessorArchitecture, test_assembly_identity_display_name_simple(), test_assembly_identity_display_name_with_culture(), test_assembly_identity_display_name_with_ecma_key(), test_assembly_identity_display_name_with_pubkey(), test_assembly_identity_equality() (+34 more)

### Community 1 - "Community 1"
Cohesion: 0.08
Nodes (23): CilPrimitive, CilPrimitiveData, CilPrimitiveKind, i32, i64, test_as_byte(), test_cil_primitive_kind_from_byte(), test_constant_encoding_round_trip() (+15 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (20): &'a TypeRegistry, CompleteTypeSpec, SourceRegistry, test_create_and_lookup(), test_create_type_empty(), test_create_type_with_flavor(), test_enhanced_generic_instance_creation(), test_get_and_lookup_methods() (+12 more)

### Community 3 - "Community 3"
Cohesion: 0.03
Nodes (1): InstructionAssembler

### Community 4 - "Community 4"
Cohesion: 0.08
Nodes (36): DllDependency, DllSource, ImportEntry, NativeImportRef, test_add_multiple_native_functions_same_dll(), test_add_native_function(), test_add_native_function_by_ordinal(), test_add_native_function_by_ordinal_invalid() (+28 more)

### Community 5 - "Community 5"
Cohesion: 0.05
Nodes (18): FieldSignatureBuilder, LocalVariableSignatureBuilder, MethodSignatureBuilder, PropertySignatureBuilder, test_field_signature_builder(), test_field_signature_builder_validation_no_type(), test_field_signature_builder_with_modifiers(), test_local_variable_signature_builder() (+10 more)

### Community 6 - "Community 6"
Cohesion: 0.08
Nodes (35): ExportedFunction, ExportEntry, ExportSource, ExportTarget, NativeExportRef, test_add_multiple_native_functions(), test_add_native_forwarder(), test_add_native_function() (+27 more)

### Community 8 - "Community 8"
Cohesion: 0.05
Nodes (13): CilAssembly, create_console_writeline_ref(), create_writeline_signature(), test_add_blob(), test_add_guid(), test_add_string(), test_add_userstring(), test_convert_from_view() (+5 more)

### Community 10 - "Community 10"
Cohesion: 0.08
Nodes (44): AssemblyRefHash, bytes_to_hex(), create_test_md5_hash(), create_test_sha1_hash(), create_test_sha256_hash(), create_test_sha384_hash(), create_test_sha512_hash(), test_bytes_to_hex_empty() (+36 more)

### Community 11 - "Community 11"
Cohesion: 0.09
Nodes (27): add_duplicate_function_name_fails(), add_duplicate_ordinal_fails(), add_forwarder_invalid_format_fails(), add_forwarder_valid_formats(), add_forwarder_with_empty_target_fails(), add_forwarder_with_null_byte_fails(), add_forwarder_works(), add_function_by_ordinal_works() (+19 more)

### Community 12 - "Community 12"
Cohesion: 0.15
Nodes (16): get_test_context(), MethodBuilder, test_abstract_method(), test_constructor_builder(), test_event_add_method(), test_event_remove_method(), test_method_builder_basic(), test_method_builder_calling_convention_switching() (+8 more)

### Community 13 - "Community 13"
Cohesion: 0.07
Nodes (16): BinaryExtractor, BytePatternMatcher, format_api(), GoblinExtractor, insert_api(), is_printable_immediate(), normalize_module(), parse_number() (+8 more)

### Community 14 - "Community 14"
Cohesion: 0.08
Nodes (9): Backend, File, load_buffer(), load_file(), load_invalid(), test_align_to_file_alignment(), test_get_data_directory(), test_pe_headers_size() (+1 more)

### Community 15 - "Community 15"
Cohesion: 0.07
Nodes (10): test_two_stage_validation_result(), test_validation_outcome(), test_validation_result_combine(), test_validation_result_from_named_results(), test_validation_result_from_results(), test_validation_result_into_result(), test_validation_result_success(), TwoStageValidationResult (+2 more)

### Community 16 - "Community 16"
Cohesion: 0.07
Nodes (8): BuilderContext, test_builder_context_assembly_ref_lookup(), test_builder_context_core_library_lookup(), test_builder_context_creation(), test_builder_context_dynamic_table_discovery(), test_builder_context_heap_operations(), test_builder_context_signature_integration(), test_builder_context_string_deduplication()

### Community 17 - "Community 17"
Cohesion: 0.07
Nodes (5): CallingConvention, MethodParameter, MethodSignatureBuilder, ParameterDirection, ParameterListBuilder

### Community 18 - "Community 18"
Cohesion: 0.07
Nodes (13): create_empty_block(), create_test_method(), Method, MethodRef, test_instruction_iterator_size_hint(), test_instructions_iterator_all_empty_blocks(), test_instructions_iterator_empty_method(), test_instructions_iterator_many_empty_blocks() (+5 more)

### Community 19 - "Community 19"
Cohesion: 0.09
Nodes (18): HeapSizes, ReferenceScanner, ScannerStatistics, test_can_delete_token_functionality(), test_comprehensive_reference_coverage(), test_customattribute_references(), test_generic_parameter_references(), test_heap_size_analysis() (+10 more)

### Community 20 - "Community 20"
Cohesion: 0.06
Nodes (5): FieldBuilder, FieldConstant, FieldLayout, FieldLayoutBuilder, FieldMarshalling

### Community 21 - "Community 21"
Cohesion: 0.06
Nodes (12): test_complex_ast_structure(), test_feature_node_and(), test_feature_node_basic_block_subscope(), test_feature_node_count(), test_feature_node_function_subscope(), test_feature_node_instruction_subscope(), test_feature_node_match(), test_feature_node_n_or_more() (+4 more)

### Community 22 - "Community 22"
Cohesion: 0.09
Nodes (16): Parser, Parser<'a>, test_error_handling(), test_parse_string(), test_peek_le(), test_read_7bit_encoded_int_five_bytes(), test_read_7bit_encoded_int_four_bytes(), test_read_7bit_encoded_int_overflow() (+8 more)

### Community 23 - "Community 23"
Cohesion: 0.10
Nodes (18): AssemblyDependencyGraph, Color, TarjanState, test_assembly_count_increments_correctly(), test_assembly_count_with_self_reference(), test_concurrent_graph_operations(), test_dependency_graph_add_dependency(), test_dependency_graph_clear() (+10 more)

### Community 24 - "Community 24"
Cohesion: 0.06
Nodes (13): MethodTypeMapping, owned_context(), OwnedValidationContext, OwnedValidationContext<'a>, raw_loading_context(), raw_modification_context(), RawValidationContext, RawValidationContext<'a> (+5 more)

### Community 25 - "Community 25"
Cohesion: 0.07
Nodes (19): decode_blocks(), decode_instruction(), decode_instruction_basic(), decode_instruction_branch(), decode_instruction_int16_operand(), decode_instruction_invalid_opcode(), decode_instruction_switch(), decode_instruction_token() (+11 more)

### Community 26 - "Community 26"
Cohesion: 0.09
Nodes (31): CustomAttributeParser, CustomAttributeParser<'a>, parse_custom_attribute_blob(), parse_custom_attribute_blob_with_registry(), parse_custom_attribute_data(), parse_custom_attribute_data_with_registry(), test_empty_string_argument(), test_parse_array_argument_error() (+23 more)

### Community 27 - "Community 27"
Cohesion: 0.15
Nodes (23): ManifestResourceBuilder, test_manifest_resource_builder_basic(), test_manifest_resource_builder_clone(), test_manifest_resource_builder_comprehensive(), test_manifest_resource_builder_configure_encoder(), test_manifest_resource_builder_debug(), test_manifest_resource_builder_default(), test_manifest_resource_builder_embedded() (+15 more)

### Community 28 - "Community 28"
Cohesion: 0.08
Nodes (4): AttributeArgument, CustomAttributeBuilder, CustomAttributeListBuilder, NamedArgument

### Community 29 - "Community 29"
Cohesion: 0.08
Nodes (24): ResourceEntry, ResourceEntryRef, ResourceType, ResourceTypeRef, test_from_type_byte_boolean_false(), test_from_type_byte_boolean_true(), test_from_type_byte_byte(), test_from_type_byte_char() (+16 more)

### Community 30 - "Community 30"
Cohesion: 0.10
Nodes (24): create_test_permission(), Permission, test_clone(), test_debug_formatting(), test_display_formatting(), test_display_formatting_empty_args(), test_get_argument(), test_get_file_path_discovery() (+16 more)

### Community 31 - "Community 31"
Cohesion: 0.17
Nodes (21): FieldMarshalBuilder, test_field_marshal_builder_all_primitive_types(), test_field_marshal_builder_basic(), test_field_marshal_builder_complex_descriptors(), test_field_marshal_builder_custom_marshaler(), test_field_marshal_builder_different_native_types(), test_field_marshal_builder_different_parents(), test_field_marshal_builder_empty_native_type() (+13 more)

### Community 32 - "Community 32"
Cohesion: 0.14
Nodes (19): test_build_array(), test_build_byref(), test_build_class(), test_build_complex_chain(), test_build_failure(), test_build_function_pointer(), test_build_generic_instance(), test_build_interface() (+11 more)

### Community 33 - "Community 33"
Cohesion: 0.09
Nodes (1): CilType

### Community 34 - "Community 34"
Cohesion: 0.05
Nodes (2): make_features(), matches_rule()

### Community 35 - "Community 35"
Cohesion: 0.06
Nodes (1): CilObject

### Community 36 - "Community 36"
Cohesion: 0.15
Nodes (15): &'a Imports, Import, ImportContainer, Imports, ImportSourceId, ImportType, test_add_method_import(), test_add_type_import() (+7 more)

### Community 37 - "Community 37"
Cohesion: 0.06
Nodes (11): CilIO, read_be_at_dyn(), read_be_dyn(), read_le_at_dyn(), read_le_dyn(), test_write_string_utf8(), write_be_at_dyn(), write_be_dyn() (+3 more)

### Community 38 - "Community 38"
Cohesion: 0.05
Nodes (23): ArchType, AttackTechnique, CharacteristicType, CompiledRegex, CountConstraint, DynamicScope, Feature, FeatureNode (+15 more)

### Community 39 - "Community 39"
Cohesion: 0.06
Nodes (8): HeapChanges, HeapChanges<String>, HeapChanges<T>, ReferenceHandlingStrategy, test_heap_changes_indexing(), test_heap_changes_items_with_indices(), test_heap_changes_modifications(), test_heap_changes_removals()

### Community 40 - "Community 40"
Cohesion: 0.07
Nodes (1): LayoutPlanner<'a>

### Community 41 - "Community 41"
Cohesion: 0.15
Nodes (15): get_test_context(), PropertyAccessors, PropertyBuilder, PropertyImplementation, test_computed_property(), test_computed_property_missing_getter_fails(), test_computed_property_missing_setter_fails(), test_custom_backing_field() (+7 more)

### Community 42 - "Community 42"
Cohesion: 0.09
Nodes (26): test_binary_format(), test_binary_format_blob_bounds_checking(), test_binary_format_blob_end_seeking(), test_binary_format_different_assembly_names(), test_binary_format_empty_permission_set(), test_binary_format_multiple_permissions(), test_binary_format_out_of_bounds_class_name(), test_binary_format_string_property() (+18 more)

### Community 43 - "Community 43"
Cohesion: 0.10
Nodes (15): IndexRemapper, test_cross_reference_integrity_after_remapping(), test_cross_reference_update_comprehensive(), test_edge_case_all_items_removed(), test_edge_case_empty_heaps(), test_heap_identity_mapping_with_removed_items(), test_index_remapper_blob_heap_mapping(), test_index_remapper_empty_changes() (+7 more)

### Community 44 - "Community 44"
Cohesion: 0.06
Nodes (2): make_features(), matches_rule()

### Community 45 - "Community 45"
Cohesion: 0.11
Nodes (17): comprehensive_engine(), EngineStatistics, minimal_engine(), production_engine(), strict_engine(), test_all_validators_registered(), test_complete_two_stage_validation(), test_engine_statistics() (+9 more)

### Community 46 - "Community 46"
Cohesion: 0.13
Nodes (8): compute_resource_hash(), DotNetResourceEncoder, test_comprehensive_resource_encoder_api(), test_debug_encoder_format(), test_dotnet_resource_encoder_basic(), test_dotnet_resource_encoder_encoding(), test_large_resource_data(), test_roundtrip_edge_values()

### Community 47 - "Community 47"
Cohesion: 0.18
Nodes (15): ClassBuilder, FieldDefinition, get_test_context(), PropertyDefinition, test_abstract_class(), test_class_with_auto_properties(), test_class_with_inheritance(), test_class_with_interfaces() (+7 more)

### Community 48 - "Community 48"
Cohesion: 0.11
Nodes (30): build_iat_map(), build_string_map(), detect_loops(), detect_thunks(), ExecutableSection, find_function_in_gap(), find_go_functions_from_pclntab_elf(), format_operand() (+22 more)

### Community 49 - "Community 49"
Cohesion: 0.13
Nodes (7): Output, test_bounds_checking(), test_copy_range(), test_finalization(), test_mmap_file_creation(), test_write_operations(), test_zero_range()

### Community 50 - "Community 50"
Cohesion: 0.09
Nodes (6): CilAssemblyView, CilAssemblyViewData, CilAssemblyViewData<'a>, from_buffer(), from_file(), test_error_handling()

### Community 51 - "Community 51"
Cohesion: 0.22
Nodes (20): ExportedTypeBuilder, test_exported_type_builder_assembly_ref_implementation(), test_exported_type_builder_basic(), test_exported_type_builder_clone(), test_exported_type_builder_comprehensive(), test_exported_type_builder_debug(), test_exported_type_builder_default(), test_exported_type_builder_empty_name() (+12 more)

### Community 52 - "Community 52"
Cohesion: 0.12
Nodes (26): BasicBlock, test_basic_block_clone(), test_basic_block_debug_format(), test_basic_block_new(), test_basic_block_new_max_values(), test_basic_block_new_zero_values(), test_block_size_and_offset_boundaries(), test_complex_control_flow_scenario() (+18 more)

### Community 53 - "Community 53"
Cohesion: 0.08
Nodes (10): &'a ImportsInfo, ImportDeclaration, ImportKind, ImportsInfo, test_imports_info_equality(), test_imports_info_into_iter_borrowed(), test_imports_info_into_iter_owned(), test_imports_info_iter() (+2 more)

### Community 54 - "Community 54"
Cohesion: 0.12
Nodes (30): test_assembly_metadata_validation(), test_complex_generic_type(), test_custom_attribute_validation(), test_enum_and_constant_validation(), test_event_and_property_semantics(), test_extension_method_generic(), test_field_validation(), test_generic_constraint_validation() (+22 more)

### Community 55 - "Community 55"
Cohesion: 0.07
Nodes (9): FlowType, Immediate, Instruction, InstructionCategory, Operand, OperandType, StackBehavior, test_instruction_get_targets() (+1 more)

### Community 56 - "Community 56"
Cohesion: 0.17
Nodes (21): make_op_with_timestamp(), make_test_row(), TableModifications, test_apply_delete_operation(), test_apply_insert_operation(), test_apply_update_operation(), test_consolidate_operations_keeps_latest(), test_consolidate_operations_multiple_rids() (+13 more)

### Community 57 - "Community 57"
Cohesion: 0.10
Nodes (17): create_test_analyzer(), DependencyAnalyzer, FileRefType, ModuleRefType, perform_dependency_analysis(), test_classify_file_ref_documentation_file(), test_classify_file_ref_external_assembly_file(), test_classify_file_ref_intra_assembly_module() (+9 more)

### Community 59 - "Community 59"
Cohesion: 0.09
Nodes (5): GenericConstraint, GenericParameterBuilder, GenericTypeBuilder, GenericTypeInstantiationBuilder, GenericVariance

### Community 60 - "Community 60"
Cohesion: 0.16
Nodes (11): test_argument_optimization(), test_arithmetic_method(), test_bitwise_operations(), test_comparison_operations(), test_constant_optimization(), test_conversion_operations(), test_field_operations_with_tokens(), test_fluent_api_basic() (+3 more)

### Community 61 - "Community 61"
Cohesion: 0.17
Nodes (11): EventBuilder, EventImplementation, get_test_context(), test_custom_backing_field(), test_custom_event(), test_custom_event_missing_add_fails(), test_custom_event_missing_remove_fails(), test_event_with_different_accessor_visibility() (+3 more)

### Community 62 - "Community 62"
Cohesion: 0.22
Nodes (16): DocumentBuilder, test_document_builder_basic(), test_document_builder_clone(), test_document_builder_custom_guid(), test_document_builder_debug(), test_document_builder_default(), test_document_builder_empty_name(), test_document_builder_fluent_api() (+8 more)

### Community 63 - "Community 63"
Cohesion: 0.12
Nodes (7): add_dll_works(), ImportAddressEntry, ImportDescriptor, NativeImports, new_native_imports_is_empty(), test_ilt_multiple_functions_per_dll(), test_import_table_string_layout_fix()

### Community 64 - "Community 64"
Cohesion: 0.09
Nodes (10): Operation, TableOperation, test_table_operation_clone(), test_table_operation_get_rid(), test_table_operation_is_delete(), test_table_operation_is_insert(), test_table_operation_is_update(), test_table_operation_new_captures_timestamp() (+2 more)

### Community 65 - "Community 65"
Cohesion: 0.08
Nodes (6): AssemblyDependency, DependencyResolutionState, DependencyResolveContext, DependencySource, DependencyType, VersionRequirement

### Community 66 - "Community 66"
Cohesion: 0.17
Nodes (11): FileIOPermissionBuilder, PermissionSetBuilder, SecurityPermissionBuilder, test_builder_default_implementation(), test_compressed_format_encoding(), test_file_io_permission_builder(), test_mixed_permission_builder(), test_permission_set_builder_basic() (+3 more)

### Community 67 - "Community 67"
Cohesion: 0.10
Nodes (6): ArrayDimensions, CilFlavor, CilModifier, CilTypeRef, CilTypeReference, CilTypeRefListIter

### Community 68 - "Community 68"
Cohesion: 0.07
Nodes (6): Architecture, Compiler, Disassembler, Runtime, test_detect_capabilities(), TestCapabilities

### Community 69 - "Community 69"
Cohesion: 0.27
Nodes (16): AssemblyRefBuilder, test_assemblyref_builder_basic(), test_assemblyref_builder_clone(), test_assemblyref_builder_comprehensive(), test_assemblyref_builder_debug(), test_assemblyref_builder_empty_name(), test_assemblyref_builder_fluent_api(), test_assemblyref_builder_invalid_public_key_token_length() (+8 more)

### Community 70 - "Community 70"
Cohesion: 0.19
Nodes (13): get_test_context(), LabeledExceptionHandler, MethodBodyBuilder, resolve_labeled_exception_handler(), test_accurate_stack_tracking(), test_filter_handler_with_labels(), test_method_body_builder_basic(), test_method_body_builder_complex_method() (+5 more)

### Community 71 - "Community 71"
Cohesion: 0.09
Nodes (4): ParamBuilder, ParamDefault, ParamDirection, ParamListBuilder

### Community 72 - "Community 72"
Cohesion: 0.09
Nodes (3): AssemblyChanges, test_assembly_changes_empty(), test_binary_heap_sizes()

### Community 73 - "Community 73"
Cohesion: 0.14
Nodes (20): encode_marshalling_descriptor(), MarshallingEncoder, test_encode_descriptor_into(), test_roundtrip_complex_nested_types(), test_roundtrip_comprehensive_scenarios(), test_roundtrip_custom_marshaler(), test_roundtrip_descriptors_with_additional_types(), test_roundtrip_fixed_array_types() (+12 more)

### Community 74 - "Community 74"
Cohesion: 0.12
Nodes (11): ReferenceAnalysis, ReferenceStatistics, ReferenceValidator, ReferenceValidator<'a>, test_circular_reference_detection(), test_deletion_safety_validation(), test_forward_reference_validation(), test_parent_child_relationship_validation() (+3 more)

### Community 76 - "Community 76"
Cohesion: 0.17
Nodes (25): parse_boolean_children(), parse_bytes_feature(), parse_count_constraint(), parse_feature_by_key(), parse_feature_from_count_spec(), parse_feature_node(), parse_features(), parse_not_child() (+17 more)

### Community 77 - "Community 77"
Cohesion: 0.18
Nodes (21): create_empty_blob_stream(), create_test_blob_stream(), ImportsParser, ImportsParser<'a>, parse_imports_blob(), test_assembly_ref_token_format(), test_imports_info_iteration(), test_imports_parser_new() (+13 more)

### Community 78 - "Community 78"
Cohesion: 0.10
Nodes (3): encode_permission_set(), PermissionSetEncoder, test_xml_escaping()

### Community 79 - "Community 79"
Cohesion: 0.14
Nodes (2): OwnedInheritanceValidator, test_owned_inheritance_validator_comprehensive()

### Community 81 - "Community 81"
Cohesion: 0.17
Nodes (11): get_mnemonic_lookup(), InstructionEncoder, LabelFixup, test_duplicate_label(), test_encoder_creation(), test_instruction_with_operands(), test_invalid_mnemonic(), test_label_resolution() (+3 more)

### Community 82 - "Community 82"
Cohesion: 0.14
Nodes (1): MethodBuilder

### Community 83 - "Community 83"
Cohesion: 0.15
Nodes (21): analyze_method_completely(), find_suitable_method(), format_operand(), main(), print_additional_metadata(), print_basic_block_analysis(), print_basic_il_statistics(), print_control_flow_analysis() (+13 more)

### Community 84 - "Community 84"
Cohesion: 0.15
Nodes (21): Identity, test_from_exact_8_bytes(), test_from_more_than_8_bytes_token(), test_hash_algorithm_consistency(), test_identity_from_ecma_key(), test_identity_from_empty_pubkey(), test_identity_from_pubkey(), test_identity_from_token() (+13 more)

### Community 85 - "Community 85"
Cohesion: 0.20
Nodes (10): SignatureParser, SignatureParser<'a>, test_complex_signature(), test_error_handling(), test_parse_arrays(), test_parse_class_and_valuetype(), test_parse_custom_mods(), test_parse_generic_instance() (+2 more)

### Community 86 - "Community 86"
Cohesion: 0.13
Nodes (9): SchemaValidationStatistics, SchemaValidator, SchemaValidator<'a>, test_basic_structure_validation(), test_coded_index_validation(), test_heap_reference_validation(), test_rid_validation(), test_schema_validator_creation() (+1 more)

### Community 87 - "Community 87"
Cohesion: 0.20
Nodes (13): bitfield_boundary(), bitfield_boundary_exact(), clear_many(), clear_one(), create_big(), create_small(), get_first_true(), get_range() (+5 more)

### Community 88 - "Community 88"
Cohesion: 0.35
Nodes (16): AssemblyRefOSBuilder, test_assemblyrefos_builder_clone(), test_assemblyrefos_builder_custom_os(), test_assemblyrefos_builder_debug(), test_assemblyrefos_builder_default(), test_assemblyrefos_builder_fluent_interface(), test_assemblyrefos_builder_large_assembly_ref(), test_assemblyrefos_builder_missing_assembly_ref() (+8 more)

### Community 89 - "Community 89"
Cohesion: 0.21
Nodes (10): get_test_context(), InterfaceBuilder, InterfaceMethodDefinition, InterfacePropertyDefinition, test_empty_interface(), test_empty_name_fails(), test_interface_inheritance(), test_interface_with_properties() (+2 more)

### Community 90 - "Community 90"
Cohesion: 0.15
Nodes (19): load_sample(), sample_path(), test_all_samples_have_entry_point(), test_dotnet_detected(), test_dotnet_imports(), test_dotnet_sample_format_detection(), test_elf_has_executable_section(), test_elf_not_dotnet() (+11 more)

### Community 91 - "Community 91"
Cohesion: 0.29
Nodes (13): ConstantBuilder, test_constant_builder_all_primitive_types(), test_constant_builder_basic_integer(), test_constant_builder_boolean(), test_constant_builder_i4_convenience(), test_constant_builder_invalid_element_type(), test_constant_builder_invalid_parent_type(), test_constant_builder_missing_element_type() (+5 more)

### Community 92 - "Community 92"
Cohesion: 0.31
Nodes (14): DeclSecurityBuilder, test_decl_security_builder_basic(), test_decl_security_builder_different_actions(), test_decl_security_builder_different_parents(), test_decl_security_builder_empty_permission_set(), test_decl_security_builder_invalid_parent_type(), test_decl_security_builder_missing_action(), test_decl_security_builder_missing_parent() (+6 more)

### Community 93 - "Community 93"
Cohesion: 0.20
Nodes (13): test_build_without_signature_fails(), test_complex_nested_generic(), test_direct_signature(), test_function_pointer(), test_generic_instantiation(), test_managed_reference(), test_multi_dimensional_array(), test_multiple_typespecs() (+5 more)

### Community 94 - "Community 94"
Cohesion: 0.13
Nodes (15): test_encode_array(), test_encode_byref(), test_encode_complex_nested_generic(), test_encode_generic_instantiation(), test_encode_generic_parameters(), test_encode_invalid_token(), test_encode_invalid_types(), test_encode_pinned_type() (+7 more)

### Community 95 - "Community 95"
Cohesion: 0.20
Nodes (15): test_recursion_limit(), test_resolve_array(), test_resolve_byref(), test_resolve_class_and_valuetype(), test_resolve_fn_ptr(), test_resolve_generic_instance(), test_resolve_generic_params(), test_resolve_modifiers() (+7 more)

### Community 96 - "Community 96"
Cohesion: 0.17
Nodes (23): create_test_assembly(), perform_method_round_trip_test(), perform_round_trip_test(), test_blob_heap_modifications_round_trip(), test_builder_context_round_trip(), test_complex_method_with_branching_roundtrip(), test_empty_operations_round_trip(), test_guid_heap_additions_round_trip() (+15 more)

### Community 97 - "Community 97"
Cohesion: 0.12
Nodes (1): PermissionSet

### Community 98 - "Community 98"
Cohesion: 0.33
Nodes (16): AssemblyOSBuilder, test_assemblyos_builder_clone(), test_assemblyos_builder_custom(), test_assemblyos_builder_debug(), test_assemblyos_builder_default(), test_assemblyos_builder_fluent_interface(), test_assemblyos_builder_linux(), test_assemblyos_builder_max_values() (+8 more)

### Community 99 - "Community 99"
Cohesion: 0.37
Nodes (16): ClassLayoutBuilder, test_class_layout_builder_all_valid_packing_sizes(), test_class_layout_builder_basic(), test_class_layout_builder_default_packing(), test_class_layout_builder_different_packings(), test_class_layout_builder_excessive_class_size(), test_class_layout_builder_excessive_packing_size(), test_class_layout_builder_explicit_sizes() (+8 more)

### Community 100 - "Community 100"
Cohesion: 0.26
Nodes (14): EncLogBuilder, test_enclog_builder_clone(), test_enclog_builder_convenience_methods(), test_enclog_builder_create_method(), test_enclog_builder_debug(), test_enclog_builder_default(), test_enclog_builder_delete_field(), test_enclog_builder_fluent_interface() (+6 more)

### Community 101 - "Community 101"
Cohesion: 0.28
Nodes (14): FileBuilder, test_file_builder_basic(), test_file_builder_clone(), test_file_builder_comprehensive(), test_file_builder_contains_metadata(), test_file_builder_contains_no_metadata(), test_file_builder_debug(), test_file_builder_empty_hash() (+6 more)

### Community 102 - "Community 102"
Cohesion: 0.26
Nodes (12): MethodImplBuilder, test_build_without_class_fails(), test_build_without_method_body_fails(), test_build_without_method_declaration_fails(), test_direct_coded_index(), test_explicit_interface_implementation(), test_external_method_body(), test_interface_implementation() (+4 more)

### Community 103 - "Community 103"
Cohesion: 0.30
Nodes (14): MethodSemanticsBuilder, test_build_without_association_fails(), test_build_without_method_fails(), test_build_without_semantics_fails(), test_combined_semantics(), test_direct_coded_index(), test_event_add_semantic(), test_event_fire_semantic() (+6 more)

### Community 104 - "Community 104"
Cohesion: 0.26
Nodes (18): PropertyPtrBuilder, test_propertyptr_builder_basic(), test_propertyptr_builder_clone(), test_propertyptr_builder_compressed_metadata_scenario(), test_propertyptr_builder_debug(), test_propertyptr_builder_default(), test_propertyptr_builder_edit_continue_property_scenario(), test_propertyptr_builder_fluent_interface() (+10 more)

### Community 105 - "Community 105"
Cohesion: 0.12
Nodes (2): TableInfo, TableRowInfo

### Community 106 - "Community 106"
Cohesion: 0.12
Nodes (11): FileStructureLayout, MetadataComponentSizes, MetadataLayout, NativeTableRequirements, PlanningInfo, SectionLayout, SizeBreakdown, StreamLayout (+3 more)

### Community 107 - "Community 107"
Cohesion: 0.18
Nodes (21): parse_field_signature(), parse_local_var_signature(), parse_method_signature(), parse_method_spec_signature(), parse_property_signature(), parse_type_spec_signature(), test_byref_parameters_comprehensive(), test_complex_signature_roundtrips() (+13 more)

### Community 108 - "Community 108"
Cohesion: 0.14
Nodes (10): TablesHeader, TablesHeader<'a>, TableSummary, test_has_table(), test_has_table_by_id(), test_table_count(), test_table_summary(), test_tables_header_empty_tables() (+2 more)

### Community 109 - "Community 109"
Cohesion: 0.27
Nodes (17): EventPtrBuilder, test_eventptr_builder_basic(), test_eventptr_builder_clone(), test_eventptr_builder_complex_indirection_scenario(), test_eventptr_builder_debug(), test_eventptr_builder_default(), test_eventptr_builder_edit_continue_scenario(), test_eventptr_builder_event_ordering_scenario() (+9 more)

### Community 110 - "Community 110"
Cohesion: 0.14
Nodes (2): OwnedSecurityValidator, test_owned_security_validator()

### Community 111 - "Community 111"
Cohesion: 0.18
Nodes (6): CilProject, test_cilproject_creation(), test_cilproject_default(), test_get_primary_with_loader(), test_load_crafted2_exe(), test_load_windowsbase_dll()

### Community 112 - "Community 112"
Cohesion: 0.15
Nodes (11): disassemble(), disassemble_with(), disassemble_with_caps(), disassemble_with_dotnet_ildasm(), disassemble_with_ildasm(), disassemble_with_monodis(), DisassemblyResult, test_disassemble_assembly() (+3 more)

### Community 113 - "Community 113"
Cohesion: 0.16
Nodes (8): generate_test_program(), MethodTest, ReflectionTestResult, run_reflection_test(), test_generate_test_program(), test_method_test_builder(), test_reflection_on_simple_class(), verify_assembly_loadable()

### Community 114 - "Community 114"
Cohesion: 0.31
Nodes (15): AssemblyRefProcessorBuilder, test_assemblyrefprocessor_builder_arm64(), test_assemblyrefprocessor_builder_clone(), test_assemblyrefprocessor_builder_custom_processor(), test_assemblyrefprocessor_builder_debug(), test_assemblyrefprocessor_builder_default(), test_assemblyrefprocessor_builder_fluent_interface(), test_assemblyrefprocessor_builder_large_assembly_ref() (+7 more)

### Community 115 - "Community 115"
Cohesion: 0.10
Nodes (5): ConstantBuilder, ConstantRawBuilder, create_test_blob_with_values(), test_blob_creation(), test_constant_raw_builder()

### Community 116 - "Community 116"
Cohesion: 0.15
Nodes (11): build_iat_map(), build_string_map(), build_thunk_map(), dtype_to_size_idx(), format_operand(), lift_cfg(), lift_from_idb(), lift_instructions() (+3 more)

### Community 117 - "Community 117"
Cohesion: 0.20
Nodes (11): count_string_matches(), match_string(), match_substring(), MatchEngine, RuleMatch, test_and_operator(), test_case_insensitive_api_match(), test_count_constraint() (+3 more)

### Community 118 - "Community 118"
Cohesion: 0.10
Nodes (2): test_write_executor_with_basic_layout(), WriteExecutor

### Community 119 - "Community 119"
Cohesion: 0.11
Nodes (8): CopyOperation, OperationSet, test_operation_set_creation(), test_operation_size_calculations(), test_operation_validation_no_overlap(), test_operation_validation_with_overlap(), WriteOperation, ZeroOperation

### Community 120 - "Community 120"
Cohesion: 0.19
Nodes (13): &'a UserStrings<'a>, crafted(), invalid(), test_userstrings_iterator_basic(), test_userstrings_iterator_empty_string(), test_userstrings_iterator_invalid_utf16_length(), test_userstrings_iterator_long_string(), test_userstrings_iterator_multiple() (+5 more)

### Community 121 - "Community 121"
Cohesion: 0.39
Nodes (13): GenericParamBuilder, test_generic_param_builder_all_constraint_types(), test_generic_param_builder_basic(), test_generic_param_builder_covariant(), test_generic_param_builder_invalid_flags(), test_generic_param_builder_invalid_number(), test_generic_param_builder_invalid_owner_type(), test_generic_param_builder_method_parameter() (+5 more)

### Community 122 - "Community 122"
Cohesion: 0.32
Nodes (11): LocalScopeBuilder, test_localscope_builder_basic(), test_localscope_builder_clone(), test_localscope_builder_debug(), test_localscope_builder_invalid_method_table(), test_localscope_builder_missing_length(), test_localscope_builder_missing_method(), test_localscope_builder_missing_start_offset() (+3 more)

### Community 123 - "Community 123"
Cohesion: 0.37
Nodes (11): MethodDefBuilder, test_method_builder_basic(), test_method_builder_default_values(), test_method_builder_instance_constructor(), test_method_builder_missing_flags(), test_method_builder_missing_impl_flags(), test_method_builder_missing_name(), test_method_builder_missing_signature() (+3 more)

### Community 124 - "Community 124"
Cohesion: 0.33
Nodes (15): NestedClassBuilder, test_nested_class_builder_basic(), test_nested_class_builder_clone(), test_nested_class_builder_debug(), test_nested_class_builder_deep_nesting(), test_nested_class_builder_default(), test_nested_class_builder_fluent_api(), test_nested_class_builder_invalid_enclosing_token() (+7 more)

### Community 125 - "Community 125"
Cohesion: 0.28
Nodes (16): ParamPtrBuilder, test_paramptr_builder_basic(), test_paramptr_builder_clone(), test_paramptr_builder_compressed_metadata_scenario(), test_paramptr_builder_debug(), test_paramptr_builder_default(), test_paramptr_builder_edit_continue_parameter_scenario(), test_paramptr_builder_fluent_interface() (+8 more)

### Community 127 - "Community 127"
Cohesion: 0.16
Nodes (16): Conflict, ConflictResolver, LastWriteWinsResolver, OperationResolution, Resolution, test_insert_delete_conflict_validation_invalid_delete_op(), test_insert_delete_conflict_validation_invalid_insert_op(), test_insert_delete_conflict_validation_update_operations() (+8 more)

### Community 128 - "Community 128"
Cohesion: 0.35
Nodes (13): CustomDebugInformationBuilder, test_customdebuginformation_builder_clone(), test_customdebuginformation_builder_debug(), test_customdebuginformation_builder_default(), test_customdebuginformation_builder_document_parent(), test_customdebuginformation_builder_empty_value(), test_customdebuginformation_builder_fluent_interface(), test_customdebuginformation_builder_method_parent() (+5 more)

### Community 129 - "Community 129"
Cohesion: 0.18
Nodes (13): CustomDebugParser, CustomDebugParser<'a>, parse_custom_debug_blob(), test_custom_debug_parser_new(), test_parse_compilation_metadata(), test_parse_compilation_options(), test_parse_embedded_source_negative_format(), test_parse_embedded_source_too_small() (+5 more)

### Community 130 - "Community 130"
Cohesion: 0.23
Nodes (14): LayoutPlanner, load_test_assembly(), test_calculate_tables_header_size_all_tables(), test_calculate_tables_header_size_full(), test_calculate_tables_header_size_full_empty(), test_plan_complete_layout_basic(), test_plan_complete_layout_has_metadata_section(), test_plan_complete_layout_metadata_layout() (+6 more)

### Community 131 - "Community 131"
Cohesion: 0.26
Nodes (9): NativeExportsBuilder, test_native_exports_builder_auto_ordinals(), test_native_exports_builder_basic(), test_native_exports_builder_dll_name_change(), test_native_exports_builder_empty(), test_native_exports_builder_fluent_api(), test_native_exports_builder_mixed_ordinals(), test_native_exports_builder_with_forwarders() (+1 more)

### Community 132 - "Community 132"
Cohesion: 0.26
Nodes (11): NativeImportsBuilder, test_native_imports_builder_auto_dll_addition(), test_native_imports_builder_basic(), test_native_imports_builder_duplicate_dlls(), test_native_imports_builder_empty(), test_native_imports_builder_fluent_api(), test_native_imports_builder_validation_dll_with_path(), test_native_imports_builder_validation_empty_dll() (+3 more)

### Community 133 - "Community 133"
Cohesion: 0.22
Nodes (12): MarshallingParser, MarshallingParser<'a>, parse_marshalling_descriptor(), test_error_conditions(), test_parse_array(), test_parse_complete_descriptor(), test_parse_custom_marshaler(), test_parse_fixed_array() (+4 more)

### Community 134 - "Community 134"
Cohesion: 0.18
Nodes (11): &'a Guid<'a>, crafted(), Guid, Guid<'a>, GuidIterator, GuidIterator<'a>, test_guid_index_calculation_correctness(), test_guid_iterator_basic() (+3 more)

### Community 135 - "Community 135"
Cohesion: 0.27
Nodes (14): EncMapBuilder, test_encmap_builder_clone(), test_encmap_builder_debug(), test_encmap_builder_default(), test_encmap_builder_field_token(), test_encmap_builder_fluent_interface(), test_encmap_builder_large_token_values(), test_encmap_builder_method_token() (+6 more)

### Community 136 - "Community 136"
Cohesion: 0.36
Nodes (14): GenericParamConstraintBuilder, test_generic_param_constraint_builder_all_constraint_types(), test_generic_param_constraint_builder_base_class(), test_generic_param_constraint_builder_basic(), test_generic_param_constraint_builder_different_parameters(), test_generic_param_constraint_builder_generic_type(), test_generic_param_constraint_builder_interface(), test_generic_param_constraint_builder_invalid_constraint_type() (+6 more)

### Community 137 - "Community 137"
Cohesion: 0.28
Nodes (15): MethodPtrBuilder, test_methodptr_builder_basic(), test_methodptr_builder_clone(), test_methodptr_builder_debug(), test_methodptr_builder_default(), test_methodptr_builder_edit_continue_scenario(), test_methodptr_builder_fluent_interface(), test_methodptr_builder_hot_reload_scenario() (+7 more)

### Community 138 - "Community 138"
Cohesion: 0.32
Nodes (11): MethodSpecBuilder, test_method_spec_builder_basic(), test_method_spec_builder_complex_instantiations(), test_method_spec_builder_convenience_methods(), test_method_spec_builder_different_methods(), test_method_spec_builder_empty_instantiation(), test_method_spec_builder_invalid_method_type(), test_method_spec_builder_missing_instantiation() (+3 more)

### Community 139 - "Community 139"
Cohesion: 0.26
Nodes (7): test_typedef_builder_basic(), test_typedef_builder_global_namespace(), test_typedef_builder_interface(), test_typedef_builder_missing_name(), test_typedef_builder_value_type(), test_typedef_builder_with_base_type(), TypeDefBuilder

### Community 140 - "Community 140"
Cohesion: 0.18
Nodes (4): ProjectLoader, test_project_loader_basic_api(), test_project_loader_build_fails_without_primary(), test_project_loader_validation_errors()

### Community 141 - "Community 141"
Cohesion: 0.10
Nodes (2): ProjectResult, VersionMismatch

### Community 142 - "Community 142"
Cohesion: 0.29
Nodes (14): AssemblyProcessorBuilder, test_assemblyprocessor_builder_clone(), test_assemblyprocessor_builder_custom(), test_assemblyprocessor_builder_debug(), test_assemblyprocessor_builder_default(), test_assemblyprocessor_builder_fluent_interface(), test_assemblyprocessor_builder_ia64(), test_assemblyprocessor_builder_max_processor() (+6 more)

### Community 143 - "Community 143"
Cohesion: 0.33
Nodes (10): EnumBuilder, EnumValueDefinition, get_test_context(), test_byte_enum(), test_empty_enum(), test_empty_name_fails(), test_flags_enum(), test_internal_enum() (+2 more)

### Community 145 - "Community 145"
Cohesion: 0.18
Nodes (14): hidden_constructor(), new_hidden_sequence_point(), new_invalid_end_col_before_start_same_line(), new_invalid_end_line_before_start(), new_valid_end_col_equals_start_col(), new_valid_multi_line_sequence_point(), new_valid_single_line_sequence_point(), parse_empty_blob() (+6 more)

### Community 146 - "Community 146"
Cohesion: 0.20
Nodes (11): &'a Blob<'a>, Blob, Blob<'a>, BlobIterator, BlobIterator<'a>, crafted(), test_blob_iterator_basic(), test_blob_iterator_empty_blob() (+3 more)

### Community 147 - "Community 147"
Cohesion: 0.35
Nodes (13): EventMapBuilder, test_event_map_builder_basic(), test_event_map_builder_clone(), test_event_map_builder_debug(), test_event_map_builder_default(), test_event_map_builder_fluent_api(), test_event_map_builder_invalid_parent_token(), test_event_map_builder_missing_event_list() (+5 more)

### Community 148 - "Community 148"
Cohesion: 0.37
Nodes (13): FieldLayoutBuilder, test_field_layout_builder_basic(), test_field_layout_builder_different_offsets(), test_field_layout_builder_invalid_field_token(), test_field_layout_builder_large_offsets(), test_field_layout_builder_missing_field(), test_field_layout_builder_missing_field_offset(), test_field_layout_builder_multiple_layouts() (+5 more)

### Community 149 - "Community 149"
Cohesion: 0.35
Nodes (13): FieldRVABuilder, test_field_rva_builder_basic(), test_field_rva_builder_clone(), test_field_rva_builder_debug(), test_field_rva_builder_default(), test_field_rva_builder_fluent_api(), test_field_rva_builder_invalid_field_token(), test_field_rva_builder_missing_field() (+5 more)

### Community 150 - "Community 150"
Cohesion: 0.40
Nodes (11): ImplMapBuilder, test_implmap_builder_basic(), test_implmap_builder_default(), test_implmap_builder_field_reference(), test_implmap_builder_invalid_coded_index(), test_implmap_builder_missing_import_name(), test_implmap_builder_missing_import_scope(), test_implmap_builder_missing_member_forwarded() (+3 more)

### Community 151 - "Community 151"
Cohesion: 0.33
Nodes (12): LocalVariableBuilder, test_localvariable_builder_anonymous_variable(), test_localvariable_builder_basic(), test_localvariable_builder_clone(), test_localvariable_builder_debug(), test_localvariable_builder_default(), test_localvariable_builder_fluent_interface(), test_localvariable_builder_missing_index() (+4 more)

### Community 152 - "Community 152"
Cohesion: 0.35
Nodes (13): PropertyMapBuilder, test_property_map_builder_basic(), test_property_map_builder_clone(), test_property_map_builder_debug(), test_property_map_builder_default(), test_property_map_builder_fluent_api(), test_property_map_builder_invalid_parent_token(), test_property_map_builder_missing_parent() (+5 more)

### Community 153 - "Community 153"
Cohesion: 0.33
Nodes (13): StateMachineMethodBuilder, test_statemachinemethod_builder_async_mapping(), test_statemachinemethod_builder_basic(), test_statemachinemethod_builder_clone(), test_statemachinemethod_builder_debug(), test_statemachinemethod_builder_default(), test_statemachinemethod_builder_fluent_interface(), test_statemachinemethod_builder_iterator_mapping() (+5 more)

### Community 154 - "Community 154"
Cohesion: 0.14
Nodes (4): RawHeapValidator, test_raw_heap_validator(), test_raw_heap_validator_configuration(), test_raw_heap_validator_metadata()

### Community 155 - "Community 155"
Cohesion: 0.11
Nodes (1): ResourceTypeRef<'_>

### Community 156 - "Community 156"
Cohesion: 0.11
Nodes (1): ResourceType

### Community 157 - "Community 157"
Cohesion: 0.22
Nodes (8): property_accepting_constants(), property_rejecting_constants(), property_with_default_set(), PropertyBuilder, PropertyConstant, test_helper_functions(), test_property_builder_basic(), test_property_with_default()

### Community 158 - "Community 158"
Cohesion: 0.22
Nodes (15): encode_custom_attribute_argument(), encode_custom_attribute_value(), encode_fixed_arguments(), encode_named_arguments(), get_serialization_type_tag(), test_debug_named_args_encoding(), test_debug_type_args_encoding(), test_encode_array_argument() (+7 more)

### Community 159 - "Community 159"
Cohesion: 0.19
Nodes (5): &'a Exports, Exports, find_by_name_works(), iter_works(), new_exports_is_empty()

### Community 160 - "Community 160"
Cohesion: 0.13
Nodes (5): &'a Resources, parse_resources(), ResourceData, Resources, test_owned_vs_ref_equivalence()

### Community 161 - "Community 161"
Cohesion: 0.16
Nodes (9): NamedArgument, test_clone(), test_debug_formatting(), test_display_formatting(), test_is_boolean(), test_is_integer(), test_is_string(), test_named_argument_getters() (+1 more)

### Community 162 - "Community 162"
Cohesion: 0.30
Nodes (13): FieldPtrBuilder, test_fieldptr_builder_basic(), test_fieldptr_builder_clone(), test_fieldptr_builder_debug(), test_fieldptr_builder_default(), test_fieldptr_builder_field_ordering_scenario(), test_fieldptr_builder_fluent_interface(), test_fieldptr_builder_large_field_rid() (+5 more)

### Community 163 - "Community 163"
Cohesion: 0.33
Nodes (12): ImportScopeBuilder, test_importscope_builder_child_scope(), test_importscope_builder_clone(), test_importscope_builder_debug(), test_importscope_builder_default(), test_importscope_builder_empty_imports(), test_importscope_builder_fluent_interface(), test_importscope_builder_missing_imports() (+4 more)

### Community 164 - "Community 164"
Cohesion: 0.42
Nodes (11): MemberRefBuilder, test_memberref_builder_basic(), test_memberref_builder_constructor_reference(), test_memberref_builder_field_reference(), test_memberref_builder_generic_type_reference(), test_memberref_builder_invalid_class_type(), test_memberref_builder_missing_class(), test_memberref_builder_missing_name() (+3 more)

### Community 165 - "Community 165"
Cohesion: 0.26
Nodes (9): generate_random_guid(), ModuleBuilder, test_guid_generation(), test_module_builder_basic(), test_module_builder_default(), test_module_builder_generation(), test_module_builder_missing_name(), test_module_builder_with_enc_support() (+1 more)

### Community 166 - "Community 166"
Cohesion: 0.22
Nodes (2): OwnedAssemblyValidator, test_owned_assembly_validator()

### Community 167 - "Community 167"
Cohesion: 0.25
Nodes (16): create_assembly_with_conflicting_inserts(), create_assembly_with_excessive_rid(), create_assembly_with_excessive_updates(), create_assembly_with_invalid_rid_zero(), create_assembly_with_nonexistent_target(), create_assembly_with_unordered_operations(), create_assembly_with_update_after_delete(), create_corrupted_changes_with_conflicting_inserts() (+8 more)

### Community 168 - "Community 168"
Cohesion: 0.20
Nodes (11): ChildExt, execute(), execute_and_verify(), execute_with_dotnet(), execute_with_mono(), execute_with_runtime(), execute_with_timeout(), ExecutionResult (+3 more)

### Community 169 - "Community 169"
Cohesion: 0.12
Nodes (2): CustomDebugInfo, CustomDebugKind

### Community 170 - "Community 170"
Cohesion: 0.15
Nodes (3): parse_dotnet_resource(), parse_dotnet_resource_ref(), Resource

### Community 171 - "Community 171"
Cohesion: 0.22
Nodes (16): encode_custom_modifier(), encode_field_signature(), encode_local_var_signature(), encode_method_signature(), encode_parameter(), encode_property_signature(), encode_type_def_or_ref_coded_index(), encode_typespec_signature() (+8 more)

### Community 172 - "Community 172"
Cohesion: 0.19
Nodes (9): &'a Strings<'a>, crafted(), Strings, Strings<'a>, StringsIterator, StringsIterator<'a>, test_strings_iterator(), test_strings_iterator_empty_strings() (+1 more)

### Community 173 - "Community 173"
Cohesion: 0.34
Nodes (11): LocalConstantBuilder, test_localconstant_builder_anonymous_constant(), test_localconstant_builder_basic(), test_localconstant_builder_clone(), test_localconstant_builder_debug(), test_localconstant_builder_default(), test_localconstant_builder_fluent_interface(), test_localconstant_builder_missing_name() (+3 more)

### Community 174 - "Community 174"
Cohesion: 0.21
Nodes (2): OwnedAttributeValidator, test_owned_attribute_validator()

### Community 175 - "Community 175"
Cohesion: 0.19
Nodes (2): OwnedTypeDefinitionValidator, test_owned_type_definition_validator()

### Community 176 - "Community 176"
Cohesion: 0.19
Nodes (13): BinaryInfo, ExportInfo, extract_strings(), ImportInfo, load_binary(), load_binary_with_format(), load_elf(), load_pe() (+5 more)

### Community 177 - "Community 177"
Cohesion: 0.23
Nodes (2): OwnedTypeConstraintValidator, test_owned_type_constraint_validator_comprehensive()

### Community 178 - "Community 178"
Cohesion: 0.40
Nodes (9): CustomAttributeBuilder, test_custom_attribute_builder_basic(), test_custom_attribute_builder_invalid_constructor_type(), test_custom_attribute_builder_invalid_parent_type(), test_custom_attribute_builder_missing_constructor(), test_custom_attribute_builder_missing_parent(), test_custom_attribute_builder_multiple_attributes(), test_custom_attribute_builder_no_value() (+1 more)

### Community 179 - "Community 179"
Cohesion: 0.13
Nodes (2): MarshallingInfo, NativeType

### Community 180 - "Community 180"
Cohesion: 0.17
Nodes (6): encode_exception_handlers(), ExceptionHandler, test_encode_exception_handlers_empty(), test_encode_exception_handlers_fat_format(), test_encode_exception_handlers_filter(), test_encode_exception_handlers_small_format()

### Community 181 - "Community 181"
Cohesion: 0.13
Nodes (13): CustomModifier, SignatureArray, SignatureField, SignatureLocalVariable, SignatureLocalVariables, SignatureMethod, SignatureMethodSpec, SignatureParameter (+5 more)

### Community 182 - "Community 182"
Cohesion: 0.43
Nodes (9): EventBuilder, test_event_builder_basic(), test_event_builder_invalid_coded_index_type(), test_event_builder_missing_event_type(), test_event_builder_missing_flags(), test_event_builder_missing_name(), test_event_builder_multiple_events(), test_event_builder_with_rtspecial_name() (+1 more)

### Community 183 - "Community 183"
Cohesion: 0.41
Nodes (10): InterfaceImplBuilder, test_interface_impl_builder_basic(), test_interface_impl_builder_complex_inheritance(), test_interface_impl_builder_generic_interface(), test_interface_impl_builder_interface_extension(), test_interface_impl_builder_invalid_interface_type(), test_interface_impl_builder_missing_class(), test_interface_impl_builder_missing_interface() (+2 more)

### Community 184 - "Community 184"
Cohesion: 0.43
Nodes (9): PropertyBuilder, test_property_builder_basic(), test_property_builder_indexer_signature(), test_property_builder_missing_flags(), test_property_builder_missing_name(), test_property_builder_missing_signature(), test_property_builder_multiple_properties(), test_property_builder_with_default() (+1 more)

### Community 185 - "Community 185"
Cohesion: 0.24
Nodes (2): OwnedOwnershipValidator, test_owned_ownership_validator()

### Community 186 - "Community 186"
Cohesion: 0.17
Nodes (4): RawChangeIntegrityValidator, test_raw_change_integrity_validator(), test_raw_change_integrity_validator_direct_corruption(), test_validator_with_corrupted_changes()

### Community 187 - "Community 187"
Cohesion: 0.17
Nodes (4): RawOperationValidator, test_raw_operation_validator(), test_raw_operation_validator_direct_corruption(), test_validator_with_corrupted_changes()

### Community 188 - "Community 188"
Cohesion: 0.21
Nodes (6): ArchTestResult, test_arch_dir_creation(), test_artifact_path(), test_for_each_architecture(), test_runner_creation(), TestRunner

### Community 189 - "Community 189"
Cohesion: 0.27
Nodes (2): CilTypeBuilder, create_exportedtype()

### Community 190 - "Community 190"
Cohesion: 0.19
Nodes (9): Capability, CapaOutput, extract_technique_id(), SampleInfo, test_json_serialization(), test_lib_rules_filtered(), test_output_from_matches(), test_timing_info() (+1 more)

### Community 191 - "Community 191"
Cohesion: 0.23
Nodes (11): Constant, test_apply_different_primitive_types(), test_apply_field_constant_already_set(), test_apply_field_constant_success(), test_apply_field_string_constant_success(), test_apply_invalid_parent(), test_apply_null_constant(), test_apply_param_constant_already_set() (+3 more)

### Community 192 - "Community 192"
Cohesion: 0.15
Nodes (2): RawLayoutConstraintValidator, test_raw_layout_constraint_validator()

### Community 193 - "Community 193"
Cohesion: 0.23
Nodes (8): FileRegion, test_contains(), test_end_offset(), test_equality(), test_file_region_creation(), test_is_adjacent_to(), test_is_empty(), test_overlaps()

### Community 194 - "Community 194"
Cohesion: 0.44
Nodes (8): FieldBuilder, test_field_builder_basic(), test_field_builder_literal_field(), test_field_builder_missing_flags(), test_field_builder_missing_name(), test_field_builder_missing_signature(), test_field_builder_multiple_fields(), test_field_builder_with_attributes()

### Community 195 - "Community 195"
Cohesion: 0.33
Nodes (8): MethodDebugInformationBuilder, test_method_debug_information_builder_basic(), test_method_debug_information_builder_default(), test_method_debug_information_builder_document_only(), test_method_debug_information_builder_empty_sequence_points(), test_method_debug_information_builder_fluent_api(), test_method_debug_information_builder_minimal(), test_method_debug_information_builder_sequence_points_only()

### Community 196 - "Community 196"
Cohesion: 0.36
Nodes (10): ModuleRefBuilder, test_moduleref_builder_basic(), test_moduleref_builder_clone(), test_moduleref_builder_debug(), test_moduleref_builder_empty_name(), test_moduleref_builder_fluent_api(), test_moduleref_builder_missing_name(), test_moduleref_builder_multiple_modules() (+2 more)

### Community 197 - "Community 197"
Cohesion: 0.44
Nodes (8): ParamBuilder, test_param_builder_basic(), test_param_builder_default_value(), test_param_builder_missing_flags(), test_param_builder_missing_sequence(), test_param_builder_multiple_params(), test_param_builder_return_type(), test_param_builder_with_attributes()

### Community 198 - "Community 198"
Cohesion: 0.38
Nodes (10): StandAloneSigBuilder, test_standalonesig_builder_basic(), test_standalonesig_builder_complex_signature(), test_standalonesig_builder_default(), test_standalonesig_builder_empty_signature(), test_standalonesig_builder_generic_signature(), test_standalonesig_builder_locals_signature(), test_standalonesig_builder_method_signature() (+2 more)

### Community 199 - "Community 199"
Cohesion: 0.45
Nodes (8): test_typeref_builder_basic(), test_typeref_builder_from_mscorlib(), test_typeref_builder_global_namespace(), test_typeref_builder_missing_name(), test_typeref_builder_missing_resolution_scope(), test_typeref_builder_system_object(), test_typeref_builder_system_value_type(), TypeRefBuilder

### Community 200 - "Community 200"
Cohesion: 0.34
Nodes (5): test_collision_resistance(), test_flavor_differentiation(), test_hash_deterministic(), test_hash_order_sensitive(), TypeSignatureHash

### Community 201 - "Community 201"
Cohesion: 0.23
Nodes (4): test_default_config(), test_validation_config_presets(), test_validation_stage_methods(), ValidationConfig

### Community 202 - "Community 202"
Cohesion: 0.13
Nodes (5): OwnedValidator, RawValidator, TestOwnedValidator, TestRawValidator, ValidatorCollection

### Community 203 - "Community 203"
Cohesion: 0.24
Nodes (2): OwnedCircularityValidator, test_owned_circularity_validator()

### Community 204 - "Community 204"
Cohesion: 0.24
Nodes (2): OwnedTypeCircularityValidator, test_owned_type_circularity_validator()

### Community 205 - "Community 205"
Cohesion: 0.31
Nodes (9): CompilationResult, compile(), compile_with_csc(), compile_with_dotnet(), compile_with_mcs(), extract_warnings(), format_compiler_error(), test_compilation_result() (+1 more)

### Community 206 - "Community 206"
Cohesion: 0.17
Nodes (7): file_verify(), owned_validator_test(), run_owned_validation_test(), run_validation_test(), TestAssembly, ValidationTestResult, validator_test()

### Community 207 - "Community 207"
Cohesion: 0.14
Nodes (1): Pe

### Community 208 - "Community 208"
Cohesion: 0.31
Nodes (4): AssemblyBuilder, test_assembly_builder_basic(), test_assembly_builder_missing_name(), test_assembly_builder_with_public_key()

### Community 209 - "Community 209"
Cohesion: 0.14
Nodes (2): FileBuilder, ModuleRefBuilder

### Community 210 - "Community 210"
Cohesion: 0.16
Nodes (2): RawGenericConstraintValidator, test_raw_generic_constraint_validator()

### Community 212 - "Community 212"
Cohesion: 0.21
Nodes (6): RidRemapper, test_rid_remapper_complex_operations(), test_rid_remapper_delete_operations(), test_rid_remapper_insert_delete_conflict(), test_rid_remapper_no_operations(), test_rid_remapper_simple_insert()

### Community 213 - "Community 213"
Cohesion: 0.30
Nodes (8): Memory, test_memory_empty_buffer(), test_memory_into_data(), test_memory_into_data_empty(), test_memory_into_data_large(), test_memory_large_buffer(), test_memory_offset_overflow(), test_memory_single_byte()

### Community 214 - "Community 214"
Cohesion: 0.31
Nodes (7): Physical, test_physical_boundary_conditions(), test_physical_empty_file(), test_physical_into_data(), test_physical_into_data_small_file(), test_physical_invalid_file_path(), test_physical_large_offset_overflow()

### Community 215 - "Community 215"
Cohesion: 0.24
Nodes (11): test_typespec_array_and_pointer_types(), test_typespec_blob_heap_sizes(), test_typespec_different_signatures(), test_typespec_edge_cases(), test_typespec_generic_instantiations(), test_typespec_known_binary_format(), test_typespec_round_trip(), test_typespec_row_write_large() (+3 more)

### Community 216 - "Community 216"
Cohesion: 0.18
Nodes (3): RawSignatureValidator, SignatureKind, test_raw_signature_validator()

### Community 217 - "Community 217"
Cohesion: 0.21
Nodes (4): RawTableValidator, test_raw_table_validator(), test_raw_table_validator_configuration(), test_raw_table_validator_metadata()

### Community 218 - "Community 218"
Cohesion: 0.27
Nodes (13): perform_round_trip_test(), test_blob_heap_add_and_verify(), test_blob_heap_replacement(), test_guid_heap_add_and_verify(), test_guid_heap_replacement(), test_heap_data_persistence(), test_heap_replacement_with_subsequent_additions(), test_mixed_heap_additions() (+5 more)

### Community 219 - "Community 219"
Cohesion: 0.14
Nodes (14): write_errors(), write_le(), write_le_at(), write_le_at_sequential(), write_le_f32(), write_le_f64(), write_le_i16(), write_le_i32() (+6 more)

### Community 221 - "Community 221"
Cohesion: 0.24
Nodes (8): detect_arch(), detect_format(), detect_os(), extract_exports(), extract_imports(), extract_sections(), extract_strings(), load_from_idb()

### Community 222 - "Community 222"
Cohesion: 0.24
Nodes (8): sample_path(), test_dotnet_sample_hash_extraction(), test_elf_sample_hash_extraction(), test_golang_sample_hash_extraction(), test_graalvm_sample_hash_extraction(), test_hash_bytes_vs_file_consistency(), test_pe_sample2_hash_extraction(), test_pe_sample_hash_extraction()

### Community 223 - "Community 223"
Cohesion: 0.23
Nodes (12): GenericStats, InheritanceStats, InterfaceStats, main(), print_generic_analysis(), print_inheritance_analysis(), print_interface_analysis(), print_signature_analysis() (+4 more)

### Community 224 - "Community 224"
Cohesion: 0.26
Nodes (10): FileRaw, test_file_common_scenarios(), test_file_different_attributes(), test_file_edge_cases(), test_file_heap_sizes(), test_file_known_binary_format(), test_file_round_trip(), test_file_row_write_large() (+2 more)

### Community 225 - "Community 225"
Cohesion: 0.26
Nodes (10): GenericParamRaw, test_genericparam_constraint_flags(), test_genericparam_different_owner_types(), test_genericparam_edge_cases(), test_genericparam_generic_scenarios(), test_genericparam_known_binary_format(), test_genericparam_parameter_positions(), test_genericparam_round_trip() (+2 more)

### Community 226 - "Community 226"
Cohesion: 0.26
Nodes (10): GenericParamConstraintRaw, test_genericparamconstraint_constraint_scenarios(), test_genericparamconstraint_different_constraint_types(), test_genericparamconstraint_edge_cases(), test_genericparamconstraint_known_binary_format(), test_genericparamconstraint_multiple_constraints(), test_genericparamconstraint_round_trip(), test_genericparamconstraint_row_write_large() (+2 more)

### Community 227 - "Community 227"
Cohesion: 0.26
Nodes (10): ManifestResourceRaw, test_manifestresource_different_implementations(), test_manifestresource_edge_cases(), test_manifestresource_heap_sizes(), test_manifestresource_known_binary_format(), test_manifestresource_resource_attributes(), test_manifestresource_resource_scenarios(), test_manifestresource_round_trip() (+2 more)

### Community 228 - "Community 228"
Cohesion: 0.26
Nodes (10): MethodSpecRaw, test_methodspec_different_method_types(), test_methodspec_edge_cases(), test_methodspec_generic_scenarios(), test_methodspec_heap_sizes(), test_methodspec_instantiation_signatures(), test_methodspec_known_binary_format(), test_methodspec_round_trip() (+2 more)

### Community 229 - "Community 229"
Cohesion: 0.26
Nodes (2): OwnedAccessibilityValidator, test_owned_accessibility_validator()

### Community 230 - "Community 230"
Cohesion: 0.28
Nodes (2): OwnedFieldValidator, test_owned_field_validator()

### Community 231 - "Community 231"
Cohesion: 0.28
Nodes (2): OwnedMethodValidator, test_owned_method_validator()

### Community 232 - "Community 232"
Cohesion: 0.27
Nodes (2): OwnedTypeDependencyValidator, test_owned_type_dependency_validator()

### Community 233 - "Community 233"
Cohesion: 0.18
Nodes (1): ProjectContext

### Community 234 - "Community 234"
Cohesion: 0.23
Nodes (7): all_successful(), CompleteTestResult, error_summary(), modify_assembly(), run_complete_test(), run_complete_test_with_reflection(), test_complete_workflow()

### Community 235 - "Community 235"
Cohesion: 0.27
Nodes (8): categorize_error(), find_mono_assemblies(), LoadComparison, LoadResult, print_analysis(), test_mono_assembly_compatibility(), try_load_with_cilassemblyview(), try_load_with_cilproject()

### Community 236 - "Community 236"
Cohesion: 0.15
Nodes (13): write_be(), write_be_at(), write_be_at_sequential(), write_be_f32(), write_be_f64(), write_be_i16(), write_be_i32(), write_be_i64() (+5 more)

### Community 237 - "Community 237"
Cohesion: 0.24
Nodes (1): AssemblyRefBuilder

### Community 239 - "Community 239"
Cohesion: 0.23
Nodes (4): Address, ExtractedFeatures, FeatureSet, FunctionFeatures

### Community 240 - "Community 240"
Cohesion: 0.30
Nodes (9): CapaOutput, extract_bracketed_id(), parse_attack(), parse_mbc(), test_parse_attack_with_subtechnique(), test_parse_attack_without_subtechnique(), test_parse_mbc(), test_parse_mbc_no_method() (+1 more)

### Community 242 - "Community 242"
Cohesion: 0.27
Nodes (9): ConstantRaw, test_constant_different_parent_types(), test_constant_edge_cases(), test_constant_element_types(), test_constant_known_binary_format(), test_constant_padding_always_zero(), test_constant_round_trip(), test_constant_row_write_large() (+1 more)

### Community 243 - "Community 243"
Cohesion: 0.17
Nodes (1): DeclSecurity

### Community 244 - "Community 244"
Cohesion: 0.27
Nodes (9): DeclSecurityRaw, test_declsecurity_different_parent_types(), test_declsecurity_edge_cases(), test_declsecurity_known_binary_format(), test_declsecurity_permission_scenarios(), test_declsecurity_round_trip(), test_declsecurity_row_write_large(), test_declsecurity_row_write_small() (+1 more)

### Community 245 - "Community 245"
Cohesion: 0.27
Nodes (9): EventRaw, test_coded_index_types(), test_edge_cases(), test_event_attributes(), test_flags_range_validation(), test_known_binary_format_large(), test_known_binary_format_small(), test_large_heap_serialization() (+1 more)

### Community 246 - "Community 246"
Cohesion: 0.27
Nodes (9): FieldRvaRaw, test_fieldrva_different_rvas(), test_fieldrva_edge_cases(), test_fieldrva_known_binary_format(), test_fieldrva_pe_context(), test_fieldrva_round_trip(), test_fieldrva_row_write_large(), test_fieldrva_row_write_small() (+1 more)

### Community 247 - "Community 247"
Cohesion: 0.27
Nodes (9): ParamRaw, test_edge_cases(), test_flags_range_validation(), test_known_binary_format_large_heap(), test_known_binary_format_small_heap(), test_large_heap_serialization(), test_parameter_attributes(), test_round_trip_serialization() (+1 more)

### Community 248 - "Community 248"
Cohesion: 0.27
Nodes (9): PropertyRaw, test_different_heap_combinations(), test_edge_cases(), test_flags_range_validation(), test_known_binary_format_large_heap(), test_known_binary_format_small_heap(), test_large_heap_serialization(), test_property_attributes() (+1 more)

### Community 249 - "Community 249"
Cohesion: 0.27
Nodes (9): PropertyMapRaw, test_propertymap_different_ranges(), test_propertymap_edge_cases(), test_propertymap_known_binary_format(), test_propertymap_property_ptr_compatibility(), test_propertymap_round_trip(), test_propertymap_row_write_large(), test_propertymap_row_write_small() (+1 more)

### Community 250 - "Community 250"
Cohesion: 0.27
Nodes (9): StandAloneSigRaw, test_standalonesig_blob_heap_sizes(), test_standalonesig_different_signatures(), test_standalonesig_edge_cases(), test_standalonesig_known_binary_format(), test_standalonesig_round_trip(), test_standalonesig_row_write_large(), test_standalonesig_row_write_small() (+1 more)

### Community 251 - "Community 251"
Cohesion: 0.29
Nodes (2): OwnedDependencyValidator, test_owned_dependency_validator()

### Community 252 - "Community 252"
Cohesion: 0.29
Nodes (2): OwnedTypeOwnershipValidator, test_owned_type_ownership_validator()

### Community 253 - "Community 253"
Cohesion: 0.33
Nodes (11): create_test_assembly_ref(), create_test_assembly_ref_with_culture(), create_test_assembly_ref_with_version(), create_test_dependency(), create_test_dependency_with_state(), create_test_dependency_with_version(), create_test_file(), create_test_file_dependency() (+3 more)

### Community 254 - "Community 254"
Cohesion: 0.33
Nodes (11): create_test_assembly(), get_initial_heap_sizes(), get_test_assembly_path(), test_blob_operations_round_trip(), test_builder_context_round_trip(), test_guid_operations_round_trip(), test_mixed_operations_round_trip(), test_string_addition_round_trip() (+3 more)

### Community 257 - "Community 257"
Cohesion: 0.29
Nodes (8): ClassLayoutRaw, test_classlayout_different_layout_values(), test_classlayout_edge_cases(), test_classlayout_known_binary_format(), test_classlayout_power_of_two_packing(), test_classlayout_round_trip(), test_classlayout_row_write_large(), test_classlayout_row_write_small()

### Community 258 - "Community 258"
Cohesion: 0.27
Nodes (10): ExceptionStats, InstructionStats, LocalVariableStats, main(), MethodBodyStats, print_exception_analysis(), print_instruction_analysis(), print_method_body_analysis() (+2 more)

### Community 259 - "Community 259"
Cohesion: 0.18
Nodes (2): UserStringHeapBuilder, UserStringHeapBuilder<'a>

### Community 260 - "Community 260"
Cohesion: 0.31
Nodes (8): fat(), fat_exceptions_1(), fat_exceptions_fat_section_3(), fat_exceptions_multiple(), fat_exceptions_tiny_section_2(), MethodBody, tiny(), validate_exception_handler_bounds()

### Community 262 - "Community 262"
Cohesion: 0.29
Nodes (8): EventMapRaw, test_eventmap_different_ranges(), test_eventmap_edge_cases(), test_eventmap_known_binary_format(), test_eventmap_round_trip(), test_eventmap_row_write_large(), test_eventmap_row_write_small(), test_eventmap_sorted_order()

### Community 263 - "Community 263"
Cohesion: 0.29
Nodes (8): FieldLayoutRaw, test_fieldlayout_alignment_scenarios(), test_fieldlayout_different_offsets(), test_fieldlayout_edge_cases(), test_fieldlayout_known_binary_format(), test_fieldlayout_round_trip(), test_fieldlayout_row_write_large(), test_fieldlayout_row_write_small()

### Community 264 - "Community 264"
Cohesion: 0.29
Nodes (8): FieldMarshalRaw, test_fieldmarshal_different_parent_types(), test_fieldmarshal_edge_cases(), test_fieldmarshal_known_binary_format(), test_fieldmarshal_marshalling_signatures(), test_fieldmarshal_round_trip(), test_fieldmarshal_row_write_large(), test_fieldmarshal_row_write_small()

### Community 265 - "Community 265"
Cohesion: 0.29
Nodes (8): ImplMapRaw, test_implmap_different_member_types(), test_implmap_edge_cases(), test_implmap_known_binary_format(), test_implmap_pinvoke_flags(), test_implmap_round_trip(), test_implmap_row_write_large(), test_implmap_row_write_small()

### Community 266 - "Community 266"
Cohesion: 0.29
Nodes (8): InterfaceImplRaw, test_coded_index_types(), test_different_table_combinations(), test_edge_cases(), test_known_binary_format_large(), test_known_binary_format_small(), test_large_table_serialization(), test_round_trip_serialization()

### Community 267 - "Community 267"
Cohesion: 0.29
Nodes (8): MethodDefRaw, test_edge_cases(), test_flags_range_validation(), test_implementation_flags(), test_known_binary_format(), test_large_heap_serialization(), test_method_attributes(), test_round_trip_serialization()

### Community 268 - "Community 268"
Cohesion: 0.29
Nodes (2): OwnedSignatureValidator, test_owned_signature_validator()

### Community 269 - "Community 269"
Cohesion: 0.35
Nodes (10): verify_cor20(), verify_methods(), verify_module(), verify_refs_assembly(), verify_refs_module(), verify_resource(), verify_root(), verify_tableheader() (+2 more)

### Community 270 - "Community 270"
Cohesion: 0.18
Nodes (1): EnumUtils

### Community 271 - "Community 271"
Cohesion: 0.36
Nodes (6): FailFastBarrier, test_barrier_break(), test_break_barrier_with_string(), test_is_broken(), test_normal_barrier_operation(), test_zero_count_returns_error()

### Community 272 - "Community 272"
Cohesion: 0.35
Nodes (10): create_console_writeline_ref(), create_mscorlib_ref(), create_test_assembly(), create_writeline_signature(), inject_hello_world_method(), test_method_injection_roundtrip(), verify_assembly_integrity(), verify_injected_method() (+2 more)

### Community 273 - "Community 273"
Cohesion: 0.18
Nodes (1): SectionTable

### Community 275 - "Community 275"
Cohesion: 0.29
Nodes (4): test_boolean_constants(), test_conditional_logic(), test_convenience_methods(), test_long_form_branches()

### Community 276 - "Community 276"
Cohesion: 0.31
Nodes (7): CustomAttributeRaw, test_customattribute_different_coded_index_types(), test_customattribute_edge_cases(), test_customattribute_known_binary_format(), test_customattribute_round_trip(), test_customattribute_row_write_large_heaps(), test_customattribute_row_write_small_heaps()

### Community 277 - "Community 277"
Cohesion: 0.27
Nodes (3): LocalVariable, MethodAccessFlags, VarArg

### Community 278 - "Community 278"
Cohesion: 0.20
Nodes (5): ArgumentType, ArgumentValue, PermissionSetFormat, Security, SecurityAction

### Community 279 - "Community 279"
Cohesion: 0.31
Nodes (7): FieldRaw, test_edge_cases(), test_field_attributes(), test_flags_range_validation(), test_known_binary_format(), test_large_heap_serialization(), test_round_trip_serialization()

### Community 280 - "Community 280"
Cohesion: 0.33
Nodes (8): ImportScopeRaw, test_known_binary_format_large_indices(), test_known_binary_format_small_indices(), test_mixed_index_sizes(), test_nested_scope_hierarchy(), test_root_scope(), test_round_trip_serialization_large_indices(), test_round_trip_serialization_small_indices()

### Community 281 - "Community 281"
Cohesion: 0.33
Nodes (8): LocalConstantRaw, test_anonymous_constant(), test_edge_case_values(), test_known_binary_format_large_heaps(), test_known_binary_format_small_heaps(), test_mixed_heap_sizes(), test_round_trip_serialization_large_heaps(), test_round_trip_serialization_small_heaps()

### Community 282 - "Community 282"
Cohesion: 0.31
Nodes (7): MemberRefRaw, test_memberref_different_coded_index_types(), test_memberref_edge_cases(), test_memberref_known_binary_format(), test_memberref_round_trip_small(), test_memberref_row_write_large_heaps(), test_memberref_row_write_small_heaps()

### Community 283 - "Community 283"
Cohesion: 0.31
Nodes (7): MethodImplRaw, test_methodimpl_different_coded_indexes(), test_methodimpl_edge_cases(), test_methodimpl_known_binary_format(), test_methodimpl_round_trip(), test_methodimpl_row_write_large(), test_methodimpl_row_write_small()

### Community 284 - "Community 284"
Cohesion: 0.31
Nodes (7): MethodSemanticsRaw, test_methodsemantics_different_semantic_types(), test_methodsemantics_edge_cases(), test_methodsemantics_known_binary_format(), test_methodsemantics_round_trip(), test_methodsemantics_row_write_large(), test_methodsemantics_row_write_small()

### Community 285 - "Community 285"
Cohesion: 0.31
Nodes (7): NestedClassRaw, test_nestedclass_different_relationships(), test_nestedclass_edge_cases(), test_nestedclass_known_binary_format(), test_nestedclass_round_trip(), test_nestedclass_row_write_large(), test_nestedclass_row_write_small()

### Community 286 - "Community 286"
Cohesion: 0.33
Nodes (8): StateMachineMethodRaw, test_async_method_mapping(), test_known_binary_format_large_table(), test_known_binary_format_small_table(), test_round_trip_serialization_large_table(), test_round_trip_serialization_small_table(), test_various_method_indices(), test_yield_method_mapping()

### Community 287 - "Community 287"
Cohesion: 0.20
Nodes (3): OptionalHeader, StandardFields, WindowsFields

### Community 288 - "Community 288"
Cohesion: 0.31
Nodes (8): create_mock_file_structure(), test_calculate_total_file_size_empty_sections(), test_calculate_total_file_size_with_sections(), test_file_offset_to_rva_first_section(), test_file_offset_to_rva_multiple_sections(), test_file_offset_to_rva_not_found(), test_file_offset_to_rva_section_boundary(), test_file_offset_to_rva_success()

### Community 289 - "Community 289"
Cohesion: 0.28
Nodes (6): AttackRow, CapabilityRow, Cli, InputFormat, main(), print_text_output()

### Community 291 - "Community 291"
Cohesion: 0.36
Nodes (7): CustomDebugInformationRaw, test_common_debug_info_scenarios(), test_known_binary_format_large_heaps(), test_known_binary_format_small_heaps(), test_round_trip_serialization_large_heaps(), test_round_trip_serialization_small_heaps(), test_various_coded_index_types()

### Community 292 - "Community 292"
Cohesion: 0.31
Nodes (1): Document

### Community 293 - "Community 293"
Cohesion: 0.42
Nodes (8): demonstrate_blob_access(), demonstrate_string_access(), display_cor20_header(), display_file_info(), display_metadata_root(), display_streams(), display_tables(), main()

### Community 294 - "Community 294"
Cohesion: 0.39
Nodes (7): Cor20Header, crafted(), test_invalid_flags(), test_invalid_strong_name_signature(), test_invalid_vtable_fixups(), test_zero_metadata_rva(), test_zero_metadata_size()

### Community 295 - "Community 295"
Cohesion: 0.39
Nodes (7): encode_method_body_header(), test_fat_format_encoding(), test_fat_format_exception_flag(), test_fat_format_without_exceptions(), test_real_method_simulation(), test_tiny_format_boundary_conditions(), test_tiny_format_encoding()

### Community 296 - "Community 296"
Cohesion: 0.36
Nodes (7): EncMapRaw, test_edge_case_tokens(), test_known_binary_format(), test_multiple_token_mappings(), test_round_trip_serialization(), test_sequential_mappings(), test_various_token_types()

### Community 297 - "Community 297"
Cohesion: 0.36
Nodes (7): LocalVariableRaw, test_anonymous_variable(), test_known_binary_format_large_heap(), test_known_binary_format_small_heap(), test_round_trip_serialization_large_heap(), test_round_trip_serialization_small_heap(), test_various_attributes_and_indices()

### Community 298 - "Community 298"
Cohesion: 0.31
Nodes (5): test_edge_cases(), test_known_binary_format(), test_large_heap_serialization(), test_round_trip_serialization(), TypeDefRaw

### Community 299 - "Community 299"
Cohesion: 0.31
Nodes (5): test_edge_cases(), test_known_binary_format(), test_large_heap_serialization(), test_round_trip_serialization(), TypeRefRaw

### Community 300 - "Community 300"
Cohesion: 0.22
Nodes (1): TableDataOwned

### Community 301 - "Community 301"
Cohesion: 0.33
Nodes (6): align_to(), align_to_4_bytes(), test_4_byte_alignment_properties(), test_align_to_non_power_of_2_panics(), test_align_to_zero_alignment_panics(), test_alignment_properties()

### Community 302 - "Community 302"
Cohesion: 0.36
Nodes (1): LoaderGraph<'a>

### Community 303 - "Community 303"
Cohesion: 0.22
Nodes (2): TableParIterator<'_, T>, TableProducerIterator<'_, T>

### Community 304 - "Community 304"
Cohesion: 0.36
Nodes (5): AssemblyRaw, test_known_binary_format_large_heaps(), test_known_binary_format_small_heaps(), test_round_trip_serialization_large_heaps(), test_round_trip_serialization_small_heaps()

### Community 305 - "Community 305"
Cohesion: 0.29
Nodes (4): DotNetExtractedFeatures, DotNetMethodFeatures, extract_dotnet_features(), parse_method_header()

### Community 306 - "Community 306"
Cohesion: 0.36
Nodes (2): CodedIndex, CodedIndexType

### Community 307 - "Community 307"
Cohesion: 0.43
Nodes (7): main(), MethodStats, print_assembly_info(), print_import_analysis(), print_instruction_analysis(), print_method_analysis(), print_type_analysis()

### Community 308 - "Community 308"
Cohesion: 0.46
Nodes (7): main(), print_custom_attribute_info(), print_custom_attributes_analysis(), print_dependency_analysis(), print_heap_analysis(), print_metadata_tables(), print_type_system_analysis()

### Community 309 - "Community 309"
Cohesion: 0.29
Nodes (1): BlobHeapBuilder

### Community 310 - "Community 310"
Cohesion: 0.29
Nodes (1): StringHeapBuilder

### Community 311 - "Community 311"
Cohesion: 0.25
Nodes (4): DataDirectory, DataDirectoryType, Export, Import

### Community 312 - "Community 312"
Cohesion: 0.39
Nodes (6): EncLogRaw, test_different_operation_codes(), test_known_binary_format(), test_multiple_entries(), test_round_trip_serialization(), test_various_token_types()

### Community 313 - "Community 313"
Cohesion: 0.29
Nodes (1): LocalScope

### Community 314 - "Community 314"
Cohesion: 0.39
Nodes (6): LocalScopeRaw, test_known_binary_format_large_indices(), test_known_binary_format_small_indices(), test_null_optional_indices(), test_round_trip_serialization_large_indices(), test_round_trip_serialization_small_indices()

### Community 315 - "Community 315"
Cohesion: 0.39
Nodes (6): MethodDebugInformationRaw, test_known_binary_format_large_indices(), test_known_binary_format_small_indices(), test_null_values(), test_round_trip_serialization_large_indices(), test_round_trip_serialization_small_indices()

### Community 316 - "Community 316"
Cohesion: 0.36
Nodes (5): ModuleRaw, test_known_binary_format_large_heaps(), test_known_binary_format_small_heaps(), test_round_trip_serialization_large_heaps(), test_round_trip_serialization_small_heaps()

### Community 318 - "Community 318"
Cohesion: 0.46
Nodes (7): create_assembly_with_duplicate_named_args(), create_assembly_with_empty_named_arg_name(), create_assembly_with_excessive_fixed_args(), create_assembly_with_excessive_named_args(), create_assembly_with_excessive_string_length(), create_assembly_with_null_character_string(), owned_attribute_validator_file_factory()

### Community 319 - "Community 319"
Cohesion: 0.39
Nodes (5): create_assembly_with_abstract_concrete_violation(), create_assembly_with_accessibility_violation(), create_assembly_with_interface_inheritance_violation(), create_assembly_with_sealed_type_inheritance(), owned_inheritance_validator_file_factory()

### Community 320 - "Community 320"
Cohesion: 0.46
Nodes (7): create_assembly_with_empty_method_name(), create_assembly_with_interface_instance_field(), create_assembly_with_interface_non_constant_field(), create_assembly_with_literal_non_static_field(), create_assembly_with_nested_accessibility_violation(), create_assembly_with_sealed_interface(), owned_accessibility_validator_file_factory()

### Community 321 - "Community 321"
Cohesion: 0.39
Nodes (5): create_assembly_with_excessive_class_size(), create_assembly_with_invalid_field_offset(), create_assembly_with_invalid_packing_size(), create_assembly_with_null_field_reference(), raw_layout_constraint_validator_file_factory()

### Community 322 - "Community 322"
Cohesion: 0.43
Nodes (6): compressed_uint_size(), test_compressed_uint_four_bytes(), test_compressed_uint_single_byte(), test_compressed_uint_two_bytes(), test_size_consistency(), write_compressed_uint()

### Community 323 - "Community 323"
Cohesion: 0.46
Nodes (7): get_test_context(), test_business_service_with_events(), test_data_model_with_validation(), test_event_driven_architecture(), test_inherited_class_with_virtual_properties(), test_mvvm_viewmodel_with_properties_and_events(), test_ultimate_integration_all_builders()

### Community 325 - "Community 325"
Cohesion: 0.25
Nodes (1): DosHeader

### Community 326 - "Community 326"
Cohesion: 0.29
Nodes (1): DataDirectories

### Community 327 - "Community 327"
Cohesion: 0.25
Nodes (5): test_calculate_metadata_root_header_size(), test_calculate_metadata_root_size(), test_calculate_stream_directory_size(), test_metadata_root_size_consistency(), test_stream_directory_includes_all_streams()

### Community 328 - "Community 328"
Cohesion: 0.25
Nodes (2): &'a MetadataTable<'a, T>, MetadataTable<'a, T>

### Community 329 - "Community 329"
Cohesion: 0.32
Nodes (2): test_get_file_paths(), test_get_file_paths_no_fileio_permission()

### Community 331 - "Community 331"
Cohesion: 0.43
Nodes (5): AssemblyRefRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 332 - "Community 332"
Cohesion: 0.43
Nodes (5): AssemblyRefOsRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 333 - "Community 333"
Cohesion: 0.43
Nodes (5): AssemblyRefProcessorRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 335 - "Community 335"
Cohesion: 0.43
Nodes (5): buf_filled_with(), extract_ascii_strings(), extract_unicode_strings(), ExtractedString, is_ascii_printable()

### Community 336 - "Community 336"
Cohesion: 0.43
Nodes (5): DocumentRaw, test_known_binary_format_large_heaps(), test_known_binary_format_small_heaps(), test_round_trip_serialization_large_heaps(), test_round_trip_serialization_small_heaps()

### Community 337 - "Community 337"
Cohesion: 0.43
Nodes (5): EventPtrRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 338 - "Community 338"
Cohesion: 0.43
Nodes (5): ExportedTypeRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 339 - "Community 339"
Cohesion: 0.43
Nodes (5): FieldPtrRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 340 - "Community 340"
Cohesion: 0.43
Nodes (5): MethodPtrRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 341 - "Community 341"
Cohesion: 0.43
Nodes (5): ModuleRefRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 342 - "Community 342"
Cohesion: 0.43
Nodes (5): ParamPtrRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 343 - "Community 343"
Cohesion: 0.43
Nodes (5): PropertyPtrRaw, test_known_binary_format_long(), test_known_binary_format_short(), test_round_trip_serialization_long(), test_round_trip_serialization_short()

### Community 345 - "Community 345"
Cohesion: 0.52
Nodes (6): create_assembly_with_broken_constraint_reference(), create_assembly_with_conflicting_constraints(), create_assembly_with_conflicting_variance(), create_assembly_with_empty_constraint_name(), create_assembly_with_fake_interface_implementation(), owned_type_constraint_validator_file_factory()

### Community 346 - "Community 346"
Cohesion: 0.52
Nodes (6): create_assembly_with_empty_field_name(), create_assembly_with_literal_non_static_field(), create_assembly_with_non_private_backing_field(), create_assembly_with_null_character_field_name(), create_assembly_with_rtspecial_without_special(), owned_field_validator_file_factory()

### Community 347 - "Community 347"
Cohesion: 0.52
Nodes (6): create_assembly_with_abstract_method_with_rva(), create_assembly_with_abstract_non_virtual_method(), create_assembly_with_empty_method_name(), create_assembly_with_invalid_instance_constructor(), create_assembly_with_static_virtual_method(), owned_method_validator_file_factory()

### Community 348 - "Community 348"
Cohesion: 0.43
Nodes (4): create_assembly_with_invalid_guid_alignment(), create_assembly_with_invalid_utf16_userstring(), create_assembly_with_valid_guid_content(), raw_heap_validator_file_factory()

### Community 349 - "Community 349"
Cohesion: 0.48
Nodes (5): create_assembly_with_empty_method_name(), create_assembly_with_long_parameter_name(), create_assembly_with_unresolved_parameter_type(), create_assembly_with_unresolved_return_type(), owned_signature_validator_file_factory()

### Community 350 - "Community 350"
Cohesion: 0.43
Nodes (4): create_assembly_with_empty_field_name(), create_assembly_with_empty_method_name(), create_assembly_with_invalid_field_visibility(), owned_type_ownership_validator_file_factory()

### Community 352 - "Community 352"
Cohesion: 0.33
Nodes (7): test_string_encoding_edge_cases(), test_write_7bit_encoded_int(), test_write_prefixed_string_utf16(), test_write_prefixed_string_utf8(), write_7bit_encoded_int(), write_prefixed_string_utf16(), write_prefixed_string_utf8()

### Community 353 - "Community 353"
Cohesion: 0.29
Nodes (7): test_write_compressed_int_negative(), test_write_compressed_int_positive(), test_write_compressed_uint_four_bytes(), test_write_compressed_uint_single_byte(), test_write_compressed_uint_two_bytes(), write_compressed_int(), write_compressed_uint()

### Community 354 - "Community 354"
Cohesion: 0.29
Nodes (7): test_write_string_at(), test_write_string_at_bounds_error(), test_write_string_at_empty_string(), test_write_string_at_exact_fit(), test_write_string_at_utf8(), test_write_string_at_with_offset(), write_string_at()

### Community 355 - "Community 355"
Cohesion: 0.47
Nodes (4): AssemblyOsRaw, test_known_binary_format(), test_round_trip_serialization(), test_zero_values()

### Community 356 - "Community 356"
Cohesion: 0.47
Nodes (4): AssemblyProcessorRaw, test_known_binary_format(), test_round_trip_serialization(), test_zero_value()

### Community 358 - "Community 358"
Cohesion: 0.53
Nodes (5): get_file_hashes(), get_sample_hashes(), SampleHashes, test_empty_input(), test_known_input()

### Community 359 - "Community 359"
Cohesion: 0.33
Nodes (2): FeatureExtractor, NullExtractor

### Community 360 - "Community 360"
Cohesion: 0.60
Nodes (5): create_console_writeline_ref(), create_writeline_signature(), find_injection_target(), find_or_create_mscorlib_ref(), main()

### Community 361 - "Community 361"
Cohesion: 0.33
Nodes (1): GuidHeapBuilder

### Community 362 - "Community 362"
Cohesion: 0.47
Nodes (3): crafted(), duplicate_stream_names_should_fail(), Root

### Community 363 - "Community 363"
Cohesion: 0.47
Nodes (1): EventMapRaw

### Community 364 - "Community 364"
Cohesion: 0.33
Nodes (1): ExportedTypeRaw

### Community 365 - "Community 365"
Cohesion: 0.33
Nodes (1): MemberRefRaw

### Community 366 - "Community 366"
Cohesion: 0.47
Nodes (1): PropertyMapRaw

### Community 367 - "Community 367"
Cohesion: 0.33
Nodes (1): TypeDefRaw

### Community 368 - "Community 368"
Cohesion: 0.60
Nodes (5): create_assembly_with_broken_dependency_chain(), create_assembly_with_invalid_dependency_ordering(), create_assembly_with_self_referential_dependencies(), create_assembly_with_unsatisfied_transitive_dependencies(), owned_dependency_validator_file_factory()

### Community 369 - "Community 369"
Cohesion: 0.60
Nodes (5): create_assembly_with_invalid_field_calling_convention(), create_assembly_with_invalid_method_calling_convention(), create_assembly_with_malformed_compressed_integer(), create_assembly_with_oversized_signature_blob(), raw_signature_validator_file_factory()

### Community 370 - "Community 370"
Cohesion: 0.60
Nodes (5): create_assembly_with_empty_module_table(), create_assembly_with_field_list_violation(), create_assembly_with_method_list_violation(), create_assembly_with_multiple_assembly_rows(), raw_table_validator_file_factory()

### Community 371 - "Community 371"
Cohesion: 0.60
Nodes (5): create_assembly_with_empty_name(), create_assembly_with_invalid_culture_format(), create_assembly_with_invalid_name_format(), create_assembly_with_maximum_version_numbers(), owned_assembly_validator_file_factory()

### Community 372 - "Community 372"
Cohesion: 0.60
Nodes (5): create_assembly_with_conflicting_security_attributes(), create_assembly_with_invalid_security_action(), create_assembly_with_malformed_permission_set(), create_assembly_with_security_transparency_violations(), owned_security_validator_file_factory()

### Community 373 - "Community 373"
Cohesion: 0.60
Nodes (5): create_assembly_with_depth_limit_violation(), create_assembly_with_inheritance_circularity(), create_assembly_with_interface_circularity(), create_assembly_with_nested_type_circularity(), owned_type_circularity_validator_file_factory()

### Community 374 - "Community 374"
Cohesion: 0.47
Nodes (3): create_assembly_with_empty_type_name(), create_assembly_with_malformed_special_name(), owned_type_definition_validator_file_factory()

### Community 375 - "Community 375"
Cohesion: 0.53
Nodes (4): create_assembly_with_broken_interface_reference(), create_assembly_with_unresolved_base_type(), create_assembly_with_unresolved_nested_type(), owned_type_dependency_validator_file_factory()

### Community 376 - "Community 376"
Cohesion: 0.40
Nodes (2): create_cil_type(), create_file()

### Community 377 - "Community 377"
Cohesion: 0.33
Nodes (1): CoffHeader

### Community 378 - "Community 378"
Cohesion: 0.40
Nodes (1): AssemblyLoader

### Community 379 - "Community 379"
Cohesion: 0.40
Nodes (1): AssemblyRaw

### Community 380 - "Community 380"
Cohesion: 0.40
Nodes (1): AssemblyOsLoader

### Community 381 - "Community 381"
Cohesion: 0.40
Nodes (1): AssemblyOsRaw

### Community 382 - "Community 382"
Cohesion: 0.40
Nodes (1): AssemblyProcessorLoader

### Community 383 - "Community 383"
Cohesion: 0.40
Nodes (1): AssemblyProcessorRaw

### Community 384 - "Community 384"
Cohesion: 0.40
Nodes (1): AssemblyRefLoader

### Community 385 - "Community 385"
Cohesion: 0.40
Nodes (1): AssemblyRefRaw

### Community 386 - "Community 386"
Cohesion: 0.40
Nodes (1): AssemblyRefOsLoader

### Community 387 - "Community 387"
Cohesion: 0.40
Nodes (1): AssemblyRefOsRaw

### Community 388 - "Community 388"
Cohesion: 0.40
Nodes (1): AssemblyRefProcessorLoader

### Community 389 - "Community 389"
Cohesion: 0.40
Nodes (1): AssemblyRefProcessorRaw

### Community 390 - "Community 390"
Cohesion: 0.40
Nodes (1): IdaExtractor

### Community 391 - "Community 391"
Cohesion: 0.60
Nodes (3): validate_count_constraint(), validate_feature_node(), validate_rule()

### Community 392 - "Community 392"
Cohesion: 0.40
Nodes (1): ClassLayoutLoader

### Community 393 - "Community 393"
Cohesion: 0.40
Nodes (1): ClassLayoutRaw

### Community 394 - "Community 394"
Cohesion: 0.40
Nodes (1): ConstantLoader

### Community 395 - "Community 395"
Cohesion: 0.40
Nodes (1): ConstantRaw

### Community 396 - "Community 396"
Cohesion: 0.40
Nodes (1): CustomAttributeLoader

### Community 397 - "Community 397"
Cohesion: 0.40
Nodes (1): CustomDebugInformationLoader

### Community 398 - "Community 398"
Cohesion: 0.40
Nodes (1): DeclSecurityLoader

### Community 399 - "Community 399"
Cohesion: 0.40
Nodes (1): DeclSecurityRaw

### Community 400 - "Community 400"
Cohesion: 0.40
Nodes (1): DocumentLoader

### Community 402 - "Community 402"
Cohesion: 0.40
Nodes (1): InheritanceResolver

### Community 403 - "Community 403"
Cohesion: 0.60
Nodes (3): crafted(), crafted_invalid(), StreamHeader

### Community 404 - "Community 404"
Cohesion: 0.40
Nodes (1): EncLogLoader

### Community 405 - "Community 405"
Cohesion: 0.40
Nodes (1): EncLogRaw

### Community 406 - "Community 406"
Cohesion: 0.40
Nodes (1): EncMapLoader

### Community 407 - "Community 407"
Cohesion: 0.40
Nodes (1): EncMapRaw

### Community 408 - "Community 408"
Cohesion: 0.40
Nodes (1): EventLoader

### Community 409 - "Community 409"
Cohesion: 0.40
Nodes (1): EventRaw

### Community 410 - "Community 410"
Cohesion: 0.40
Nodes (1): EventMapLoader

### Community 411 - "Community 411"
Cohesion: 0.40
Nodes (1): EventPtrLoader

### Community 412 - "Community 412"
Cohesion: 0.40
Nodes (1): EventPtrRaw

### Community 413 - "Community 413"
Cohesion: 0.40
Nodes (1): ExportedTypeLoader

### Community 414 - "Community 414"
Cohesion: 0.40
Nodes (1): FieldLoader

### Community 415 - "Community 415"
Cohesion: 0.40
Nodes (1): FieldRaw

### Community 416 - "Community 416"
Cohesion: 0.40
Nodes (1): FieldLayoutLoader

### Community 417 - "Community 417"
Cohesion: 0.40
Nodes (1): FieldLayoutRaw

### Community 418 - "Community 418"
Cohesion: 0.40
Nodes (1): FieldMarshalLoader

### Community 419 - "Community 419"
Cohesion: 0.40
Nodes (1): FieldMarshalRaw

### Community 420 - "Community 420"
Cohesion: 0.40
Nodes (1): FieldPtrLoader

### Community 421 - "Community 421"
Cohesion: 0.40
Nodes (1): FieldPtrRaw

### Community 422 - "Community 422"
Cohesion: 0.40
Nodes (1): FieldRvaLoader

### Community 423 - "Community 423"
Cohesion: 0.40
Nodes (1): FieldRvaRaw

### Community 424 - "Community 424"
Cohesion: 0.40
Nodes (1): FileLoader

### Community 425 - "Community 425"
Cohesion: 0.40
Nodes (1): FileRaw

### Community 426 - "Community 426"
Cohesion: 0.40
Nodes (1): GenericParamLoader

### Community 427 - "Community 427"
Cohesion: 0.40
Nodes (1): GenericParamConstraintLoader

### Community 428 - "Community 428"
Cohesion: 0.40
Nodes (1): GenericParamConstraintRaw

### Community 429 - "Community 429"
Cohesion: 0.40
Nodes (1): ImplMapLoader

### Community 430 - "Community 430"
Cohesion: 0.40
Nodes (1): ImplMapRaw

### Community 431 - "Community 431"
Cohesion: 0.40
Nodes (1): ImportScopeLoader

### Community 432 - "Community 432"
Cohesion: 0.40
Nodes (1): InterfaceImplLoader

### Community 433 - "Community 433"
Cohesion: 0.40
Nodes (1): InterfaceImplRaw

### Community 434 - "Community 434"
Cohesion: 0.40
Nodes (1): LocalConstantLoader

### Community 435 - "Community 435"
Cohesion: 0.40
Nodes (1): LocalScopeLoader

### Community 436 - "Community 436"
Cohesion: 0.40
Nodes (1): LocalVariableLoader

### Community 437 - "Community 437"
Cohesion: 0.40
Nodes (1): ManifestResourceLoader

### Community 438 - "Community 438"
Cohesion: 0.40
Nodes (1): ManifestResourceRaw

### Community 439 - "Community 439"
Cohesion: 0.40
Nodes (1): MemberRefLoader

### Community 440 - "Community 440"
Cohesion: 0.40
Nodes (1): MethodDebugInformationLoader

### Community 441 - "Community 441"
Cohesion: 0.40
Nodes (1): MethodDefLoader

### Community 442 - "Community 442"
Cohesion: 0.40
Nodes (1): MethodDefRaw

### Community 443 - "Community 443"
Cohesion: 0.40
Nodes (1): MethodImplLoader

### Community 444 - "Community 444"
Cohesion: 0.40
Nodes (1): MethodImplRaw

### Community 445 - "Community 445"
Cohesion: 0.40
Nodes (1): MethodPtrLoader

### Community 446 - "Community 446"
Cohesion: 0.40
Nodes (1): MethodPtrRaw

### Community 447 - "Community 447"
Cohesion: 0.40
Nodes (1): MethodSemanticsLoader

### Community 448 - "Community 448"
Cohesion: 0.40
Nodes (1): MethodSemanticsRaw

### Community 449 - "Community 449"
Cohesion: 0.40
Nodes (1): MethodSpecLoader

### Community 450 - "Community 450"
Cohesion: 0.40
Nodes (1): ModuleLoader

### Community 451 - "Community 451"
Cohesion: 0.40
Nodes (1): ModuleRaw

### Community 452 - "Community 452"
Cohesion: 0.40
Nodes (1): ModuleRefLoader

### Community 453 - "Community 453"
Cohesion: 0.40
Nodes (1): ModuleRefRaw

### Community 454 - "Community 454"
Cohesion: 0.40
Nodes (1): NestedClassLoader

### Community 455 - "Community 455"
Cohesion: 0.40
Nodes (1): NestedClassRaw

### Community 456 - "Community 456"
Cohesion: 0.40
Nodes (1): ParamLoader

### Community 457 - "Community 457"
Cohesion: 0.40
Nodes (1): ParamRaw

### Community 458 - "Community 458"
Cohesion: 0.40
Nodes (1): ParamPtrLoader

### Community 459 - "Community 459"
Cohesion: 0.40
Nodes (1): ParamPtrRaw

### Community 460 - "Community 460"
Cohesion: 0.40
Nodes (1): PropertyLoader

### Community 461 - "Community 461"
Cohesion: 0.40
Nodes (1): PropertyRaw

### Community 462 - "Community 462"
Cohesion: 0.40
Nodes (1): PropertyMapLoader

### Community 463 - "Community 463"
Cohesion: 0.40
Nodes (1): PropertyPtrLoader

### Community 464 - "Community 464"
Cohesion: 0.40
Nodes (1): PropertyPtrRaw

### Community 465 - "Community 465"
Cohesion: 0.40
Nodes (1): StandAloneSigLoader

### Community 466 - "Community 466"
Cohesion: 0.40
Nodes (1): StandAloneSigRaw

### Community 467 - "Community 467"
Cohesion: 0.40
Nodes (1): StateMachineMethodLoader

### Community 468 - "Community 468"
Cohesion: 0.40
Nodes (1): TypeDefLoader

### Community 469 - "Community 469"
Cohesion: 0.40
Nodes (1): TypeRefLoader

### Community 470 - "Community 470"
Cohesion: 0.40
Nodes (1): TypeRefRaw

### Community 471 - "Community 471"
Cohesion: 0.40
Nodes (4): TableIterator, TableParIterator, TableProducer, TableProducerIterator

### Community 472 - "Community 472"
Cohesion: 0.40
Nodes (1): TypeSpecLoader

### Community 473 - "Community 473"
Cohesion: 0.40
Nodes (1): TypeSpecRaw

### Community 474 - "Community 474"
Cohesion: 0.70
Nodes (4): create_assembly_with_circular_inheritance(), create_assembly_with_circular_interface_implementation(), create_assembly_with_self_referential_type(), owned_circularity_validator_file_factory()

### Community 475 - "Community 475"
Cohesion: 0.70
Nodes (4): create_assembly_with_broken_method_ownership(), create_assembly_with_invalid_method_accessibility(), create_assembly_with_invalid_static_constructor(), owned_ownership_validator_file_factory()

### Community 476 - "Community 476"
Cohesion: 0.70
Nodes (4): create_assembly_with_constraint_owner_exceeding_bounds(), create_assembly_with_invalid_parameter_flags(), create_assembly_with_null_constraint_owner(), raw_generic_constraint_validator_file_factory()

### Community 481 - "Community 481"
Cohesion: 0.40
Nodes (1): f32

### Community 482 - "Community 482"
Cohesion: 0.40
Nodes (1): f64

### Community 483 - "Community 483"
Cohesion: 0.40
Nodes (1): i16

### Community 484 - "Community 484"
Cohesion: 0.40
Nodes (1): i32

### Community 485 - "Community 485"
Cohesion: 0.40
Nodes (1): i64

### Community 486 - "Community 486"
Cohesion: 0.40
Nodes (1): i8

### Community 487 - "Community 487"
Cohesion: 0.40
Nodes (1): isize

### Community 488 - "Community 488"
Cohesion: 0.40
Nodes (5): read_be(), read_be_at(), read_le(), read_le_at(), round_trip_consistency()

### Community 489 - "Community 489"
Cohesion: 0.40
Nodes (1): u16

### Community 490 - "Community 490"
Cohesion: 0.40
Nodes (1): u32

### Community 491 - "Community 491"
Cohesion: 0.40
Nodes (1): u64

### Community 492 - "Community 492"
Cohesion: 0.40
Nodes (1): u8

### Community 493 - "Community 493"
Cohesion: 0.40
Nodes (1): usize

### Community 494 - "Community 494"
Cohesion: 0.50
Nodes (1): TableId

### Community 495 - "Community 495"
Cohesion: 0.50
Nodes (1): CustomAttributeRaw

### Community 496 - "Community 496"
Cohesion: 0.50
Nodes (3): CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue

### Community 497 - "Community 497"
Cohesion: 0.50
Nodes (1): CustomDebugInformationRaw

### Community 499 - "Community 499"
Cohesion: 0.50
Nodes (1): DocumentRaw

### Community 500 - "Community 500"
Cohesion: 0.67
Nodes (2): CilObjectData, load_native_tables()

### Community 501 - "Community 501"
Cohesion: 0.50
Nodes (1): MetadataLoader

### Community 502 - "Community 502"
Cohesion: 0.50
Nodes (1): ExportedType

### Community 503 - "Community 503"
Cohesion: 0.50
Nodes (1): GenericParamRaw

### Community 504 - "Community 504"
Cohesion: 0.50
Nodes (1): ImportScopeRaw

### Community 505 - "Community 505"
Cohesion: 0.50
Nodes (1): LocalConstantRaw

### Community 506 - "Community 506"
Cohesion: 0.50
Nodes (1): LocalScopeRef

### Community 507 - "Community 507"
Cohesion: 0.50
Nodes (1): LocalScopeRaw

### Community 508 - "Community 508"
Cohesion: 0.50
Nodes (1): LocalVariableRaw

### Community 509 - "Community 509"
Cohesion: 0.50
Nodes (1): MethodDebugInformationRaw

### Community 510 - "Community 510"
Cohesion: 0.50
Nodes (1): MethodSpecRaw

### Community 511 - "Community 511"
Cohesion: 0.50
Nodes (2): StandAloneSig, StandAloneSignature

### Community 512 - "Community 512"
Cohesion: 0.50
Nodes (1): StateMachineMethodRaw

### Community 513 - "Community 513"
Cohesion: 0.83
Nodes (3): fuzzer_corpus(), fuzzer_crashes(), test_load_path()

### Community 514 - "Community 514"
Cohesion: 0.50
Nodes (1): InstructionIterator<'a>

### Community 515 - "Community 515"
Cohesion: 0.50
Nodes (1): ArchTestResult<T>

### Community 516 - "Community 516"
Cohesion: 0.50
Nodes (1): CilTypeRefListIter<'a>

### Community 517 - "Community 517"
Cohesion: 0.50
Nodes (4): read_compressed_int(), read_compressed_int_at(), read_compressed_uint(), read_compressed_uint_at()

### Community 520 - "Community 520"
Cohesion: 0.67
Nodes (1): AssemblyRefOs

### Community 522 - "Community 522"
Cohesion: 0.67
Nodes (1): AssemblyRefProcessor

### Community 525 - "Community 525"
Cohesion: 0.67
Nodes (1): HeapChanges<Vec<u8>>

### Community 526 - "Community 526"
Cohesion: 0.67
Nodes (1): ClassLayout

### Community 529 - "Community 529"
Cohesion: 0.67
Nodes (1): CustomAttribute

### Community 534 - "Community 534"
Cohesion: 1.00
Nodes (2): test_write_assembly_to_file_basic(), write_assembly_to_file()

### Community 535 - "Community 535"
Cohesion: 0.67
Nodes (1): Error

### Community 536 - "Community 536"
Cohesion: 0.67
Nodes (1): LoaderContext

### Community 537 - "Community 537"
Cohesion: 0.67
Nodes (2): LoaderGraph, LoaderKey

### Community 539 - "Community 539"
Cohesion: 0.67
Nodes (1): EventMapEntry

### Community 544 - "Community 544"
Cohesion: 0.67
Nodes (1): FieldLayout

### Community 546 - "Community 546"
Cohesion: 0.67
Nodes (1): FieldMarshal

### Community 549 - "Community 549"
Cohesion: 0.67
Nodes (1): FieldRva

### Community 552 - "Community 552"
Cohesion: 0.67
Nodes (1): GenericParam

### Community 554 - "Community 554"
Cohesion: 0.67
Nodes (1): GenericParamConstraint

### Community 556 - "Community 556"
Cohesion: 0.67
Nodes (1): ImplMap

### Community 559 - "Community 559"
Cohesion: 0.67
Nodes (1): InterfaceImpl

### Community 565 - "Community 565"
Cohesion: 0.67
Nodes (1): MemberRef

### Community 569 - "Community 569"
Cohesion: 0.67
Nodes (1): MethodImpl

### Community 572 - "Community 572"
Cohesion: 0.67
Nodes (1): MethodSemantics

### Community 577 - "Community 577"
Cohesion: 0.67
Nodes (1): NestedClass

### Community 579 - "Community 579"
Cohesion: 0.67
Nodes (1): Param

### Community 583 - "Community 583"
Cohesion: 0.67
Nodes (1): PropertyMapEntry

### Community 593 - "Community 593"
Cohesion: 0.67
Nodes (1): TableProducer<'a, T>

### Community 594 - "Community 594"
Cohesion: 1.00
Nodes (1): ResourceTypeRef<'a>

### Community 595 - "Community 595"
Cohesion: 0.67
Nodes (1): Vec<Box<dyn OwnedValidator>>

### Community 596 - "Community 596"
Cohesion: 0.67
Nodes (1): Vec<Box<dyn RawValidator>>

### Community 597 - "Community 597"
Cohesion: 1.00
Nodes (1): CilInstruction

### Community 598 - "Community 598"
Cohesion: 1.00
Nodes (1): Assembly

### Community 599 - "Community 599"
Cohesion: 1.00
Nodes (1): AssemblyRaw

### Community 600 - "Community 600"
Cohesion: 1.00
Nodes (1): AssemblyOsRaw

### Community 602 - "Community 602"
Cohesion: 1.00
Nodes (1): AssemblyProcessorRaw

### Community 604 - "Community 604"
Cohesion: 1.00
Nodes (1): AssemblyRefRc

### Community 605 - "Community 605"
Cohesion: 1.00
Nodes (1): AssemblyRef

### Community 606 - "Community 606"
Cohesion: 1.00
Nodes (1): AssemblyRefRaw

### Community 607 - "Community 607"
Cohesion: 1.00
Nodes (1): AssemblyRefOsRaw

### Community 608 - "Community 608"
Cohesion: 1.00
Nodes (1): AssemblyRefProcessorRaw

### Community 617 - "Community 617"
Cohesion: 1.00
Nodes (1): CapaError

### Community 618 - "Community 618"
Cohesion: 1.00
Nodes (1): HeapChanges<[u8; 16]>

### Community 619 - "Community 619"
Cohesion: 1.00
Nodes (1): ClassLayoutRaw

### Community 620 - "Community 620"
Cohesion: 1.00
Nodes (1): ConstantRaw

### Community 621 - "Community 621"
Cohesion: 1.00
Nodes (1): CustomAttributeRaw

### Community 622 - "Community 622"
Cohesion: 1.00
Nodes (1): CustomDebugInformation

### Community 623 - "Community 623"
Cohesion: 1.00
Nodes (1): CustomDebugInformationRaw

### Community 624 - "Community 624"
Cohesion: 1.00
Nodes (1): DeclSecurityRaw

### Community 625 - "Community 625"
Cohesion: 1.00
Nodes (1): DocumentRaw

### Community 631 - "Community 631"
Cohesion: 1.00
Nodes (1): HeapBuilder

### Community 632 - "Community 632"
Cohesion: 1.00
Nodes (1): InstructionIterator

### Community 635 - "Community 635"
Cohesion: 1.00
Nodes (1): Event

### Community 636 - "Community 636"
Cohesion: 1.00
Nodes (1): EventPtr

### Community 637 - "Community 637"
Cohesion: 1.00
Nodes (1): Field

### Community 638 - "Community 638"
Cohesion: 1.00
Nodes (1): FieldPtr

### Community 639 - "Community 639"
Cohesion: 1.00
Nodes (1): File

### Community 640 - "Community 640"
Cohesion: 1.00
Nodes (1): ImportScope

### Community 641 - "Community 641"
Cohesion: 1.00
Nodes (1): LocalConstant

### Community 642 - "Community 642"
Cohesion: 1.00
Nodes (1): LocalVariable

### Community 643 - "Community 643"
Cohesion: 1.00
Nodes (1): ManifestResource

### Community 644 - "Community 644"
Cohesion: 1.00
Nodes (1): MemberRefSignature

### Community 645 - "Community 645"
Cohesion: 1.00
Nodes (1): MethodDebugInformation

### Community 646 - "Community 646"
Cohesion: 1.00
Nodes (1): MethodPtr

### Community 647 - "Community 647"
Cohesion: 1.00
Nodes (1): MethodSpec

### Community 648 - "Community 648"
Cohesion: 1.00
Nodes (1): Module

### Community 649 - "Community 649"
Cohesion: 1.00
Nodes (1): ModuleRef

### Community 650 - "Community 650"
Cohesion: 1.00
Nodes (1): ParamPtr

### Community 651 - "Community 651"
Cohesion: 1.00
Nodes (1): Property

### Community 652 - "Community 652"
Cohesion: 1.00
Nodes (1): PropertyPtr

### Community 653 - "Community 653"
Cohesion: 1.00
Nodes (1): StateMachineMethod

### Community 654 - "Community 654"
Cohesion: 1.00
Nodes (1): TableRow

### Community 655 - "Community 655"
Cohesion: 1.00
Nodes (1): TableAccess

### Community 656 - "Community 656"
Cohesion: 1.00
Nodes (1): TableData

### Community 657 - "Community 657"
Cohesion: 1.00
Nodes (1): MetadataTable

### Community 658 - "Community 658"
Cohesion: 1.00
Nodes (1): RowReadable

### Community 659 - "Community 659"
Cohesion: 1.00
Nodes (1): RowWritable

### Community 660 - "Community 660"
Cohesion: 1.00
Nodes (1): TypeSpec

### Community 666 - "Community 666"
Cohesion: 1.00
Nodes (1): EncLogRaw

### Community 667 - "Community 667"
Cohesion: 1.00
Nodes (1): EncMapRaw

### Community 668 - "Community 668"
Cohesion: 1.00
Nodes (1): EventRaw

### Community 669 - "Community 669"
Cohesion: 1.00
Nodes (1): EventMapRaw

### Community 670 - "Community 670"
Cohesion: 1.00
Nodes (1): EventPtrRaw

### Community 671 - "Community 671"
Cohesion: 1.00
Nodes (1): ExportedTypeRaw

### Community 672 - "Community 672"
Cohesion: 1.00
Nodes (1): FieldRaw

### Community 673 - "Community 673"
Cohesion: 1.00
Nodes (1): FieldLayoutRaw

### Community 674 - "Community 674"
Cohesion: 1.00
Nodes (1): FieldMarshalRaw

### Community 675 - "Community 675"
Cohesion: 1.00
Nodes (1): FieldPtrRaw

### Community 676 - "Community 676"
Cohesion: 1.00
Nodes (1): FieldRvaRaw

### Community 677 - "Community 677"
Cohesion: 1.00
Nodes (1): Arc<File>

### Community 678 - "Community 678"
Cohesion: 1.00
Nodes (1): FileRaw

### Community 679 - "Community 679"
Cohesion: 1.00
Nodes (1): GenericParamRaw

### Community 680 - "Community 680"
Cohesion: 1.00
Nodes (1): GenericParamConstraintRaw

### Community 681 - "Community 681"
Cohesion: 1.00
Nodes (1): BlobHeapBuilder<'a>

### Community 682 - "Community 682"
Cohesion: 1.00
Nodes (1): GuidHeapBuilder<'a>

### Community 683 - "Community 683"
Cohesion: 1.00
Nodes (1): StringHeapBuilder<'a>

### Community 684 - "Community 684"
Cohesion: 1.00
Nodes (1): ImplMapRaw

### Community 685 - "Community 685"
Cohesion: 1.00
Nodes (1): ImportScopeRaw

### Community 686 - "Community 686"
Cohesion: 1.00
Nodes (1): InterfaceImplRaw

### Community 687 - "Community 687"
Cohesion: 1.00
Nodes (1): LocalConstantRaw

### Community 688 - "Community 688"
Cohesion: 1.00
Nodes (1): LocalScopeRaw

### Community 689 - "Community 689"
Cohesion: 1.00
Nodes (1): LocalVariableRaw

### Community 690 - "Community 690"
Cohesion: 1.00
Nodes (1): ManifestResourceRaw

### Community 691 - "Community 691"
Cohesion: 1.00
Nodes (1): MemberRefRaw

### Community 692 - "Community 692"
Cohesion: 1.00
Nodes (1): MethodImplCodeType

### Community 693 - "Community 693"
Cohesion: 1.00
Nodes (1): MethodImplManagement

### Community 694 - "Community 694"
Cohesion: 1.00
Nodes (1): MethodImplOptions

### Community 695 - "Community 695"
Cohesion: 1.00
Nodes (1): MethodModifiers

### Community 696 - "Community 696"
Cohesion: 1.00
Nodes (1): MethodVtableFlags

### Community 697 - "Community 697"
Cohesion: 1.00
Nodes (1): MethodDebugInformationRaw

### Community 698 - "Community 698"
Cohesion: 1.00
Nodes (1): MethodDefRaw

### Community 699 - "Community 699"
Cohesion: 1.00
Nodes (1): MethodImplRaw

### Community 700 - "Community 700"
Cohesion: 1.00
Nodes (1): MethodPtrRaw

### Community 701 - "Community 701"
Cohesion: 1.00
Nodes (1): MethodSemanticsRaw

### Community 702 - "Community 702"
Cohesion: 1.00
Nodes (1): MethodSpecRaw

### Community 703 - "Community 703"
Cohesion: 1.00
Nodes (1): ModuleRaw

### Community 704 - "Community 704"
Cohesion: 1.00
Nodes (1): Arc<ModuleRef>

### Community 705 - "Community 705"
Cohesion: 1.00
Nodes (1): ModuleRefRaw

### Community 706 - "Community 706"
Cohesion: 1.00
Nodes (1): NestedClassRaw

### Community 707 - "Community 707"
Cohesion: 1.00
Nodes (1): ParamRaw

### Community 708 - "Community 708"
Cohesion: 1.00
Nodes (1): ParamPtrRaw

### Community 709 - "Community 709"
Cohesion: 1.00
Nodes (1): PropertyRaw

### Community 710 - "Community 710"
Cohesion: 1.00
Nodes (1): PropertyMapRaw

### Community 711 - "Community 711"
Cohesion: 1.00
Nodes (1): PropertyPtrRaw

### Community 712 - "Community 712"
Cohesion: 1.00
Nodes (1): TableIterator<'_, T>

### Community 713 - "Community 713"
Cohesion: 1.00
Nodes (1): TableParIterator<'a, T>

### Community 714 - "Community 714"
Cohesion: 1.00
Nodes (1): u16

### Community 715 - "Community 715"
Cohesion: 1.00
Nodes (1): StandAloneSigRaw

### Community 716 - "Community 716"
Cohesion: 1.00
Nodes (1): StateMachineMethodRaw

### Community 717 - "Community 717"
Cohesion: 1.00
Nodes (2): make_features_with(), match_with_env()

### Community 718 - "Community 718"
Cohesion: 1.00
Nodes (2): make_features(), match_single()

### Community 719 - "Community 719"
Cohesion: 1.00
Nodes (2): make_features(), matches_rule()

### Community 720 - "Community 720"
Cohesion: 1.00
Nodes (1): TypeDefRaw

### Community 721 - "Community 721"
Cohesion: 1.00
Nodes (1): TypeRefRaw

### Community 722 - "Community 722"
Cohesion: 1.00
Nodes (1): TypeSpecRaw

### Community 723 - "Community 723"
Cohesion: 1.00
Nodes (1): bool

### Community 724 - "Community 724"
Cohesion: 1.00
Nodes (1): f64

### Community 725 - "Community 725"
Cohesion: 1.00
Nodes (1): String

## Knowledge Gaps
- **353 isolated node(s):** `DotNetMethodFeatures`, `DotNetExtractedFeatures`, `SampleHashes`, `LiftedProgram`, `LiftedFunction` (+348 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 3`** (1 nodes): `InstructionAssembler`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (1 nodes): `CilType`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (2 nodes): `make_features()`, `matches_rule()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (1 nodes): `CilObject`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `LayoutPlanner<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (2 nodes): `make_features()`, `matches_rule()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 79`** (2 nodes): `OwnedInheritanceValidator`, `test_owned_inheritance_validator_comprehensive()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 82`** (1 nodes): `MethodBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 97`** (1 nodes): `PermissionSet`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 105`** (2 nodes): `TableInfo`, `TableRowInfo`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 110`** (2 nodes): `OwnedSecurityValidator`, `test_owned_security_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 118`** (2 nodes): `test_write_executor_with_basic_layout()`, `WriteExecutor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 141`** (2 nodes): `ProjectResult`, `VersionMismatch`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 155`** (1 nodes): `ResourceTypeRef<'_>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 156`** (1 nodes): `ResourceType`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 166`** (2 nodes): `OwnedAssemblyValidator`, `test_owned_assembly_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 169`** (2 nodes): `CustomDebugInfo`, `CustomDebugKind`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 174`** (2 nodes): `OwnedAttributeValidator`, `test_owned_attribute_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 175`** (2 nodes): `OwnedTypeDefinitionValidator`, `test_owned_type_definition_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 177`** (2 nodes): `OwnedTypeConstraintValidator`, `test_owned_type_constraint_validator_comprehensive()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 179`** (2 nodes): `MarshallingInfo`, `NativeType`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 185`** (2 nodes): `OwnedOwnershipValidator`, `test_owned_ownership_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 189`** (2 nodes): `CilTypeBuilder`, `create_exportedtype()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 192`** (2 nodes): `RawLayoutConstraintValidator`, `test_raw_layout_constraint_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 203`** (2 nodes): `OwnedCircularityValidator`, `test_owned_circularity_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 204`** (2 nodes): `OwnedTypeCircularityValidator`, `test_owned_type_circularity_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 207`** (1 nodes): `Pe`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 209`** (2 nodes): `FileBuilder`, `ModuleRefBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 210`** (2 nodes): `RawGenericConstraintValidator`, `test_raw_generic_constraint_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 229`** (2 nodes): `OwnedAccessibilityValidator`, `test_owned_accessibility_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 230`** (2 nodes): `OwnedFieldValidator`, `test_owned_field_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 231`** (2 nodes): `OwnedMethodValidator`, `test_owned_method_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 232`** (2 nodes): `OwnedTypeDependencyValidator`, `test_owned_type_dependency_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 233`** (1 nodes): `ProjectContext`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 237`** (1 nodes): `AssemblyRefBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 243`** (1 nodes): `DeclSecurity`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 251`** (2 nodes): `OwnedDependencyValidator`, `test_owned_dependency_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 252`** (2 nodes): `OwnedTypeOwnershipValidator`, `test_owned_type_ownership_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 259`** (2 nodes): `UserStringHeapBuilder`, `UserStringHeapBuilder<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 268`** (2 nodes): `OwnedSignatureValidator`, `test_owned_signature_validator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 270`** (1 nodes): `EnumUtils`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 273`** (1 nodes): `SectionTable`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 292`** (1 nodes): `Document`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 300`** (1 nodes): `TableDataOwned`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 302`** (1 nodes): `LoaderGraph<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 303`** (2 nodes): `TableParIterator<'_, T>`, `TableProducerIterator<'_, T>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 306`** (2 nodes): `CodedIndex`, `CodedIndexType`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 309`** (1 nodes): `BlobHeapBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 310`** (1 nodes): `StringHeapBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 313`** (1 nodes): `LocalScope`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 325`** (1 nodes): `DosHeader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 326`** (1 nodes): `DataDirectories`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 328`** (2 nodes): `&'a MetadataTable<'a, T>`, `MetadataTable<'a, T>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 329`** (2 nodes): `test_get_file_paths()`, `test_get_file_paths_no_fileio_permission()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 359`** (2 nodes): `FeatureExtractor`, `NullExtractor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 361`** (1 nodes): `GuidHeapBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 363`** (1 nodes): `EventMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 364`** (1 nodes): `ExportedTypeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 365`** (1 nodes): `MemberRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 366`** (1 nodes): `PropertyMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 367`** (1 nodes): `TypeDefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 376`** (2 nodes): `create_cil_type()`, `create_file()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 377`** (1 nodes): `CoffHeader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 378`** (1 nodes): `AssemblyLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 379`** (1 nodes): `AssemblyRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 380`** (1 nodes): `AssemblyOsLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 381`** (1 nodes): `AssemblyOsRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 382`** (1 nodes): `AssemblyProcessorLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 383`** (1 nodes): `AssemblyProcessorRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 384`** (1 nodes): `AssemblyRefLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 385`** (1 nodes): `AssemblyRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 386`** (1 nodes): `AssemblyRefOsLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 387`** (1 nodes): `AssemblyRefOsRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 388`** (1 nodes): `AssemblyRefProcessorLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 389`** (1 nodes): `AssemblyRefProcessorRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 390`** (1 nodes): `IdaExtractor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 392`** (1 nodes): `ClassLayoutLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 393`** (1 nodes): `ClassLayoutRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 394`** (1 nodes): `ConstantLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 395`** (1 nodes): `ConstantRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 396`** (1 nodes): `CustomAttributeLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 397`** (1 nodes): `CustomDebugInformationLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 398`** (1 nodes): `DeclSecurityLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 399`** (1 nodes): `DeclSecurityRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 400`** (1 nodes): `DocumentLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 402`** (1 nodes): `InheritanceResolver`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 404`** (1 nodes): `EncLogLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 405`** (1 nodes): `EncLogRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 406`** (1 nodes): `EncMapLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 407`** (1 nodes): `EncMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 408`** (1 nodes): `EventLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 409`** (1 nodes): `EventRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 410`** (1 nodes): `EventMapLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 411`** (1 nodes): `EventPtrLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 412`** (1 nodes): `EventPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 413`** (1 nodes): `ExportedTypeLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 414`** (1 nodes): `FieldLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 415`** (1 nodes): `FieldRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 416`** (1 nodes): `FieldLayoutLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 417`** (1 nodes): `FieldLayoutRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 418`** (1 nodes): `FieldMarshalLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 419`** (1 nodes): `FieldMarshalRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 420`** (1 nodes): `FieldPtrLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 421`** (1 nodes): `FieldPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 422`** (1 nodes): `FieldRvaLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 423`** (1 nodes): `FieldRvaRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 424`** (1 nodes): `FileLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 425`** (1 nodes): `FileRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 426`** (1 nodes): `GenericParamLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 427`** (1 nodes): `GenericParamConstraintLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 428`** (1 nodes): `GenericParamConstraintRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 429`** (1 nodes): `ImplMapLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 430`** (1 nodes): `ImplMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 431`** (1 nodes): `ImportScopeLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 432`** (1 nodes): `InterfaceImplLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 433`** (1 nodes): `InterfaceImplRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 434`** (1 nodes): `LocalConstantLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 435`** (1 nodes): `LocalScopeLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 436`** (1 nodes): `LocalVariableLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 437`** (1 nodes): `ManifestResourceLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 438`** (1 nodes): `ManifestResourceRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 439`** (1 nodes): `MemberRefLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 440`** (1 nodes): `MethodDebugInformationLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 441`** (1 nodes): `MethodDefLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 442`** (1 nodes): `MethodDefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 443`** (1 nodes): `MethodImplLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 444`** (1 nodes): `MethodImplRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 445`** (1 nodes): `MethodPtrLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 446`** (1 nodes): `MethodPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 447`** (1 nodes): `MethodSemanticsLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 448`** (1 nodes): `MethodSemanticsRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 449`** (1 nodes): `MethodSpecLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 450`** (1 nodes): `ModuleLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 451`** (1 nodes): `ModuleRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 452`** (1 nodes): `ModuleRefLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 453`** (1 nodes): `ModuleRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 454`** (1 nodes): `NestedClassLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 455`** (1 nodes): `NestedClassRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 456`** (1 nodes): `ParamLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 457`** (1 nodes): `ParamRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 458`** (1 nodes): `ParamPtrLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 459`** (1 nodes): `ParamPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 460`** (1 nodes): `PropertyLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 461`** (1 nodes): `PropertyRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 462`** (1 nodes): `PropertyMapLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 463`** (1 nodes): `PropertyPtrLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 464`** (1 nodes): `PropertyPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 465`** (1 nodes): `StandAloneSigLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 466`** (1 nodes): `StandAloneSigRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 467`** (1 nodes): `StateMachineMethodLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 468`** (1 nodes): `TypeDefLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 469`** (1 nodes): `TypeRefLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 470`** (1 nodes): `TypeRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 472`** (1 nodes): `TypeSpecLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 473`** (1 nodes): `TypeSpecRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 481`** (1 nodes): `f32`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 482`** (1 nodes): `f64`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 483`** (1 nodes): `i16`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 484`** (1 nodes): `i32`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 485`** (1 nodes): `i64`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 486`** (1 nodes): `i8`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 487`** (1 nodes): `isize`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 489`** (1 nodes): `u16`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 490`** (1 nodes): `u32`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 491`** (1 nodes): `u64`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 492`** (1 nodes): `u8`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 493`** (1 nodes): `usize`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 494`** (1 nodes): `TableId`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 495`** (1 nodes): `CustomAttributeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 497`** (1 nodes): `CustomDebugInformationRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 499`** (1 nodes): `DocumentRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 500`** (2 nodes): `CilObjectData`, `load_native_tables()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 501`** (1 nodes): `MetadataLoader`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 502`** (1 nodes): `ExportedType`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 503`** (1 nodes): `GenericParamRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 504`** (1 nodes): `ImportScopeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 505`** (1 nodes): `LocalConstantRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 506`** (1 nodes): `LocalScopeRef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 507`** (1 nodes): `LocalScopeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 508`** (1 nodes): `LocalVariableRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 509`** (1 nodes): `MethodDebugInformationRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 510`** (1 nodes): `MethodSpecRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 511`** (2 nodes): `StandAloneSig`, `StandAloneSignature`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 512`** (1 nodes): `StateMachineMethodRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 514`** (1 nodes): `InstructionIterator<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 515`** (1 nodes): `ArchTestResult<T>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 516`** (1 nodes): `CilTypeRefListIter<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 520`** (1 nodes): `AssemblyRefOs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 522`** (1 nodes): `AssemblyRefProcessor`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 525`** (1 nodes): `HeapChanges<Vec<u8>>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 526`** (1 nodes): `ClassLayout`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 529`** (1 nodes): `CustomAttribute`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 534`** (2 nodes): `test_write_assembly_to_file_basic()`, `write_assembly_to_file()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 535`** (1 nodes): `Error`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 536`** (1 nodes): `LoaderContext`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 537`** (2 nodes): `LoaderGraph`, `LoaderKey`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 539`** (1 nodes): `EventMapEntry`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 544`** (1 nodes): `FieldLayout`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 546`** (1 nodes): `FieldMarshal`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 549`** (1 nodes): `FieldRva`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 552`** (1 nodes): `GenericParam`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 554`** (1 nodes): `GenericParamConstraint`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 556`** (1 nodes): `ImplMap`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 559`** (1 nodes): `InterfaceImpl`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 565`** (1 nodes): `MemberRef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 569`** (1 nodes): `MethodImpl`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 572`** (1 nodes): `MethodSemantics`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 577`** (1 nodes): `NestedClass`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 579`** (1 nodes): `Param`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 583`** (1 nodes): `PropertyMapEntry`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 593`** (1 nodes): `TableProducer<'a, T>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 594`** (1 nodes): `ResourceTypeRef<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 595`** (1 nodes): `Vec<Box<dyn OwnedValidator>>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 596`** (1 nodes): `Vec<Box<dyn RawValidator>>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 597`** (1 nodes): `CilInstruction`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 598`** (1 nodes): `Assembly`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 599`** (1 nodes): `AssemblyRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 600`** (1 nodes): `AssemblyOsRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 602`** (1 nodes): `AssemblyProcessorRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 604`** (1 nodes): `AssemblyRefRc`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 605`** (1 nodes): `AssemblyRef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 606`** (1 nodes): `AssemblyRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 607`** (1 nodes): `AssemblyRefOsRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 608`** (1 nodes): `AssemblyRefProcessorRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 617`** (1 nodes): `CapaError`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 618`** (1 nodes): `HeapChanges<[u8; 16]>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 619`** (1 nodes): `ClassLayoutRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 620`** (1 nodes): `ConstantRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 621`** (1 nodes): `CustomAttributeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 622`** (1 nodes): `CustomDebugInformation`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 623`** (1 nodes): `CustomDebugInformationRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 624`** (1 nodes): `DeclSecurityRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 625`** (1 nodes): `DocumentRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 631`** (1 nodes): `HeapBuilder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 632`** (1 nodes): `InstructionIterator`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 635`** (1 nodes): `Event`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 636`** (1 nodes): `EventPtr`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 637`** (1 nodes): `Field`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 638`** (1 nodes): `FieldPtr`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 639`** (1 nodes): `File`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 640`** (1 nodes): `ImportScope`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 641`** (1 nodes): `LocalConstant`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 642`** (1 nodes): `LocalVariable`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 643`** (1 nodes): `ManifestResource`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 644`** (1 nodes): `MemberRefSignature`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 645`** (1 nodes): `MethodDebugInformation`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 646`** (1 nodes): `MethodPtr`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 647`** (1 nodes): `MethodSpec`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 648`** (1 nodes): `Module`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 649`** (1 nodes): `ModuleRef`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 650`** (1 nodes): `ParamPtr`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 651`** (1 nodes): `Property`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 652`** (1 nodes): `PropertyPtr`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 653`** (1 nodes): `StateMachineMethod`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 654`** (1 nodes): `TableRow`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 655`** (1 nodes): `TableAccess`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 656`** (1 nodes): `TableData`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 657`** (1 nodes): `MetadataTable`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 658`** (1 nodes): `RowReadable`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 659`** (1 nodes): `RowWritable`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 660`** (1 nodes): `TypeSpec`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 666`** (1 nodes): `EncLogRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 667`** (1 nodes): `EncMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 668`** (1 nodes): `EventRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 669`** (1 nodes): `EventMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 670`** (1 nodes): `EventPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 671`** (1 nodes): `ExportedTypeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 672`** (1 nodes): `FieldRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 673`** (1 nodes): `FieldLayoutRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 674`** (1 nodes): `FieldMarshalRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 675`** (1 nodes): `FieldPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 676`** (1 nodes): `FieldRvaRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 677`** (1 nodes): `Arc<File>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 678`** (1 nodes): `FileRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 679`** (1 nodes): `GenericParamRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 680`** (1 nodes): `GenericParamConstraintRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 681`** (1 nodes): `BlobHeapBuilder<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 682`** (1 nodes): `GuidHeapBuilder<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 683`** (1 nodes): `StringHeapBuilder<'a>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 684`** (1 nodes): `ImplMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 685`** (1 nodes): `ImportScopeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 686`** (1 nodes): `InterfaceImplRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 687`** (1 nodes): `LocalConstantRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 688`** (1 nodes): `LocalScopeRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 689`** (1 nodes): `LocalVariableRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 690`** (1 nodes): `ManifestResourceRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 691`** (1 nodes): `MemberRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 692`** (1 nodes): `MethodImplCodeType`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 693`** (1 nodes): `MethodImplManagement`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 694`** (1 nodes): `MethodImplOptions`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 695`** (1 nodes): `MethodModifiers`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 696`** (1 nodes): `MethodVtableFlags`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 697`** (1 nodes): `MethodDebugInformationRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 698`** (1 nodes): `MethodDefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 699`** (1 nodes): `MethodImplRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 700`** (1 nodes): `MethodPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 701`** (1 nodes): `MethodSemanticsRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 702`** (1 nodes): `MethodSpecRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 703`** (1 nodes): `ModuleRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 704`** (1 nodes): `Arc<ModuleRef>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 705`** (1 nodes): `ModuleRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 706`** (1 nodes): `NestedClassRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 707`** (1 nodes): `ParamRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 708`** (1 nodes): `ParamPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 709`** (1 nodes): `PropertyRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 710`** (1 nodes): `PropertyMapRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 711`** (1 nodes): `PropertyPtrRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 712`** (1 nodes): `TableIterator<'_, T>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 713`** (1 nodes): `TableParIterator<'a, T>`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 714`** (1 nodes): `u16`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 715`** (1 nodes): `StandAloneSigRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 716`** (1 nodes): `StateMachineMethodRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 717`** (2 nodes): `make_features_with()`, `match_with_env()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 718`** (2 nodes): `make_features()`, `match_single()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 719`** (2 nodes): `make_features()`, `matches_rule()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 720`** (1 nodes): `TypeDefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 721`** (1 nodes): `TypeRefRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 722`** (1 nodes): `TypeSpecRaw`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 723`** (1 nodes): `bool`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 724`** (1 nodes): `f64`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 725`** (1 nodes): `String`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `InstructionAssembler` connect `Community 3` to `Community 60`, `Community 275`, `Community 274`, `Community 330`, `Community 256`?**
  _High betweenness centrality (0.000) - this node is a cross-community bridge._
- **Why does `LayoutPlanner<'a>` connect `Community 40` to `Community 130`, `Community 480`, `Community 255`, `Community 327`, `Community 288`, `Community 351`?**
  _High betweenness centrality (0.000) - this node is a cross-community bridge._
- **Why does `PermissionSet` connect `Community 97` to `Community 42`, `Community 329`?**
  _High betweenness centrality (0.000) - this node is a cross-community bridge._
- **What connects `DotNetMethodFeatures`, `DotNetExtractedFeatures`, `SampleHashes` to the rest of the system?**
  _353 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.051228070175438595 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.07894736842105263 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06841046277665996 - nodes in this community are weakly interconnected._