// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.5
// source: datadog/api/v1/api.proto

package pbgo

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_datadog_api_v1_api_proto protoreflect.FileDescriptor

var file_datadog_api_v1_api_proto_rawDesc = []byte{
	0x0a, 0x18, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31,
	0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2f, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x6f, 0x64,
	0x65, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x72,
	0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x71, 0x0a, 0x05,
	0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x68, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x21, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d,
	0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x6e,
	0x61, 0x6d, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x15, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0f,
	0x12, 0x0d, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x32,
	0xe4, 0x06, 0x0a, 0x0b, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x12,
	0x8f, 0x01, 0x0a, 0x14, 0x54, 0x61, 0x67, 0x67, 0x65, 0x72, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x12, 0x23, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64,
	0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x54, 0x61, 0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e,
	0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x54, 0x61, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x2a, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x24, 0x22, 0x1f, 0x2f, 0x76, 0x31,
	0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x3a, 0x01, 0x2a, 0x30,
	0x01, 0x12, 0x89, 0x01, 0x0a, 0x11, 0x54, 0x61, 0x67, 0x67, 0x65, 0x72, 0x46, 0x65, 0x74, 0x63,
	0x68, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x24, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x65, 0x74, 0x63, 0x68,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e,
	0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31,
	0x2e, 0x46, 0x65, 0x74, 0x63, 0x68, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x27, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x21, 0x22, 0x1c, 0x2f, 0x76,
	0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f, 0x66, 0x65,
	0x74, 0x63, 0x68, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x3a, 0x01, 0x2a, 0x12, 0x9b, 0x01,
	0x0a, 0x17, 0x44, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x43, 0x61, 0x70, 0x74, 0x75,
	0x72, 0x65, 0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x12, 0x27, 0x2e, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x61, 0x70,
	0x74, 0x75, 0x72, 0x65, 0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x28, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x6d, 0x6f, 0x64,
	0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x54, 0x72, 0x69,
	0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2d, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x27, 0x22, 0x22, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x64,
	0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x2f, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65,
	0x2f, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x3a, 0x01, 0x2a, 0x12, 0x8c, 0x01, 0x0a, 0x17,
	0x44, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x53, 0x65, 0x74, 0x54, 0x61, 0x67, 0x67,
	0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1d, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x61, 0x67, 0x67, 0x65,
	0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x1a, 0x25, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67,
	0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x61, 0x67, 0x67, 0x65, 0x72,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2b, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x25, 0x22, 0x20, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f,
	0x64, 0x6f, 0x67, 0x73, 0x74, 0x61, 0x74, 0x73, 0x64, 0x2f, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72,
	0x65, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x01, 0x2a, 0x12, 0x8f, 0x01, 0x0a, 0x10, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x12,
	0x27, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x28, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64,
	0x6f, 0x67, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x28, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x22, 0x22, 0x1d, 0x2f, 0x76, 0x31, 0x2f,
	0x67, 0x72, 0x70, 0x63, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x3a, 0x01, 0x2a, 0x12, 0x78, 0x0a, 0x0e,
	0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x26, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x26,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x20, 0x22, 0x1b, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x3a, 0x01, 0x2a, 0x42, 0x10, 0x5a, 0x0e, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x62, 0x67, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_datadog_api_v1_api_proto_goTypes = []interface{}{
	(*HostnameRequest)(nil),          // 0: datadog.model.v1.HostnameRequest
	(*StreamTagsRequest)(nil),        // 1: datadog.model.v1.StreamTagsRequest
	(*FetchEntityRequest)(nil),       // 2: datadog.model.v1.FetchEntityRequest
	(*CaptureTriggerRequest)(nil),    // 3: datadog.model.v1.CaptureTriggerRequest
	(*TaggerState)(nil),              // 4: datadog.model.v1.TaggerState
	(*ClientGetConfigsRequest)(nil),  // 5: datadog.config.ClientGetConfigsRequest
	(*emptypb.Empty)(nil),            // 6: google.protobuf.Empty
	(*HostnameReply)(nil),            // 7: datadog.model.v1.HostnameReply
	(*StreamTagsResponse)(nil),       // 8: datadog.model.v1.StreamTagsResponse
	(*FetchEntityResponse)(nil),      // 9: datadog.model.v1.FetchEntityResponse
	(*CaptureTriggerResponse)(nil),   // 10: datadog.model.v1.CaptureTriggerResponse
	(*TaggerStateResponse)(nil),      // 11: datadog.model.v1.TaggerStateResponse
	(*ClientGetConfigsResponse)(nil), // 12: datadog.config.ClientGetConfigsResponse
	(*GetStateConfigResponse)(nil),   // 13: datadog.config.GetStateConfigResponse
}
var file_datadog_api_v1_api_proto_depIdxs = []int32{
	0,  // 0: datadog.api.v1.Agent.GetHostname:input_type -> datadog.model.v1.HostnameRequest
	1,  // 1: datadog.api.v1.AgentSecure.TaggerStreamEntities:input_type -> datadog.model.v1.StreamTagsRequest
	2,  // 2: datadog.api.v1.AgentSecure.TaggerFetchEntity:input_type -> datadog.model.v1.FetchEntityRequest
	3,  // 3: datadog.api.v1.AgentSecure.DogstatsdCaptureTrigger:input_type -> datadog.model.v1.CaptureTriggerRequest
	4,  // 4: datadog.api.v1.AgentSecure.DogstatsdSetTaggerState:input_type -> datadog.model.v1.TaggerState
	5,  // 5: datadog.api.v1.AgentSecure.ClientGetConfigs:input_type -> datadog.config.ClientGetConfigsRequest
	6,  // 6: datadog.api.v1.AgentSecure.GetConfigState:input_type -> google.protobuf.Empty
	7,  // 7: datadog.api.v1.Agent.GetHostname:output_type -> datadog.model.v1.HostnameReply
	8,  // 8: datadog.api.v1.AgentSecure.TaggerStreamEntities:output_type -> datadog.model.v1.StreamTagsResponse
	9,  // 9: datadog.api.v1.AgentSecure.TaggerFetchEntity:output_type -> datadog.model.v1.FetchEntityResponse
	10, // 10: datadog.api.v1.AgentSecure.DogstatsdCaptureTrigger:output_type -> datadog.model.v1.CaptureTriggerResponse
	11, // 11: datadog.api.v1.AgentSecure.DogstatsdSetTaggerState:output_type -> datadog.model.v1.TaggerStateResponse
	12, // 12: datadog.api.v1.AgentSecure.ClientGetConfigs:output_type -> datadog.config.ClientGetConfigsResponse
	13, // 13: datadog.api.v1.AgentSecure.GetConfigState:output_type -> datadog.config.GetStateConfigResponse
	7,  // [7:14] is the sub-list for method output_type
	0,  // [0:7] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_datadog_api_v1_api_proto_init() }
func file_datadog_api_v1_api_proto_init() {
	if File_datadog_api_v1_api_proto != nil {
		return
	}
	file_datadog_model_v1_model_proto_init()
	file_datadog_remoteconfig_remoteconfig_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_datadog_api_v1_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_datadog_api_v1_api_proto_goTypes,
		DependencyIndexes: file_datadog_api_v1_api_proto_depIdxs,
	}.Build()
	File_datadog_api_v1_api_proto = out.File
	file_datadog_api_v1_api_proto_rawDesc = nil
	file_datadog_api_v1_api_proto_goTypes = nil
	file_datadog_api_v1_api_proto_depIdxs = nil
}
