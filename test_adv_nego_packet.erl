#!/usr/bin/env escript
%% Test script to generate and display advanced negotiation packet bytes

-include("include/jamdb_oracle.hrl").

main(_) ->
    %% Build the advanced negotiation packet
    Packet = build_nego_request(),

    io:format("Advanced Negotiation Packet (~p bytes):~n", [byte_size(Packet)]),
    io:format("~nHex dump:~n"),
    print_hex(Packet, 0),

    io:format("~n~nExpected total size: 147 bytes~n"),
    io:format("Actual size: ~p bytes~n", [byte_size(Packet)]),

    %% Wrap in TNS DATA packet
    Length = 8192,  %% Typical SDU
    {TNSPacket, _} = encode_packet(6, Packet, Length),
    io:format("~nTNS DATA Packet (~p bytes):~n", [byte_size(TNSPacket)]),
    io:format("~nFirst 20 bytes (TNS header + start of data):~n"),
    <<Header:20/binary, _/binary>> = TNSPacket,
    print_hex(Header, 0).

print_hex(<<>>, _) ->
    ok;
print_hex(Data, Offset) when byte_size(Data) >= 16 ->
    <<Line:16/binary, Rest/binary>> = Data,
    io:format("~4.16.0B: ~s  ~s~n", [
        Offset,
        format_hex_bytes(Line),
        format_ascii(Line)
    ]),
    print_hex(Rest, Offset + 16);
print_hex(Data, Offset) ->
    io:format("~4.16.0B: ~s  ~s~n", [
        Offset,
        format_hex_bytes(Data),
        format_ascii(Data)
    ]).

format_hex_bytes(<<>>) -> "";
format_hex_bytes(<<B, Rest/binary>>) ->
    io_lib:format("~2.16.0B ", [B]) ++ format_hex_bytes(Rest).

format_ascii(<<>>) -> "";
format_ascii(<<B, Rest/binary>>) when B >= 32, B =< 126 ->
    [B | format_ascii(Rest)];
format_ascii(<<_, Rest/binary>>) ->
    [$. | format_ascii(Rest)].

%% Copy of jamdb_oracle_tns_encoder:encode_packet/3
encode_packet(6, Data, Length) ->
    PacketSize = byte_size(Data) + 10,
    BodySize = Length - 10,
    case Data of
        <<PacketBody:BodySize/binary, Rest/bits>> when PacketSize > Length ->
            {<<Length:16, 0:16, 6:8, 0:8, 0:16, 32:16, PacketBody/binary>>, Rest};
        _ ->  {<<PacketSize:16, 0:16, 6:8, 0:8, 0:16, 0:16, Data/binary>>, <<>>}
    end.

%% Service type constants
-define(SERVICE_AUTH, 1).
-define(SERVICE_ENCRYPTION, 2).
-define(SERVICE_DATA_INTEGRITY, 3).
-define(SERVICE_SUPERVISOR, 4).

%% Algorithm IDs
-define(ALGO_AES256, 17).
-define(ALGO_AES192, 16).
-define(ALGO_AES128, 15).
-define(ALGO_DES56C, 2).

%% Build negotiation request
build_nego_request() ->
    Magic = 16#DEADBEEF,
    Version = 16#0B200200,
    ServiceCount = 4,
    ErrorFlags = 0,

    SupervisorData = build_supervisor_service(),
    AuthData = build_auth_service(),
    EncryptData = build_encryption_service([0, ?ALGO_DES56C, ?ALGO_AES128, ?ALGO_AES192, ?ALGO_AES256]),
    IntegrityData = build_integrity_service([0, 1, 3, 4, 5, 6]),

    AllServices = <<SupervisorData/binary, AuthData/binary, EncryptData/binary, IntegrityData/binary>>,
    TotalLength = 13 + byte_size(AllServices),

    <<
        Magic:32/big,
        TotalLength:16/big,
        Version:32/big,
        ServiceCount:16/big,
        ErrorFlags:8,
        AllServices/binary
    >>.

build_supervisor_service() ->
    ServiceType = ?SERVICE_SUPERVISOR,
    SubPacketCount = 3,
    ErrorCode = 0,
    Version = 16#0B200200,

    CID = <<0, 0, 16, 28, 102, 236, 40, 234>>,
    ServArray = [4, 1, 2, 3],
    ServArrayBin = << <<S:16/big>> || S <- ServArray >>,
    ServArrayLen = 10 + length(ServArray) * 2,

    ServiceData = <<
        4:16/big, 5:16/big, Version:32/big,
        8:16/big, 1:16/big, CID/binary,
        ServArrayLen:16/big, 1:16/big,
        16#DEADBEEF:32/big, 3:16/big, (length(ServArray)):32/big,
        ServArrayBin/binary
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

build_auth_service() ->
    ServiceType = ?SERVICE_AUTH,
    SubPacketCount = 3,
    ErrorCode = 0,
    Version = 16#0B200200,

    ServiceData = <<
        4:16/big, 5:16/big, Version:32/big,
        2:16/big, 3:16/big, 16#E0E1:16/big,
        2:16/big, 6:16/big, 16#FCFF:16/big
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

build_encryption_service(Algos) ->
    ServiceType = ?SERVICE_ENCRYPTION,
    SubPacketCount = 3,
    ErrorCode = 0,
    Version = 16#0B200200,

    AlgoList = << <<AlgoId:8>> || AlgoId <- Algos >>,
    AlgoListLen = byte_size(AlgoList),

    ServiceData = <<
        4:16/big, 5:16/big, Version:32/big,
        AlgoListLen:16/big, 1:16/big, AlgoList/binary,
        1:16/big, 2:16/big, 1:8
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

build_integrity_service(Algos) ->
    ServiceType = ?SERVICE_DATA_INTEGRITY,
    SubPacketCount = 2,
    ErrorCode = 0,
    Version = 16#0B200200,

    AlgoList = << <<AlgoId:8>> || AlgoId <- Algos >>,
    AlgoListLen = byte_size(AlgoList),

    ServiceData = <<
        4:16/big, 5:16/big, Version:32/big,
        AlgoListLen:16/big, 1:16/big, AlgoList/binary
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.
