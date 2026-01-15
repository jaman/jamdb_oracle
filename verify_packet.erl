#!/usr/bin/env escript
%% Verify our advanced negotiation packet structure

main(_) ->
    Hex = <<222,173,190,239,0,147,11,32,2,0,0,4,0,0,4,0,3,0,0,0,0,0,4,0,5,11,32,2,0,0,8,0,1,0,0,16,28,102,236,40,234,0,18,0,1,222,173,190,239,0,3,0,0,0,4,0,4,0,1,0,2,0,3,0>>,
    
    io:format("Parsing first 64 bytes of advanced negotiation packet:~n~n"),
    
    %% Main header (13 bytes)
    <<Magic:32/big, Length:16/big, Version:32/big, ServiceCount:16/big, ErrorFlags:8, Rest1/binary>> = Hex,
    io:format("Main Header (13 bytes):~n"),
    io:format("  DEADBEEF: 0x~8.16.0B (~p)~n", [Magic, Magic =:= 16#DEADBEEF]),
    io:format("  Length: ~p~n", [Length]),
    io:format("  Version: 0x~8.16.0B~n", [Version]),
    io:format("  Service Count: ~p~n", [ServiceCount]),
    io:format("  Error Flags: ~p~n~n", [ErrorFlags]),
    
    %% Supervisor service header (8 bytes)
    <<ServType1:16/big, SubPkt1:16/big, ErrorCode1:32/big, Rest2/binary>> = Rest1,
    io:format("Supervisor Service Header (8 bytes):~n"),
    io:format("  Service Type: ~p (SUPERVISOR=4)~n", [ServType1]),
    io:format("  Sub-packets: ~p~n", [SubPkt1]),
    io:format("  Error Code: ~p~n~n", [ErrorCode1]),
    
    %% Version sub-packet (8 bytes)
    <<PktLen1:16/big, PktType1:16/big, Ver1:32/big, Rest3/binary>> = Rest2,
    io:format("Supervisor Version Sub-packet (8 bytes):~n"),
    io:format("  Packet Length: ~p~n", [PktLen1]),
    io:format("  Packet Type: ~p (VERSION=5)~n", [PktType1]),
    io:format("  Version: 0x~8.16.0B~n~n", [Ver1]),
    
    %% CID sub-packet (12 bytes)
    <<PktLen2:16/big, PktType2:16/big, CID:8/binary, Rest4/binary>> = Rest3,
    io:format("Supervisor CID Sub-packet (12 bytes):~n"),
    io:format("  Packet Length: ~p~n", [PktLen2]),
    io:format("  Packet Type: ~p (BYTES=1)~n", [PktType2]),
    io:format("  CID: ~w~n~n", [CID]),
    
    %% ServArray sub-packet header
    <<PktLen3:16/big, PktType3:16/big, Rest5/binary>> = Rest4,
    io:format("Supervisor ServArray Sub-packet:~n"),
    io:format("  Packet Length: ~p~n", [PktLen3]),
    io:format("  Packet Type: ~p (BYTES=1)~n", [PktType3]),
    
    <<ArrayMagic:32/big, ArrayMagic2:16/big, ArrayCount:32/big, Rest6/binary>> = Rest5,
    io:format("  DEADBEEF: 0x~8.16.0B (~p)~n", [ArrayMagic, ArrayMagic =:= 16#DEADBEEF]),
    io:format("  Magic2: ~p~n", [ArrayMagic2]),
    io:format("  Array Count: ~p~n", [ArrayCount]),
    
    case Rest6 of
        <<S1:16/big, S2:16/big, S3:16/big, S4:16/big, _/binary>> ->
            io:format("  Services: [~p, ~p, ~p, ~p]~n~n", [S1, S2, S3, S4]);
        _ ->
            io:format("  Services: (not enough bytes)~n~n")
    end.
