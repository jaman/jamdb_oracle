-module(jamdb_oracle_network_hash).

%% Oracle Native Network Data Integrity Hash Algorithms
%% Based on go-ora implementation

-export([new/3, compute/2]).

-include("jamdb_oracle_network_hash.hrl").

%% Create new Oracle hash state for MD5 or SHA1 (OracleNetworkHash)
new(md5, Key, IV) ->
    new_oracle_hash(md5, 16, Key, IV);
new(sha, Key, IV) ->
    new_oracle_hash(sha, 20, Key, IV);

%% Create new Oracle hash state for SHA256/384/512 (OracleNetworkHash2)
new(sha256, Key, IV) ->
    new_oracle_hash2(sha256, 32, Key, IV);
new(sha384, Key, IV) ->
    new_oracle_hash2(sha384, 48, Key, IV);
new(sha512, Key, IV) ->
    new_oracle_hash2(sha512, 64, Key, IV).

%% Oracle's OracleNetworkHash for MD5/SHA1 (uses RC4)
new_oracle_hash(Algorithm, HashSize, Key, IV) ->
    %% Take last 5 bytes of key, append 0xFF, append IV
    KeyLen = byte_size(Key),
    Key1Start = KeyLen - 5,
    <<_:Key1Start/binary, Key1Tail:5/binary>> = Key,
    Key1 = <<Key1Tail/binary, 16#FF, IV/binary>>,

    %% Initialize RC4 cipher for key generation
    KeyGenState = crypto:crypto_init(rc4, Key1, <<>>, true),

    %% Generate 5 bytes of keystream
    KeyStream = crypto:crypto_update(KeyGenState, <<0:40>>),

    %% Create encryptor with keystream + 90
    EncKey = <<KeyStream/binary, 90>>,
    EncState = crypto:crypto_init(rc4, EncKey, <<>>, true),

    %% Create decryptor with keystream + 180
    DecKey = <<KeyStream/binary, 180>>,
    DecState = crypto:crypto_init(rc4, DecKey, <<>>, true),

    #oracle_hash_state{
        algorithm = Algorithm,
        hash_size = HashSize,
        key_gen = KeyGenState,
        encryptor = EncState,
        decryptor = DecState
    }.

%% Oracle's OracleNetworkHash2 for SHA256/384/512 (uses AES-CBC)
new_oracle_hash2(Algorithm, HashSize, Key, IV) ->
    %% Take first 5 bytes of key, append 0xFF, pad to 16 bytes, append IV[:16]
    <<Key1Head:5/binary, _/binary>> = Key,
    AesKey = <<Key1Head/binary, 16#FF, 0:(10*8)>>,
    IVPart = binary:part(IV, 0, min(16, byte_size(IV))),

    %% Create initial buffer (32 bytes of zeros)
    Buffer = <<0:(32*8)>>,

    %% Initialize AES-CBC for key generation
    KeyGenCipher = crypto:crypto_init(aes_128_cbc, AesKey, IVPart, true),
    NewBuffer = crypto:crypto_update(KeyGenCipher, Buffer),

    %% Extract key and IV from buffer
    <<EncKey0:16/binary, NewIV:16/binary>> = NewBuffer,

    %% Create encryptor (key[5] = 90)
    <<EncKey1:5/binary, _:8, EncKey1Rest/binary>> = EncKey0,
    EncKey = <<EncKey1/binary, 90, EncKey1Rest/binary>>,
    EncCipher = crypto:crypto_init(aes_128_cbc, EncKey, NewIV, true),

    %% Create decryptor (key[5] = 180)
    <<DecKey1:5/binary, _:8, DecKey1Rest/binary>> = EncKey0,
    DecKey = <<DecKey1/binary, 180, DecKey1Rest/binary>>,
    DecCipher = crypto:crypto_init(aes_128_cbc, DecKey, NewIV, true),

    %% Generate initial output
    Output = crypto:crypto_update(EncCipher, <<0:(HashSize*8)>>),

    #oracle_hash_state{
        algorithm = Algorithm,
        hash_size = HashSize,
        key_gen = Output,  %% Store output buffer
        encryptor = EncCipher,
        decryptor = DecCipher
    }.

%% Compute Oracle hash on input data
compute(Input, #oracle_hash_state{algorithm = Algorithm, hash_size = HashSize, encryptor = EncState} = State)
        when Algorithm =:= md5; Algorithm =:= sha ->
    %% OracleNetworkHash: XOR keystream with zeros, then hash(input + keystream)
    KeyStream = crypto:crypto_update(EncState, <<0:(HashSize*8)>>),
    DataWithKeyStream = <<Input/binary, KeyStream/binary>>,
    Hash = crypto:hash(Algorithm, DataWithKeyStream),
    {Hash, State};

compute(Input, #oracle_hash_state{algorithm = Algorithm, hash_size = _HashSize, key_gen = Output, encryptor = EncState} = State) ->
    %% OracleNetworkHash2: Generate new output, then hash(input + output)
    NewOutput = crypto:crypto_update(EncState, Output),
    DataWithOutput = <<Input/binary, NewOutput/binary>>,
    Hash = crypto:hash(Algorithm, DataWithOutput),
    {Hash, State#oracle_hash_state{key_gen = NewOutput}}.
