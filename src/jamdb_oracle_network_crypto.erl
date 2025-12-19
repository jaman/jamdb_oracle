-module(jamdb_oracle_network_crypto).

%% Oracle Native Network Encryption support
%% Based on go-ora implementation

-export([new_aes_cbc/2, new_3des_cbc/2, new_des_cbc/2, new_rc4/3]).
-export([encrypt/2, decrypt/2, reset/1]).

-record(crypto_state, {
    algorithm :: atom(),
    key :: binary(),
    iv :: binary(),
    encrypt_iv :: binary(),
    decrypt_iv :: binary()
}).

%% API

%% Create AES-CBC encryptor
new_aes_cbc(Key, IV) when byte_size(Key) =:= 16; byte_size(Key) =:= 24; byte_size(Key) =:= 32 ->
    IVec = case IV of
        undefined -> <<0:128>>;
        _ -> IV
    end,
    {ok, #crypto_state{
        algorithm = aes_cbc,
        key = Key,
        iv = IVec,
        encrypt_iv = IVec,
        decrypt_iv = IVec
    }}.

%% Create 3DES-CBC encryptor
new_3des_cbc(Key, IV) when byte_size(Key) =:= 24 ->
    IVec = case IV of
        undefined -> <<0:64>>;
        _ -> IV
    end,
    {ok, #crypto_state{
        algorithm = des_ede3_cbc,
        key = Key,
        iv = IVec,
        encrypt_iv = IVec,
        decrypt_iv = IVec
    }}.

%% Create DES-CBC encryptor
new_des_cbc(Key, IV) when byte_size(Key) =:= 8 ->
    IVec = case IV of
        undefined -> <<1,35,69,103,137,171,205,239>>;  % Default Oracle IV
        _ -> IV
    end,
    {ok, #crypto_state{
        algorithm = des_cbc,
        key = Key,
        iv = IVec,
        encrypt_iv = IVec,
        decrypt_iv = IVec
    }}.

%% Create RC4 encryptor (matches go-ora rc4_cryptor.go:16-51)
new_rc4(InitBuffer, IV, KeySize) ->
    Length = KeySize div 8,

    %% Take LAST Length bytes from InitBuffer, append 0x7B, append IV
    BufferSize = byte_size(InitBuffer),
    StartPos = BufferSize - Length,
    <<_:StartPos/binary, KeyTail:Length/binary>> = InitBuffer,
    InitKey = <<KeyTail/binary, 16#7B, IV/binary>>,

    %% Initialize key generator cipher
    KeyGenState = crypto:crypto_init(rc4, InitKey, <<>>, true),

    %% Generate key derivation buffer: 15 zeros + 21 spaces = 36 bytes
    KeyBuffer = <<0:(15*8), (list_to_binary(lists:duplicate(21, 16#20)))/binary>>,

    %% Encrypt first Length bytes to derive actual keys
    DerivedKey = crypto:crypto_update(KeyGenState, binary:part(KeyBuffer, 0, Length)),

    %% Extract last byte for XOR operations
    <<KeyHead:(Length-1)/binary, LastByte:8>> = DerivedKey,

    %% Create decryption key (last byte XOR 0xAA)
    DecKey = <<KeyHead/binary, (LastByte bxor 16#AA)>>,
    DecState = crypto:crypto_init(rc4, DecKey, <<>>, true),

    %% Create encryption key (original last byte)
    EncKey = DerivedKey,
    EncState = crypto:crypto_init(rc4, EncKey, <<>>, true),

    {ok, #crypto_state{
        algorithm = rc4,
        key = InitBuffer,
        iv = IV,
        encrypt_iv = EncState,
        decrypt_iv = DecState
    }}.

%% Reset encryption state (for marker packets)
reset(#crypto_state{iv = IV} = State) ->
    {ok, State#crypto_state{encrypt_iv = IV, decrypt_iv = IV}}.

%% Encrypt data using RC4 with stateful cipher
encrypt(Data, #crypto_state{algorithm = rc4, encrypt_iv = EncState} = State) ->
    Encrypted = crypto:crypto_update(EncState, Data),
    {ok, Encrypted, State};

encrypt(Data, #crypto_state{algorithm = Algo, key = Key, encrypt_iv = IV} = State) ->
    BlockSize = get_block_size(Algo),

    %% Calculate padding needed
    PaddingLen = case byte_size(Data) rem BlockSize of
        0 -> 0;
        Rem -> BlockSize - Rem
    end,

    %% Add ZERO padding (Oracle uses zero bytes, not PKCS7!)
    Padding = <<0:(PaddingLen * 8)>>,
    PaddedData = <<Data/binary, Padding/binary>>,

    %% Encrypt using CBC mode
    Encrypted = crypto:crypto_one_time(Algo, Key, IV, PaddedData, true),

    %% Update IV for DES/3DES only (go-ora: DES updates IV, AES keeps it static)
    NewIV = case Algo of
        des_cbc -> binary:part(Encrypted, byte_size(Encrypted) - BlockSize, BlockSize);
        des_ede3_cbc -> binary:part(Encrypted, byte_size(Encrypted) - BlockSize, BlockSize);
        aes_cbc -> IV  %% AES keeps static IV (zero IV) - no IV chaining!
    end,

    %% Add (padding length + 1) byte at the end (Oracle protocol requirement)
    PaddingLenByte = PaddingLen + 1,
    Result = <<Encrypted/binary, PaddingLenByte>>,

    {ok, Result, State#crypto_state{encrypt_iv = NewIV}}.

%% Decrypt data using RC4 with stateful cipher
decrypt(Data, #crypto_state{algorithm = rc4, decrypt_iv = DecState} = State) ->
    Decrypted = crypto:crypto_update(DecState, Data),
    {ok, Decrypted, State};

decrypt(Data, #crypto_state{algorithm = Algo, key = Key, decrypt_iv = IV} = State) ->
    BlockSize = get_block_size(Algo),

    %% Extract padding length byte from end (it's paddingLen + 1)
    DataLen = byte_size(Data),
    ActualLen = DataLen - 1,
    <<ToDecrypt:ActualLen/binary, PaddingLenBytePlusOne:8>> = Data,

    %% Validate padding length byte (go-ora validates 0..BlockSize)
    case PaddingLenBytePlusOne of
        Num when Num >= 0, Num =< BlockSize ->
            %% Check that encrypted data is a multiple of block size
            case byte_size(ToDecrypt) rem BlockSize of
                0 ->
                    %% Decrypt using CBC mode
                    Decrypted = crypto:crypto_one_time(Algo, Key, IV, ToDecrypt, false),

                    %% Update IV for DES/3DES only (go-ora: DES updates IV, AES keeps it static)
                    NewIV = case Algo of
                        des_cbc -> binary:part(ToDecrypt, byte_size(ToDecrypt) - BlockSize, BlockSize);
                        des_ede3_cbc -> binary:part(ToDecrypt, byte_size(ToDecrypt) - BlockSize, BlockSize);
                        aes_cbc -> IV  %% AES keeps static IV (zero IV) - no IV chaining!
                    end,

                    %% Remove zero padding (paddingLen = paddingLenByte - 1)
                    PaddingLen = Num - 1,
                    PlainLen = byte_size(Decrypted) - PaddingLen,
                    <<PlainText:PlainLen/binary, _Padding/binary>> = Decrypted,

                    {ok, PlainText, State#crypto_state{decrypt_iv = NewIV}};
                _Rem ->
                    {error, invalid_ciphertext_length}
            end;
        _BadNum ->
            {error, invalid_padding_byte}
    end.

%% Internal functions

get_block_size(aes_cbc) -> 16;
get_block_size(des_ede3_cbc) -> 8;
get_block_size(des_cbc) -> 8.
