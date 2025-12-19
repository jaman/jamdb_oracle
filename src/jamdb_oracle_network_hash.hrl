-ifndef(ORACLE_HASH_HRL).
-define(ORACLE_HASH_HRL, true).

-record(oracle_hash_state, {
    algorithm :: md5 | sha | sha256 | sha384 | sha512,
    hash_size :: integer(),
    key_gen :: binary(),
    encryptor :: binary(),
    decryptor :: binary()
}).

-endif.
