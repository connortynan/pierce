/* Generated from the cacophony Noise test vectors (public domain):
   https://github.com/haskell-cryptography/cacophony/blob/master/vectors/cacophony.txt
   Only the two suites Pierce uses. Hex strings; messages alternate
   initiator, responder, ... starting at the first handshake message. */
#ifndef PIERCE_VECTORS_NOISE_H
#define PIERCE_VECTORS_NOISE_H

typedef struct { const char *payload, *ciphertext; } nv_msg;
typedef struct {
    const char *name;
    int pattern; /* 1 = IK, 2 = XX */
    const char *prologue, *init_static, *init_ephemeral, *init_remote_static;
    const char *resp_static, *resp_ephemeral, *handshake_hash;
    int msg_count;
    nv_msg msgs[8];
} noise_vector;

static const noise_vector noise_vectors[] = {
    {
        "Noise_IK_25519_ChaChaPoly_BLAKE2b", 1,
        "4a6f686e2047616c74",
        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        "1c8fa891cb414fedba6daa7c6f4ae0a6d98e5f9768cc9cecd27e805614943ee9c8a1b27fbfb76dc197255c8aa69f6b4285c423840b8bedf45e652ca64f797d81",
        6,
        {
            {"4c756477696720766f6e204d69736573",
             "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944ba83a447b38c83e327ad936929812f624884847b7831e95e197b2f797088efdd2f88f1db7e1fb0e99c64419097af91cee64e470f4b6fcd9298ce0b56fe20f86e13bf70439c538e3602a7127af71a29cc"},
            {"4d757272617920526f746862617264",
             "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088439f069b267a06b3de3ecb1043bcb098e9af91d9c64748d998c7b47890871571"},
            {"462e20412e20486179656b",
             "cd54383060e7a28434cca27fb1cc524cfbabeb18181589df219d07"},
            {"4361726c204d656e676572",
             "a856d3bf0246bfc476c655009cd1ed677b8dcc5b349ae8ef2a05f2"},
            {"4a65616e2d426170746973746520536179",
             "49063084b2c51f098337cb8a13739ac848f907e67cfb2cc8a8b60586467aa02fc7"},
            {"457567656e2042f6686d20766f6e2042617765726b",
             "8b9709d23b47e4639df7678d7a21741eba4ef1e9c60383001c7435549c20f9d56f30e935d3"},
        },
    },
    {
        "Noise_XX_25519_ChaChaPoly_BLAKE2b", 2,
        "4a6f686e2047616c74",
        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        NULL,
        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        "8cf47d7b3cb5804c0109d48e8bcdbee2cbb65687d8ea2c92994ca361fb86151ad93627b98936cbb32de56e8abb21def3925011ac3e35db9cbeea73ab9a4392c2",
        6,
        {
            {"4c756477696720766f6e204d69736573",
             "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"},
            {"4d757272617920526f746862617264",
             "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088430505b6745ce64a5f33f0e8e3b83f11ce8802bca507f4f2d8b564dbe277e1966116e132faa2dfd70b8b077b9f94b913df5056ae1319469b824a98d54bbaa82c325595587064f978c4b6d104f7596e6f"},
            {"462e20412e20486179656b",
             "99579e1c1ee15e422a57ddd6b16d37087b17558e8369c18991b4b2ca3a824abf904cdcf5458b5431a75af034ca9e9b982de039eaaf156775e2d580cd4e5ebae89c3f8cb2594b556d8a8169"},
            {"4361726c204d656e676572",
             "fc56eea290b3f3a21aac0c70cd5787b5ee99be37d2f4d751329b55"},
            {"4a65616e2d426170746973746520536179",
             "bb31c9da10d5639a4cdb88a12f5c61de41bbc7df09bf75d94f8184fe4157f5c68f"},
            {"457567656e2042f6686d20766f6e2042617765726b",
             "f6199cadb152fb27f82be0a0891ec76a33598ae92a46cab2fb5a8ed5bf48b7f267f8370af7"},
        },
    },
};

#endif
