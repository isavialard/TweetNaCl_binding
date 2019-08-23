pragma Style_Checks (Off);
-- No style checks for low-level binding based on generated code

with Interfaces.C; use Interfaces.C;

package TweetNaCl_Binding is

   pragma Assertion_Policy (Pre => Check, Post => Check);
   
   type u8 is mod 2 ** 8;
   type u64 is range -2 ** 63 .. +2 ** 63 - 1;
   
   KEY_BYTES             : constant := 32;
   SIGN_SECRET_KEY_BYTES : constant := 64;
   NONCE_BYTES           : constant := 24;
   CORE_IN_BYTES         : constant := 16;
   CORE_OUT_BYTES        : constant := 64;
   AUTHENTICATOR_BYTES   : constant := 16;
   TEXT_MAX_SIZE         : constant := 1000;
   SIGN_BYTES            : constant := 64;
   BOX_BYTES             : constant := 32;
   
   
  
   subtype Index is u64 range 1 .. TEXT_MAX_SIZE;

   type Authenticator is array(1 .. AUTHENTICATOR_BYTES) of u8;
   type Nonce is limited private;
   type Key is array(1 .. KEY_BYTES) of u8;
   type Key64 is array(1 .. SIGN_SECRET_KEY_BYTES) of u8;
   
   type Core_In is array(1 .. CORE_IN_BYTES) of u8;
   type Core_Out is array(1 .. CORE_OUT_BYTES) of u8;

   type Cipher_Text is array(Index range<>) of u8;
   type Plain_Text is array(Index range<>) of u8;


   procedure randombytes (x: out Key; xlen : in U64) with
     Pre => x'Length=xlen,
     Global => null;  -- ./tweetnacl.h:4
   procedure randombytes (x: out Nonce; xlen : in U64) with
     Pre => xlen=NONCE_BYTES,
     Global => null;  -- ./tweetnacl.h:4
   pragma Import (C, randombytes, "randombytes");


   function Crypto_Box_curve25519xsalsa20poly1305_tweet
     (c  :    out Cipher_Text;
      m  : in     Plain_Text;
      d  : in     U64;
      n  : in     Nonce;
      pk : in     Key;
      sk : in     Key) return int
   with
       Pre => d >= BOX_BYTES 
         and then c'Length=d 
         and then m'Length=d 
         and then (for all I in m'First .. m'First+BOX_BYTES-1 => m (I) = 0);  -- ./tweetnacl.h:44
   pragma Import (C, Crypto_Box_curve25519xsalsa20poly1305_tweet, "crypto_box_curve25519xsalsa20poly1305_tweet");

   function Crypto_Box_curve25519xsalsa20poly1305_tweet_open
     (m  :    out Plain_Text;
      c  : in     Cipher_Text;
      d  : in     U64;
      n  : in     Nonce;
      pk : in     Key;
      sk : in     Key) return int
   with
       Pre => d >= BOX_BYTES 
         and then c'Length=d 
         and then m'Length=d;  -- ./tweetnacl.h:45
   pragma Import (C, Crypto_Box_curve25519xsalsa20poly1305_tweet_open, "crypto_box_curve25519xsalsa20poly1305_tweet_open");

   function Crypto_Box_curve25519xsalsa20poly1305_tweet_keypair (pk : out Key; sk : out Key) return int;  -- ./tweetnacl.h:46
   pragma Import (C, Crypto_Box_curve25519xsalsa20poly1305_tweet_keypair, "crypto_box_curve25519xsalsa20poly1305_tweet_keypair");

   function Crypto_Box_curve25519xsalsa20poly1305_tweet_beforenm
     (k  :    out Key;
      pk : in     Key;
      sk : in     Key) return int;  -- ./tweetnacl.h:47
   pragma Import (C, Crypto_Box_curve25519xsalsa20poly1305_tweet_beforenm, "crypto_box_curve25519xsalsa20poly1305_tweet_beforenm");

   function Crypto_Box_curve25519xsalsa20poly1305_tweet_afternm
     (c :    out Cipher_Text;
      m : in     Plain_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
       Pre => d >= BOX_BYTES
         and then m'Length=d 
         and then c'Length=d 
         and then (for all I in m'First .. m'First+BOX_BYTES-1 => m (I) = 0);  -- ./tweetnacl.h:48
   pragma Import (C, Crypto_Box_curve25519xsalsa20poly1305_tweet_afternm, "crypto_box_curve25519xsalsa20poly1305_tweet_afternm");

   function Crypto_Box_curve25519xsalsa20poly1305_tweet_open_afternm
     (m :    out Plain_Text;
      c : in     Cipher_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
       Pre => d>=BOX_BYTES
         and then c'Length=d 
         and then m'Length=d ;  -- ./tweetnacl.h:49
   pragma Import (C, Crypto_Box_curve25519xsalsa20poly1305_tweet_open_afternm, "crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm");

   function crypto_core_salsa20_tweet
     (argOut :    out Core_Out;
      argIn  : in     Core_In;
      k      : in     Key;
      sigma  : in     Authenticator) return int;  -- ./tweetnacl.h:77
   pragma Import (C, crypto_core_salsa20_tweet, "crypto_core_salsa20_tweet");

   function crypto_core_hsalsa20_tweet
     (ArgOut :    out Core_Out;
      argIn  : in     Core_In;
      k      : in     Key;
      sigma  : in     Authenticator) return int;  -- ./tweetnacl.h:90
   pragma Import (C, crypto_core_hsalsa20_tweet, "crypto_core_hsalsa20_tweet");

   function crypto_hashblocks_sha512_tweet
     (x :    out Key64;
      m : in     Plain_Text;
      n : in     U64) return int
   with
    Pre => m'Length=n;  -- ./tweetnacl.h:107
   pragma Import (C, crypto_hashblocks_sha512_tweet, "crypto_hashblocks_sha512_tweet");

   function crypto_hash_sha512_tweet
     (argOut :    out Key64;
      m      : in     Plain_Text;
      n      : in     U64) return int
   with
    Pre => m'Length=n;  -- ./tweetnacl.h:129
   pragma Import (C, crypto_hash_sha512_tweet, "crypto_hash_sha512_tweet");

   function crypto_onetimeauth_poly1305_tweet
     (argOut :    out Authenticator;
      m      : in     Plain_Text;
      n      : in     U64;
      k      : in     Key) return int
   with
    Pre => m'Length=n;  -- ./tweetnacl.h:151
   pragma Import (C, crypto_onetimeauth_poly1305_tweet, "crypto_onetimeauth_poly1305_tweet");

   function crypto_onetimeauth_poly1305_tweet_verify
     (h : in     Authenticator;
      m : in     Plain_Text;
      n : in     U64;
      k : in     Key) return int
   with
    Pre => m'Length=n;  -- ./tweetnacl.h:152
   pragma Import (C, crypto_onetimeauth_poly1305_tweet_verify, "crypto_onetimeauth_poly1305_tweet_verify");

   function crypto_scalarmult_curve25519_tweet
     (q :    out Key;
      n : in     Key;
      p : in     Key) return int;  -- ./tweetnacl.h:169
   pragma Import (C, crypto_scalarmult_curve25519_tweet, "crypto_scalarmult_curve25519_tweet");

   function crypto_scalarmult_curve25519_tweet_base (q : out Key; n : in Key) return int;  -- ./tweetnacl.h:170
   pragma Import (C, crypto_scalarmult_curve25519_tweet_base, "crypto_scalarmult_curve25519_tweet_base");

   function crypto_secretbox_xsalsa20poly1305_tweet
     (c :    out Cipher_Text;
      m : in     Plain_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
       Pre => d >= BOX_BYTES
         and then c'Length=d 
         and then m'Length=d;  -- ./tweetnacl.h:191
   pragma Import (C, crypto_secretbox_xsalsa20poly1305_tweet, "crypto_secretbox_xsalsa20poly1305_tweet");

   function crypto_secretbox_xsalsa20poly1305_tweet_open
     (m :    out Plain_Text;
      c : in     Cipher_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
       Pre => d >= BOX_BYTES
         and then c'Length=d 
         and then m'Length=d;  -- ./tweetnacl.h:192
   pragma Import (C, crypto_secretbox_xsalsa20poly1305_tweet_open, "crypto_secretbox_xsalsa20poly1305_tweet_open");

   function Crypto_Sign_ed25519_tweet
     (sm    :    out Plain_Text;
      smlen :    out U64;
      m     : in     Plain_Text;
      n     : in     U64;
      k     : in     Key64) return int
   with
       Pre => sm'Length=n + SIGN_BYTES
         and then m'Length=n,
       Post => Crypto_Sign_ed25519_tweet'Result=0 
         and then smlen=n + SIGN_BYTES;  -- ./tweetnacl.h:214
   pragma Import (C, Crypto_Sign_ed25519_tweet, "crypto_sign_ed25519_tweet");

   function Crypto_Sign_ed25519_tweet_open
     (m    :    out Plain_Text;
      mlen :    out U64;
      sm   : in     Plain_Text;
      n    : in     U64;
      pk   : in     Key) return int
     with
       Pre => n >= SIGN_BYTES
         and then m'Length=n 
         and then sm'Length=n,
       Post => Crypto_Sign_ed25519_tweet_open'Result=0 
         and then mlen=n - SIGN_BYTES;  -- ./tweetnacl.h:215
   pragma Import (C, Crypto_Sign_ed25519_tweet_open, "crypto_sign_ed25519_tweet_open");

   function Crypto_Sign_ed25519_tweet_keypair (pk : out Key; sk : out Key64) return int;  -- ./tweetnacl.h:216
   pragma Import (C, Crypto_Sign_ed25519_tweet_keypair, "crypto_sign_ed25519_tweet_keypair");

   function crypto_stream_xsalsa20_tweet
     (c :    out Cipher_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
    Pre => c'Length=d;  -- ./tweetnacl.h:235
   pragma Import (C, crypto_stream_xsalsa20_tweet, "crypto_stream_xsalsa20_tweet");

   function crypto_stream_xsalsa20_tweet_xor
     (c :    out Cipher_Text;
      m : in     Plain_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
       Pre => c'Length=d 
         and then c'Length=m'Length;  -- ./tweetnacl.h:236
   pragma Import (C, crypto_stream_xsalsa20_tweet_xor, "crypto_stream_xsalsa20_tweet_xor");

   function crypto_stream_salsa20_tweet
     (c :    out Cipher_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
   with
    Pre => c'Length=d;  -- ./tweetnacl.h:246
   pragma Import (C, crypto_stream_salsa20_tweet, "crypto_stream_salsa20_tweet");

   function crypto_stream_salsa20_tweet_xor
     (c :    out Cipher_Text;
      m : in     Plain_Text;
      d : in     U64;
      n : in     Nonce;
      k : in     Key) return int
    with
       Pre => c'Length=d 
           and then c'Length=m'Length;  -- ./tweetnacl.h:247
   pragma Import (C, crypto_stream_salsa20_tweet_xor, "crypto_stream_salsa20_tweet_xor");

   function crypto_verify_16_tweet (x :in Authenticator; y :in Authenticator) return int;  -- ./tweetnacl.h:261
   pragma Import (C, crypto_verify_16_tweet, "crypto_verify_16_tweet");

   function crypto_verify_32_tweet (x :in Key; y :in Key) return int;  -- ./tweetnacl.h:268
   pragma Import (C, crypto_verify_32_tweet, "crypto_verify_32_tweet");

private
   type Nonce is array(1 .. NONCE_BYTES) of u8;

end TweetNaCl_Binding;
