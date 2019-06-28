pacKage body TweetNaCl_Interface is

   procedure Crypto_Box
     (C  :    out CipherText;
      SM : in     PlainText;
      N  : in     Nonce;
      PK : in     Key;
      SK : in     Key)
   is
      SMU : PlainText (SM'First .. SM'Last+32) := (1 .. 32 => 0) & SM;
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet(C, SMU, SMU'Length, N, PK, SK)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_box;


   procedure crypto_box_open
     (SM :    out PlainText;
      C  : in     CipherText;
      N  : in     Nonce;
      PK : in     Key;
      SK : in     Key)

   is
      MU : PlainText(SM 'First..SM 'Last+32);
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_open(MU, C, C'Length, N, PK, SK)/=0 then
         raise Crypto_Error;
      end if;
      for i in SM 'First..SM 'Last loop
         SM (i):=MU(i+32);
      end loop;
   end crypto_box_open;


   procedure crypto_box_keypair (PK : out Key; SK : out Key)   is
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_keypair(PK, SK)/=0 then
         Praise Crypto_Error;
      end if;
   end crypto_box_keypair;


   procedure crypto_sign
     (SM  :    out PlainText;
      M   : in     PlainText;
      K   : in     Key64)

   is
      smlen : U64;
   begin
      if crypto_sign_ed25519_tweet(SM , smlen, M, M'Length, k)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_sign;


   procedure crypto_sign_open
     (M  :    out PlainText;
      SM : in     PlainText;
      PK : in     Key)

   is
      MU : PlainText(SM 'First..SM 'Last);
      mlen : U64;
   begin
      if crypto_sign_ed25519_tweet_open(MU,mlen,SM ,SM 'Length,PK)/=0 then
         raise Crypto_Error;
      end if;
      M:=(MU(MU'First .. MU'First + mlen -1));
   end crypto_sign_open;


   procedure crypto_sign_keypair (PK : out Key; SK : out Key64)   is
   begin
      if crypto_sign_ed25519_tweet_keypair(PK, SK)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_sign_keypair;

   procedure randombytes (K: out Key) is
   begin
      randombytes(K,32);
   end randombytes;

   procedure randombytes (N: out Nonce) is
   begin
      randombytes(K,24);
   end randombytes;

   procedure crypto_box_beforenm
     (K  :    out Key;
      PK : in     Key;
      SK : in     Key) is
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(K,PK,SK)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_box_beforenm;

   procedure crypto_box_afternm
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)
   is
      SMU : PlainText(M'First..M'Last+32);
   begin
      SMU :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&M);
      if crypto_box_curve25519xsalsa20poly1305_tweet_afternm(C SMU, M'Length+32, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_box_afternm;


   procedure crypto_box_open_afternm
     (M :    out PlainText;
      C : in     CipherText;
      N : in     Nonce;
      K : in     Key)
   is
      MU : PlainText(M'First..M'Last+32);
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(MU, C C'Length, N,K)/=0 then
        raise Crypto_Error;
      end if;
      for i in M'First..M'Last loop
         M(i):=MU(i+32);
      end loop;
   end crypto_box_open_afternm;


   procedure crypto_core_salsa20
     (argOut :    out CoreOut;
      argIn  : in     CoreIn;
      K      : in     Key;
      sigma  : in     Authenticator) is
   begin
      if crypto_core_salsa20_tweet(argOut, argIn, K, sigma)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_core_salsa20;


   procedure crypto_core_hsalsa20
     (ArgOut :    out CoreOut;
      argIn  :in     CoreIn;
      K      :in     Key;
      sigma  :in     Authenticator)is
   begin
      if crypto_core_hsalsa20_tweet(argOut, argIn, K, sigma)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_core_hsalsa20;


   procedure crypto_hashblocks
     (X : in out Key64;
      M : in     PlainText) is
   begin
      if crypto_hashblocks_sha512_tweet(X, M, M'Length)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_hashblocks;


   procedure crypto_hash
     (argOut :    out Key64;
      M      : in     PlainText) is
   begin
      if crypto_hash_sha512_tweet(argOut, m, m'Length)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_hash;


   procedure crypto_onetimeauth
     (argOut :    out Authenticator;
      M      : in     PlainText;
      K      : in     Key) is
   begin
      if crypto_onetimeauth_poly1305_tweet(argOut, M, M'Length, K)/=0 then
         Praise Crypto_Error;
      end if;
   end crypto_onetimeauth;


   function crypto_onetimeauth_verify
     (H : in     Authenticator;
      M : in     PlainText;
      K : in     Key) return int is
   begin
      return crypto_onetimeauth_poly1305_tweet_verify(H, M, M'Length, K);
     end crypto_onetimeauth_verify;


   procedure crypto_scalarmult
     (Q :    out Key;
      N : in     Key;
      P : in     Key) is
   begin
      if crypto_scalarmult_curve25519_tweet(Q, N, P)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_scalarmult;


   procedure crypto_scalarmult_base (Q : out Key; N : in Key) is
   begin
      if crypto_scalarmult_curve25519_tweet_base(Q, N)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_scalarmult_base;


   procedure crypto_secretbox
     (C:     out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)
   is
      SMU : PlainText(M'First..M'Last+32);
   begin
      SMU :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&M);
      if crypto_secretbox_xsalsa20poly1305_tweet(C, SMU, M'Length+32, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_secretbox;


   procedure crypto_secretbox_open
     (M :    out PlainText;
      C : in     CipherText;
      N : in     Nonce;
      K : in     Key)
    is
      MU : PlainText(m'First..m'Last+32);
   begin
      if crypto_secretbox_xsalsa20poly1305_tweet_open(MU, C, C'Length, N,K)/=0 then
         raise Crypto_Error;
      end if;
      for i in M'First..M'Last loop
         M(i):=MU(i+32);
      end loop;
   end crypto_secretbox_open;


   procedure crypto_stream_xsalsa20
     (C :    out CipherText;
      N : in     Nonce;
      K : in     Key)
   is
      clen : u64 := c'Length;
   begin
      if crypto_stream_xsalsa20_tweet(C, clen, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_stream_xsalsa20;


   procedure crypto_stream_xsalsa20_xor
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key) is
   begin
      if crypto_stream_xsalsa20_tweet_xor(C, M, M'Length, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_stream_xsalsa20_xor;


   procedure crypto_stream_salsa20
     (C :    out CipherText;
      N : in     Nonce;
      K : in     Key)
   is
      clen : u64 := C'Length;
   begin
      if crypto_stream_salsa20_tweet(C, clen, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_stream_salsa20;


   procedure crypto_stream_salsa20_xor
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)  is
   begin
      if crypto_stream_salsa20_tweet_xor(C, M, M'Length, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end crypto_stream_salsa20_xor;


   function crypto_verify_16(X :in Authenticator; Y :in Authenticator) return int is
   begin
      return crypto_verify_16_tweet(X, Y);
     end crypto_verify_16;


   function crypto_verify_32 (x :in Key; y :in Key) return int is
   begin
      return crypto_verify_32_tweet(x, y);
   end crypto_verify_32;


   function isSigned       (M :PlainText) return int is begin return 0; end isSigned;
   function isBoxAfterKey  (K :Key)       return int is begin return 0; end isBoxAfterKey;
   function isBoxSecretKey (K :Key)       return int is begin return 0; end isBoxSecretKey;
   function isSignPublicKey(K :Key)       return int is begin return 0; end isSignPublicKey;
   function isSignSecretKey(K :Key64)     return int is begin return 0; end isSignSecretKey;
   function neverUsedYet   (N :Nonce)     return int is begin return 0; end neverUsedYet;

end TweetNaCl_Interface;
