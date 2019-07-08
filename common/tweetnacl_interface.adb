
package body TweetNaCl_Interface is

   procedure Crypto_Box
     (C  :    out Cipher_Text;
      SM : in     Plain_Text;
      N  : in out Nonce;
      PK : in     Key;
      SK : in     Key)
   is
      SMU : Plain_Text (SM'First .. SM'Last+32) := (1 .. 32 => 0) & SM;
   begin
      if Crypto_Box_curve25519Xsalsa20poly1305_tweet(C, SMU, SMU'Length, N, PK, SK)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Box;


   procedure Crypto_Box_Open
     (SM :    out Plain_Text;
      C  : in     Cipher_Text;
      N  : in     Nonce;
      PK : in     Key;
      SK : in     Key)

   is
      MU : Plain_Text(SM 'First..SM 'Last+32);
   begin
      if Crypto_Box_curve25519Xsalsa20poly1305_tweet_Open(MU, C, C'Length, N, PK, SK)/=0 then
         raise Crypto_Error;
      end if;
      for i in SM 'First..SM 'Last loop
         SM (i):=MU(i+32);
      end loop;
   end Crypto_Box_Open;


   procedure Crypto_Box_Keypair (PK : out Key; SK : out Key)   is
   begin
      if Crypto_Box_curve25519Xsalsa20poly1305_tweet_Keypair(PK, SK)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Box_Keypair;


   procedure Crypto_Sign
     (SM  :    out Plain_Text;
      M   : in     Plain_Text;
      K   : in     Key64)

   is
      smlen : U64;
   begin
      if Crypto_Sign_ed25519_tweet(SM , smlen, M, M'Length, k)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Sign;


   procedure Crypto_Sign_Open
     (M  :    out Plain_Text;
      SM : in     Plain_Text;
      PK : in     Key)

   is
      MU : Plain_Text(SM 'First..SM 'Last);
      mlen : U64;
   begin
      if Crypto_Sign_ed25519_tweet_Open(MU,mlen,SM ,SM 'Length,PK)/=0 then
         raise Crypto_Error;
      end if;
      M:=(MU(MU'First .. MU'First + mlen -1));
   end Crypto_Sign_Open;


   procedure Crypto_Sign_Keypair (PK : out Key; SK : out Key64)   is
   begin
      if Crypto_Sign_ed25519_tweet_Keypair(PK, SK)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Sign_Keypair;

   procedure Randombytes (K: out Key) is
   begin
      Randombytes(K,32);
   end Randombytes;

   procedure Randombytes (N: out Nonce) is
   begin
      Randombytes(N,24);
   end Randombytes;

   procedure Crypto_Box_Beforenm
     (K  :    out Key;
      PK : in     Key;
      SK : in     Key) is
   begin
      if Crypto_Box_curve25519Xsalsa20poly1305_tweet_beforenm(K,PK,SK)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Box_Beforenm;

   procedure Crypto_Box_Afternm
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)
   is
      SMU : Plain_Text(M'First..M'Last+32);
   begin
      SMU :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&M);
      if Crypto_Box_curve25519Xsalsa20poly1305_tweet_afternm(C, SMU, M'Length+32, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Box_Afternm;


   procedure Crypto_Box_Open_Afternm
     (M :    out Plain_Text;
      C : in     Cipher_Text;
      N : in     Nonce;
      K : in     Key)
   is
      MU : Plain_Text(M'First..M'Last+32);
   begin
      if Crypto_box_curve25519Xsalsa20poly1305_tweet_Open_afternm(MU, C, C'Length, N,K)/=0 then
        raise Crypto_Error;
      end if;
      for i in M'First..M'Last loop
         M(i):=MU(i+32);
      end loop;
   end Crypto_Box_Open_Afternm;


   procedure Crypto_Core_Salsa20
     (argOut :    out Core_Out;
      argIn  : in     Core_In;
      K      : in     Key;
      sigma  : in     Authenticator) is
   begin
      if Crypto_core_Salsa20_tweet(argOut, argIn, K, sigma)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Core_Salsa20;


   procedure Crypto_Core_Hsalsa20
     (ArgOut :    out Core_Out;
      argIn  :in     Core_In;
      K      :in     Key;
      sigma  :in     Authenticator)is
   begin
      if Crypto_core_Hsalsa20_tweet(argOut, argIn, K, sigma)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Core_Hsalsa20;


   procedure Crypto_Hashblocks
     (X : in out Key64;
      M : in     Plain_Text) is
   begin
      if Crypto_hashblocks_sha512_tweet(X, M, M'Length)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Hashblocks;


   procedure Crypto_Hash
     (argOut :    out Key64;
      M      : in     Plain_Text) is
   begin
      if Crypto_hash_sha512_tweet(argOut, m, m'Length)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Hash;


   procedure Crypto_Onetimeauth
     (argOut :    out Authenticator;
      M      : in     Plain_Text;
      K      : in     Key) is
   begin
      if Crypto_onetimeauth_poly1305_tweet(argOut, M, M'Length, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Onetimeauth;


   function Crypto_Onetimeauth_Verify
     (H : in     Authenticator;
      M : in     Plain_Text;
      K : in     Key) return int is
   begin
      return Crypto_onetimeauth_poly1305_tweet_verify(H, M, M'Length, K);
     end Crypto_Onetimeauth_Verify;


   procedure Crypto_Scalarmult
     (Q :    out Key;
      N : in     Key;
      P : in     Key) is
   begin
      if Crypto_scalarmult_curve25519_tweet(Q, N, P)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Scalarmult;


   procedure Crypto_Scalarmult_Base (Q : out Key; N : in Key) is
   begin
      if Crypto_scalarmult_curve25519_tweet_base(Q, N)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Scalarmult_Base;


   procedure Crypto_Secretbox
     (C:     out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)
   is
      SMU : Plain_Text(M'First..M'Last+32);
   begin
      SMU :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&M);
      if Crypto_secretbox_Xsalsa20poly1305_tweet(C, SMU, M'Length+32, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Secretbox;


   procedure Crypto_Secretbox_Open
     (M :    out Plain_Text;
      C : in     Cipher_Text;
      N : in     Nonce;
      K : in     Key)
    is
      MU : Plain_Text(m'First..m'Last+32);
   begin
      if Crypto_secretbox_Xsalsa20poly1305_tweet_open(MU, C, C'Length, N,K)/=0 then
         raise Crypto_Error;
      end if;
      for i in M'First..M'Last loop
         M(i):=MU(i+32);
      end loop;
   end Crypto_Secretbox_Open;


   procedure Crypto_Stream_Xsalsa20
     (C :    out Cipher_Text;
      N : in     Nonce;
      K : in     Key)
   is
      clen : u64 := c'Length;
   begin
      if Crypto_stream_Xsalsa20_tweet(C, clen, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Stream_Xsalsa20;


   procedure Crypto_Stream_Xsalsa20_Xor
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key) is
   begin
      if Crypto_stream_Xsalsa20_tweet_Xor(C, M, M'Length, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Stream_Xsalsa20_Xor;


   procedure Crypto_Stream_Salsa20
     (C :    out Cipher_Text;
      N : in     Nonce;
      K : in     Key)
   is
      clen : u64 := C'Length;
   begin
      if Crypto_stream_salsa20_tweet(C, clen, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Stream_Salsa20;


   procedure Crypto_Stream_Salsa20_Xor
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)  is
   begin
      if Crypto_stream_salsa20_tweet_Xor(C, M, M'Length, N, K)/=0 then
         raise Crypto_Error;
      end if;
   end Crypto_Stream_Salsa20_Xor;


   function Crypto_Verify_16(X :in Authenticator; Y :in Authenticator) return int is
   begin
      return Crypto_verify_16_tweet(X, Y);
     end Crypto_Verify_16;


   function Crypto_Verify_32 (x :in Key; y :in Key) return int is
   begin
      return Crypto_verify_32_tweet(x, y);
   end Crypto_Verify_32;



end TweetNaCl_Interface;
