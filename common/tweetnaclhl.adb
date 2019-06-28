package body tweetnaclhl is


   procedure crypto_box
     (c : out CipherText;
      sm : in PlainText;
      n : in Nonce;
      pk : in Key;
      sk : in Key)

   is

      smu : PlainText(sm'First..sm'Last+32);

   begin
      smu :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&sm);
      if crypto_box_curve25519xsalsa20poly1305_tweet(c, smu, smu'Length, n, pk, sk)/=0 then
         Put_Line("error crypto_box");
      end if;
   end crypto_box;


   procedure crypto_box_open
     (sm : out PlainText;
      c : in CipherText;
      n : in Nonce;
      pk : in Key;
      sk : in Key)

   is
      mu : PlainText(sm'First..sm'Last+32);
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_open(mu, c, c'Length, n, pk, sk)/=0 then
         Put_Line("error crypto_box_open");
      end if;
      for i in sm'First..sm'Last loop
         sm(i):=mu(i+32);
      end loop;
   end crypto_box_open;


   procedure crypto_box_keypair (pk : out Key; sk : out Key)   is
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_keypair(pk, sk)/=0 then
         Put_Line("error crypto_box_keypair");
      end if;
   end crypto_box_keypair;


   procedure crypto_sign
     (sm : out PlainText;
      m : in PlainText;
      k : in Key64)

   is
      smlen : U64;
   begin
      if crypto_sign_ed25519_tweet(sm, smlen, m, m'Length, k)/=0 then
         Put_Line("error crypto_sign");
      end if;
   end crypto_sign;


   procedure crypto_sign_open
     (m : out PlainText;
      sm : in PlainText;
      pk : in Key)

   is
      mu : PlainText(sm'First..sm'Last);
      mlen : U64;
   begin
      if crypto_sign_ed25519_tweet_open(mu,mlen,sm,sm'Length,pk)/=0 then
         Put_Line("error crypto_sign_open");
      end if;
      m:=(mu(mu'First .. mu'First + mlen -1));
   end crypto_sign_open;


   procedure crypto_sign_keypair (pk : out Key; sk : out Key64)   is
   begin
      if crypto_sign_ed25519_tweet_keypair(pk, sk)/=0 then
         Put_Line("error crypto_sign_keypair");
      end if;
   end crypto_sign_keypair;


   procedure randombytes (x: out Key) is
   begin
      randombytes(x,32);
   end randombytes;
   procedure randombytes (x: out Nonce) is
   begin
      randombytes(x,24);
   end randombytes;

   procedure crypto_box_beforenm
     (k : out Key;
      pk : in Key;
      sk : in Key) is
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k,pk,sk)/=0 then
         Put_Line("error crypto_box_beforenm");
      end if;
   end crypto_box_beforenm;

   procedure crypto_box_afternm
     (c : out CipherText;
      m : in PlainText;
      n : in Nonce;
      k : in Key)
   is
      smu : PlainText(m'First..m'Last+32);
   begin
      smu :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&m);
      if crypto_box_curve25519xsalsa20poly1305_tweet_afternm(c, smu, m'Length+32, n, k)/=0 then
         Put_Line("error crypto_box_afternm");
      end if;
   end crypto_box_afternm;


   procedure crypto_box_open_afternm
     (m : out PlainText;
      c : in CipherText;
      n : in Nonce;
      k : in Key)
   is
      mu : PlainText(m'First..m'Last+32);
   begin
      if crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(mu, c, c'Length, n,k)/=0 then
         Put_Line("error crypto_box_open_afternm");
      end if;
      for i in m'First..m'Last loop
         m(i):=mu(i+32);
      end loop;
   end crypto_box_open_afternm;


   procedure crypto_core_salsa20
     (argOut : out CoreOut;
      argIn : in CoreIn;
      k : in Key;
      sigma : in Authenticator) is
   begin
      if crypto_core_salsa20_tweet(argOut, argIn, k, sigma)/=0 then
         Put_Line("error crypto_core_salsa20");
      end if;
   end crypto_core_salsa20;


   procedure crypto_core_hsalsa20
     (ArgOut : out CoreOut;
      argIn :in CoreIn;
      k :in Key;
      sigma :in Authenticator)is
   begin
      if crypto_core_hsalsa20_tweet(argOut, argIn, k, sigma)/=0 then
         Put_Line("error crypto_core_hsalsa20");
      end if;
   end crypto_core_hsalsa20;


   procedure crypto_hashblocks
     (x : in out Key64;
      m : in PlainText) is
   begin
      if crypto_hashblocks_sha512_tweet(x, m, m'Length)/=0 then
         Put_Line("error crypto_hashblocks");
      end if;
   end crypto_hashblocks;


   procedure crypto_hash
     (argOut : out Key64;
      m : in PlainText) is
   begin
      if crypto_hash_sha512_tweet(argOut, m, m'Length)/=0 then
         Put_Line("error crypto_hash");
      end if;
   end crypto_hash;


   procedure crypto_onetimeauth
     (argOut : out Authenticator;
      m : in  PlainText;
      k : in Key) is
   begin
      if crypto_onetimeauth_poly1305_tweet(argOut, m, m'Length, k)/=0 then
         Put_Line("error crypto_onetimeauth");
      end if;
   end crypto_onetimeauth;


   function crypto_onetimeauth_verify
     (h : in Authenticator;
      m : in PlainText;
      k : in Key) return int is
   begin
      return crypto_onetimeauth_poly1305_tweet_verify(h, m, m'Length, k);
     end crypto_onetimeauth_verify;


   procedure crypto_scalarmult
     (q : out Key;
      n : in Key;
      p : in Key) is
   begin
      if crypto_scalarmult_curve25519_tweet(q, n, p)/=0 then
         Put_Line("error crypto_scalarmult");
      end if;
   end crypto_scalarmult;


   procedure crypto_scalarmult_base (q : out Key; n : in Key) is
   begin
      if crypto_scalarmult_curve25519_tweet_base(q, n)/=0 then
         Put_Line("error crypto_scalarmult_base");
      end if;
   end crypto_scalarmult_base;


   procedure crypto_secretbox
     (c : out CipherText;
      m : in PlainText;
      n : in Nonce;
      k : in Key)
   is
      smu : PlainText(m'First..m'Last+32);
   begin
      smu :=((0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)&m);
      if crypto_secretbox_xsalsa20poly1305_tweet(c, smu, m'Length+32, n, k)/=0 then
         Put_Line("error crypto_secretbox");
      end if;
   end crypto_secretbox;


   procedure crypto_secretbox_open
     (m : out PlainText;
      c : in CipherText;
      n : in Nonce;
      k : in Key)
    is
      mu : PlainText(m'First..m'Last+32);
   begin
      if crypto_secretbox_xsalsa20poly1305_tweet_open(mu, c, c'Length, n,k)/=0 then
         Put_Line("error crypto_secretbox_open");
      end if;
      for i in m'First..m'Last loop
         m(i):=mu(i+32);
      end loop;
   end crypto_secretbox_open;


   procedure crypto_stream_xsalsa20
     (c : out CipherText;
      n : in Nonce;
      k : in Key)
   is
      clen : u64 := c'Length;
   begin
      if crypto_stream_xsalsa20_tweet(c, clen, n, k)/=0 then
         Put_Line("error crypto_stream_xsalsa20");
      end if;
   end crypto_stream_xsalsa20;


   procedure crypto_stream_xsalsa20_xor
     (c : out CipherText;
      m : in  PlainText;
      n : in Nonce;
      k : in Key) is
   begin
      if crypto_stream_xsalsa20_tweet_xor(c, m, m'Length, n, k)/=0 then
         Put_Line("error crypto_stream_xsalsa20_xor");
      end if;
   end crypto_stream_xsalsa20_xor;


   procedure crypto_stream_salsa20
     (c : out CipherText;
      n : in Nonce;
      k : in Key)
   is
      clen : u64 := c'Length;
   begin
      if crypto_stream_salsa20_tweet(c, clen, n, k)/=0 then
         Put_Line("error crypto_stream_salsa20");
      end if;
   end crypto_stream_salsa20;


   procedure crypto_stream_salsa20_xor
     (c : out CipherText;
      m : in PlainText;
      n : in Nonce;
      k : in Key)  is
   begin
      if crypto_stream_salsa20_tweet_xor(c, m, m'Length, n, k)/=0 then
         Put_Line("error crypto_stream_salsa20_xor");
      end if;
   end crypto_stream_salsa20_xor;


   function crypto_verify_16(x :in Authenticator; y :in Authenticator) return int is
   begin
      return crypto_verify_16_tweet(x, y);
     end crypto_verify_16;


   function crypto_verify_32 (x :in Key; y :in Key) return int is
   begin
      return crypto_verify_32_tweet(x, y);
   end crypto_verify_32;


   function isSigned(m :PlainText) return int is begin return 0; end isSigned;
   function isBoxPublicKey(k :Key) return int is begin return 0; end isBoxPublicKey;
   function isBoxAfterKey(k :Key) return int is begin return 0; end isBoxAfterKey;
   function isBoxSecretKey(k :Key) return int is begin return 0; end isBoxSecretKey;
   function isSignPublicKey(k :Key) return int is begin return 0; end isSignPublicKey;
   function isSignSecretKey(k :Key64) return int is begin return 0; end isSignSecretKey;
   function neverUsedYet(n :Nonce) return int is begin return 0; end neverUsedYet;

end tweetnaclhl;
