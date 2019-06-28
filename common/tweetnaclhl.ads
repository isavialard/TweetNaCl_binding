pragma SPARK_Mode;
pragma Style_Checks (Off);
with Ada.Text_IO;  use Ada.Text_IO;
with Interfaces.C; use Interfaces.C;
with Interfaces.C.Extensions;
with tweetnacl_h; use tweetnacl_h;


package tweetnaclhl is

   pragma Assertion_Policy (Pre => Check, Post => Check);

   -- 6 main procedures to generate keypairs, encrypt and decrypt, sign and authenticate.

   procedure crypto_box --Encrypts and authenticates a signed message m using a nonce n and public and secret keys sk and pk and returns the corresponding cipher text x.
     (c : out CipherText;
      sm : in PlainText;
      n : in Nonce;
      pk : in Key;
      sk : in Key)
   with
    Pre => c'Length=sm'Length+32 and isBoxPublicKey(pk)=0 and isBoxSecretKey(sk)=0 and isSigned(sm)=0 and neverUsedYet(n)=0;

   procedure crypto_box_open --Decrypt and verify a  cipher text c using a nonce n and public and secret keys sk and pk, and returns the corresponding signed message sm.

     (sm : out PlainText;
      c : in CipherText;
      n : in Nonce;
      pk : in Key;
      sk : in Key)
   with
       Pre => c'Length=sm'Length+32 and isBoxPublicKey(pk)=0 and isBoxSecretKey(sk)=0,
       Post => isSigned(sm)=0;

   procedure crypto_box_keypair (pk : out Key; sk : out Key) -- generates a secret key sk and the corresponding public key pk to be used with crypto_box and crypto_box_open.
   with
      Post => isBoxPublicKey(pk)=0 and isBoxSecretKey(sk)=0;

   procedure crypto_sign --signs a message m using the signer's secret key sk and returns the resulting signed message sm.
     (sm : out PlainText;
      m : in PlainText;
      k : in Key64)
   with
       Pre => sm'Length = m'Length + 64 and isSignSecretKey(k)=0,
       Post => isSigned(sm)=0;


   procedure crypto_sign_open -- verifies the signature in sm using the signer's public key pk and returns the initial message m.  verification.
     (m : out PlainText;
      sm : in PlainText;
      pk : in Key)
     with
       Pre =>m'Length=sm'Length-64 and isSignPublicKey(pk)=0 and isSigned(sm)=0 ;

   procedure crypto_sign_keypair (pk : out Key; sk : out Key64) --generates randomly a secret key sk and the corresponding public key pk to be used with crypto_sign and crypto_sign_open.
   with
      Post => isSignPublicKey(pk)=0 and isSignSecretKey(sk)=0;


   -- Building blocks of the 6 main programs

   procedure randombytes (x: out Key) with
     Global => null;
   procedure randombytes (x: out Nonce) with
     Post => neverUsedYet(x)=0,
     Global => null;

   procedure crypto_box_beforenm
     (k : out Key;
      pk : in Key;
      sk : in Key)
   with
      Pre => isBoxPublicKey(pk)=0 and isBoxSecretKey(sk)=0,
      Post => isBoxAfterKey(k)=0;


   procedure crypto_box_afternm
     (c : out CipherText;
      m : in PlainText;
      n : in Nonce;
      k : in Key)
   with
    Pre => c'Length=m'Length+32 and isBoxAfterKey(k)=0 and isSigned(m)=0;

   procedure crypto_box_open_afternm
     (m : out PlainText;
      c : in CipherText;
      n : in Nonce;
      k : in Key)
   with
       Pre => c'Length=m'Length+32 and isBoxAfterKey(k)=0,
       Post => isSigned(m)=0;

   procedure crypto_core_salsa20
     (argOut : out CoreOut;
      argIn : in CoreIn;
      k : in Key;
      sigma : in Authenticator) ;

   procedure crypto_core_hsalsa20
     (ArgOut : out CoreOut;
      argIn :in CoreIn;
      k :in Key;
      sigma :in Authenticator) ;

   procedure crypto_hashblocks
     (x : in out Key64;
      m : in PlainText) ;

   procedure crypto_hash
     (argOut : out Key64;
      m : in PlainText) ;

   procedure crypto_onetimeauth
     (argOut : out Authenticator;
      m : in  PlainText;
      k : in Key)
   with Pre => isSigned(m)=0;

   function crypto_onetimeauth_verify
     (h : in Authenticator;
      m : in PlainText;
      k : in Key) return int
    with Pre => isSigned(m)=0;

   procedure crypto_scalarmult
     (q : out Key;
      n : in Key;
      p : in Key) ;

   procedure crypto_scalarmult_base (q : out Key; n : in Key) ;

   procedure crypto_secretbox
     (c : out CipherText;
      m : in PlainText;
      n : in Nonce;
      k : in Key)
   with
       Pre => c'Length=m'Length+32 and isBoxAfterKey(k)=0 and isSigned(m)=0;

   procedure crypto_secretbox_open
     (m : out PlainText;
      c : in CipherText;
      n : in Nonce;
      k : in Key)
   with
       Pre => c'Length=m'Length+32 and isBoxAfterKey(k)=0,
       Post => isSigned(m)=0;

   procedure crypto_stream_xsalsa20
     (c : out CipherText;
      n : in Nonce;
      k : in Key)
   with
      Pre => isBoxAfterKey(k)=0;

   procedure crypto_stream_xsalsa20_xor
     (c : out CipherText;
      m : in  PlainText;
      n : in Nonce;
      k : in Key)
   with
    Pre => c'Length=m'Length and isBoxAfterKey(k)=0 and isSigned(m)=0;


   procedure crypto_stream_salsa20
     (c : out CipherText;
      n : in Nonce;
      k : in Key)
   with
      Pre => isBoxAfterKey(k)=0;


   procedure crypto_stream_salsa20_xor
     (c : out CipherText;
      m : in PlainText;
      n : in Nonce;
      k : in Key)
    with
    Pre => c'Length=m'Length and isBoxAfterKey(k)=0 and isSigned(m)=0;

   function crypto_verify_16 (x :in Authenticator; y :in Authenticator) return int;

   function crypto_verify_32 (x :in Key; y :in Key) return int;

   -- Ghost functions used for Pre- and Post-conditions

   function isBoxPublicKey(k :Key) return int;
   function isBoxAfterKey(k :Key) return int;
   function isBoxSecretKey(k :Key) return int;
   function isSignPublicKey(k :Key) return int;
   function isSignSecretKey(k :Key64) return int;
   function isSigned(m :Plaintext) return int;
   function neverUsedYet(n :Nonce) return int;



end tweetnaclhl;
