with Ada.Text_IO;  use Ada.Text_IO;
with Interfaces.C; use Interfaces.C;
with Interfaces.C.Extensions;
with TweetNaCl_Binding; use TweetNaCl_Binding;

--  This package provides a high-level interface to the six main services of
--  TweeNacl, to generate keypairs, encrypt and decrypt, sign and authenticate.
--  We use types and contracts to ensure correct use of the interface.

package TweetNaCl_Interface
  with SPARK_Mode
is
   Crypto_Error : exception;
   --  Same exception used for all cryptographic errors

   procedure Crypto_Box
     (C  :    out CipherText;
      SM : in     PlainText;
      N  : in     Nonce;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => C'Length = SM'Length + 32
         and then not Is_Box_Public_Key (PK)
         and then IsBoxSecretKey(Sk) = 0
         and then IsSigned(Sm) = 0
         and then NeverUsedYet(N) = 0;
   --  Encrypts and authenticates a signed message M using a nonce N and public
   --  and secret keys SK and PK and returns the corresponding cipher text X.


   procedure Crypto_Box_Open --Decrypt and verify a  cipher text c using a nonce n and public and secret keys sk and pk, and returns the corresponding signed message sm.

     (Sm : out PlainText;
      C : in CipherText;
      N : in Nonce;
      Pk : in Key;
      Sk : in Key)
     with
       Pre => C'Length=Sm'Length+32 and not Is_Box_Public_Key(Pk) and IsBoxSecretKey(Sk)=0,
     Post => IsSigned(Sm)=0;

   procedure Crypto_Box_Keypair (Pk : out Key; Sk : out Key) -- generates a secret key sk and the corresponding public key pk to be used with crypto_box and crypto_box_open.
     with
       Post => not Is_Box_Public_Key(Pk) and IsBoxSecretKey(Sk)=0;

   procedure Crypto_Sign --signs a message m using the signer's secret key sk and returns the resulting signed message sm.
     (Sm : out PlainText;
      M : in PlainText;
      K : in Key64)
     with
       Pre => Sm'Length = M'Length + 64 and IsSignSecretKey(K)=0,
     Post => IsSigned(Sm)=0;


   procedure Crypto_Sign_Open -- verifies the signature in sm using the signer's public key pk and returns the initial message m.  verification.
     (M : out PlainText;
      Sm : in PlainText;
      Pk : in Key)
     with
       Pre =>M'Length=Sm'Length-64 and IsSignPublicKey(Pk)=0 and IsSigned(Sm)=0 ;

   procedure Crypto_Sign_Keypair (Pk : out Key; Sk : out Key64) --generates randomly a secret key sk and the corresponding public key pk to be used with crypto_sign and crypto_sign_open.
     with
       Post => IsSignPublicKey(Pk)=0 and IsSignSecretKey(Sk)=0;


   -- Building blocks of the 6 main programs

   procedure Randombytes (X: out Key) with
     Global => null;
   procedure Randombytes (X: out Nonce) with
     Post => NeverUsedYet(X)=0,
     Global => null;

   procedure Crypto_Box_Beforenm
     (K : out Key;
      Pk : in Key;
      Sk : in Key)
     with
       Pre => not Is_Box_Public_Key(Pk) and IsBoxSecretKey(Sk)=0,
     Post => IsBoxAfterKey(K)=0;


   procedure Crypto_Box_Afternm
     (C : out CipherText;
      M : in PlainText;
      N : in Nonce;
      K : in Key)
     with
       Pre => C'Length=M'Length+32 and IsBoxAfterKey(K)=0 and IsSigned(M)=0;

   procedure Crypto_Box_Open_Afternm
     (M : out PlainText;
      C : in CipherText;
      N : in Nonce;
      K : in Key)
     with
       Pre => C'Length=M'Length+32 and IsBoxAfterKey(K)=0,
     Post => IsSigned(M)=0;

   procedure Crypto_Core_Salsa20
     (ArgOut : out CoreOut;
      ArgIn : in CoreIn;
      K : in Key;
      Sigma : in Authenticator) ;

   procedure Crypto_Core_Hsalsa20
     (ArgOut : out CoreOut;
      ArgIn :in CoreIn;
      K :in Key;
      Sigma :in Authenticator) ;

   procedure Crypto_Hashblocks
     (X : in out Key64;
      M : in PlainText) ;

   procedure Crypto_Hash
     (ArgOut : out Key64;
      M : in PlainText) ;

   procedure Crypto_Onetimeauth
     (ArgOut : out Authenticator;
      M : in  PlainText;
      K : in Key)
     with Pre => IsSigned(M)=0;

   function Crypto_Onetimeauth_Verify
     (H : in Authenticator;
      M : in PlainText;
      K : in Key) return Int
     with Pre => IsSigned(M)=0;

   procedure Crypto_Scalarmult
     (Q : out Key;
      N : in Key;
      P : in Key) ;

   procedure Crypto_Scalarmult_Base (Q : out Key; N : in Key) ;

   procedure Crypto_Secretbox
     (C : out CipherText;
      M : in PlainText;
      N : in Nonce;
      K : in Key)
     with
       Pre => C'Length=M'Length+32 and IsBoxAfterKey(K)=0 and IsSigned(M)=0;

   procedure Crypto_Secretbox_Open
     (M : out PlainText;
      C : in CipherText;
      N : in Nonce;
      K : in Key)
     with
       Pre => C'Length=M'Length+32 and IsBoxAfterKey(K)=0,
     Post => IsSigned(M)=0;

   procedure Crypto_Stream_Xsalsa20
     (C : out CipherText;
      N : in Nonce;
      K : in Key)
     with
       Pre => IsBoxAfterKey(K)=0;

   procedure Crypto_Stream_Xsalsa20_Xor
     (C : out CipherText;
      M : in  PlainText;
      N : in Nonce;
      K : in Key)
     with
       Pre => C'Length=M'Length and IsBoxAfterKey(K)=0 and IsSigned(M)=0;


   procedure Crypto_Stream_Salsa20
     (C : out CipherText;
      N : in Nonce;
      K : in Key)
     with
       Pre => IsBoxAfterKey(K)=0;


   procedure Crypto_Stream_Salsa20_Xor
     (C : out CipherText;
      M : in PlainText;
      N : in Nonce;
      K : in Key)
     with
       Pre => C'Length=M'Length and IsBoxAfterKey(K)=0 and IsSigned(M)=0;

   function Crypto_Verify_16 (X :in Authenticator; Y :in Authenticator) return Int;

   function Crypto_Verify_32 (X :in Key; Y :in Key) return Int;

   --  Properties defined as ghost functions

   function Is_Box_Public_Key (K : Key) return Boolean with Ghost;

   function IsBoxAfterKey(K :Key) return Int;
   function IsBoxSecretKey(K :Key) return Int;
   function IsSignPublicKey(K :Key) return Int;
   function IsSignSecretKey(K :Key64) return Int;
   function IsSigned(M :Plaintext) return Int;
   function NeverUsedYet(N :Nonce) return Int;

private
   pragma SPARK_Mode (Off);

   --  Properties are intentionally hidden from SPARK analysis under SPARK_Mode
   --  Off. This ensures that proof considers them as black boxes.

   function Is_Box_Public_Key (K : Key) return Boolean is (True);


end TweetNaCl_Interface;
