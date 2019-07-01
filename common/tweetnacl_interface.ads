with Ada.Text_IO;  use Ada.Text_IO;
with Interfaces.C; use Interfaces.C;
with Interfaces.C.Extensions;
with TweetNaCl_Binding; use TweetNaCl_Binding;

--  This package provides a high-level interface to the six main services of
--  TweeNacl, to generate Keypairs, encrypt and decrypt, sign and authenticate.
--  We use types and contracts to ensure correct use of the interface.

--Size_Truc : constant := 32;
--faire aussi des test qui marchent pas (à la compile, à l'exe, à l'analyse et à la preuve) le tout en bien plus bavard.

package TweetNaCl_Interface
  with SPARK_Mode
is
   Crypto_Error : exception;
   --  Same exception used for all cryptographic errors

   procedure Crypto_Box
     (C  :    out CipherText;
      SM : in     PlainText;
      N  : in out Nonce;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => C'Length = SM'Length + BOX_BYTES
         and then  Is_Box_Public_Key (PK)
         and then IsBoxSecretKey(SK)
         and then IsSigned(Sm)
         and then NeverUsedYet(N) ;
   --  Encrypts and authenticates a signed message M using a nonce N and public
   --  and secret keys SK and PK and returns the corresponding cipher text X.


   procedure Crypto_Box_Open
     (SM :    out PlainText;
      C  : in     CipherText;
      N  : in     Nonce;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => C'Length=SM'Length+BOX_BYTES
         and then Is_Box_Public_Key(PK)
         and then IsBoxSecretKey(SK),
       Post => IsSigned(SM);
   --  Decrypt and Verify a  cipher text C using a nonce N and public and secret
   --  keys SK and PK, and returns the corresponding signed message SM.

   procedure Crypto_Box_Keypair (PK : out Key; SK : out Key)
     with
       Post => Is_Box_Public_Key(PK)
     and then IsBoxSecretKey(SK);
   --  generates a secret key SK and the corresponding public key PK to be used
   --  with Crypto_Box and Crypto_Box_Open.

   procedure Crypto_Sign
     (SM :    out PlainText;
      M  : in     PlainText;
      K  : in     Key64)
     with
       Pre => SM'Length = M'Length + SIGN_BYTES
          and then IsSignSecretKey(K),
       Post => IsSigned(SM);
   --  signs a message M using the signer's secret key SK and returns the
   --  resulting signed message SM.


   procedure Crypto_Sign_Open
     (M  :    out PlainText;
      SM : in     PlainText;
      PK : in     Key)
     with
       Pre =>M'Length=SM'Length-SIGN_BYTES
          and then IsSignPublicKey(PK)
          and then IsSigned(SM) ;
   --  verifies the signature in SM using the signer's public key PK and
   --  returns the initial message M.


   procedure Crypto_Sign_Keypair (PK : out Key; SK : out Key64)
     with
       Post => IsSignPublicKey(PK)
         and then IsSignSecretKey(SK);
   --  generates randomly a secret key SK and the corresponding public key PK
   --  to be used with Crypto_Sign and Crypto_Sign_Open.

   -- Building blocks of the 6 main programs

   procedure Randombytes (K: out Key) with
     Global => null;
   procedure Randombytes (N: out Nonce) with
     Post => NeverUsedYet(N),
     Global => null;

   procedure Crypto_Box_Beforenm
     (K  :    out Key;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => not Is_Box_Public_Key(PK)
         and then IsBoxSecretKey(SK),
       Post => IsBoxAfterKey(K);


   procedure Crypto_Box_Afternm
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then IsBoxAfterKey(K)
         and then IsSigned(M);

   procedure Crypto_Box_Open_Afternm
     (M :    out PlainText;
      C : in     CipherText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then IsBoxAfterKey(K),
       Post => IsSigned(M);

   procedure Crypto_Core_Salsa20
     (ArgOut :    out CoreOut;
      ArgIn  : in     CoreIn;
      K      : in     Key;
      Sigma  : in     Authenticator) ;

   procedure Crypto_Core_Hsalsa20
     (ArgOut :   out CoreOut;
      ArgIn  :in     CoreIn;
      K      :in     Key;
      Sigma  :in     Authenticator) ;

   procedure Crypto_Hashblocks
     (X : in out Key64;
      M : in     PlainText) ;

   procedure Crypto_Hash
     (ArgOut :    out Key64;
      M      : in     PlainText) ;

   procedure Crypto_Onetimeauth
     (ArgOut :    out Authenticator;
      M      : in     PlainText;
      K      : in     Key)
     with Pre => IsSigned(M);

   function Crypto_Onetimeauth_Verify
     (H : in Authenticator;
      M : in PlainText;
      K : in Key) return Int
     with Pre => IsSigned(M);

   procedure Crypto_Scalarmult
     (Q :    out Key;
      N : in     Key;
      P : in     Key) ;

   procedure Crypto_Scalarmult_Base (Q : out Key; N : in Key) ;

   procedure Crypto_Secretbox
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then IsBoxAfterKey(K)
         and then IsSigned(M);

   procedure Crypto_Secretbox_Open
     (M :    out PlainText;
      C : in     CipherText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then IsBoxAfterKey(K),
       Post => IsSigned(M);

   procedure Crypto_Stream_Xsalsa20
     (C :    out CipherText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => IsBoxAfterKey(K);

   procedure Crypto_Stream_Xsalsa20_Xor
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length
         and then IsBoxAfterKey(K)
         and then IsSigned(M);


   procedure Crypto_Stream_Salsa20
     (C :    out CipherText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => IsBoxAfterKey(K);


   procedure Crypto_Stream_Salsa20_Xor
     (C :    out CipherText;
      M : in     PlainText;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length
         and then IsBoxAfterKey(K)
         and then IsSigned(M);

   function Crypto_Verify_16 (X :in Authenticator; Y :in Authenticator) return Int;

   function Crypto_Verify_32 (X :in Key; Y :in Key) return Int;

   --  Properties defined as ghost functions

   function Is_Box_Public_Key (K : Key) return Boolean with Ghost;

   function IsBoxAfterKey  (K :Key)       return Boolean with Ghost;
   function IsBoxSecretKey (K :Key)       return Boolean with Ghost;
   function IsSignPublicKey(K :Key)       return Boolean with Ghost;
   function IsSignSecretKey(K :Key64)     return Boolean with Ghost;
   function IsSigned       (M :Plaintext) return Boolean with Ghost;
   function NeverUsedYet   (N :Nonce)     return Boolean with Ghost;

private
   pragma SPARK_Mode (Off);

   --  Properties are intentionally hidden from SPARK analysis under SPARK_Mode
   --  Off. This ensures that proof considers them as black boxes.

   function Is_Box_Public_Key (K : Key)      return Boolean is (True);
   function IsBoxAfterKey     (K :Key)       return Boolean is (True);
   function IsBoxSecretKey    (K :Key)       return Boolean is (True);
   function IsSignPublicKey   (K :Key)       return Boolean is (True);
   function IsSignSecretKey   (K :Key64)     return Boolean is (True);
   function IsSigned          (M :Plaintext) return Boolean is (True);
   function NeverUsedYet      (N :Nonce)     return Boolean is (True);


end TweetNaCl_Interface;
