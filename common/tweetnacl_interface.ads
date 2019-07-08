with Ada.Text_IO;             use Ada.Text_IO;
with Interfaces.C;            use Interfaces.C;
with Interfaces.C.Extensions;
with TweetNaCl_Binding;       use TweetNaCl_Binding;

--  This package provides a high-level interface to the six main services of
--  TweeNacl, to generate Keypairs, encrypt and decrypt, sign and authenticate.
--  We use types and contracts to ensure correct use of the interface.


package TweetNaCl_Interface
  with SPARK_Mode
is
   Crypto_Error : exception;
   --  Same exception used for all cryptographic errors

   procedure Crypto_Box
     (C  :    out Cipher_Text;
      SM : in     Plain_Text;
      N  : in out Nonce;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => C'Length = SM'Length + BOX_BYTES
         and then  Is_Box_Public_Key (PK)
         and then Is_Box_Secret_Key(SK)
         and then Is_Signed(Sm)
         and then Never_Used_Yet(N) ;
   --  Encrypts and authenticates a signed message M using a nonce N and public
   --  and secret keys SK and PK and returns the corresponding cipher text X.


   procedure Crypto_Box_Open
     (SM :    out Plain_Text;
      C  : in     Cipher_Text;
      N  : in     Nonce;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => C'Length=SM'Length+BOX_BYTES
         and then Is_Box_Public_Key(PK)
         and then Is_Box_Secret_Key(SK),
       Post => Is_Signed(SM);
   --  Decrypt and Verify a  cipher text C using a nonce N and public and secret
   --  keys SK and PK, and returns the corresponding signed message SM.

   procedure Crypto_Box_Keypair (PK : out Key; SK : out Key)
     with
       Post => Is_Box_Public_Key(PK)
     and then Is_Box_Secret_Key(SK);
   --  generates a secret key SK and the corresponding public key PK to be used
   --  with Crypto_Box and Crypto_Box_Open.

   procedure Crypto_Sign
     (SM :    out Plain_Text;
      M  : in     Plain_Text;
      K  : in     Key64)
     with
       Pre => SM'Length = M'Length + SIGN_BYTES
          and then Is_Sign_Secret_Key(K),
       Post => Is_Signed(SM);
   --  signs a message M using the signer's secret key SK and returns the
   --  resulting signed message SM.


   procedure Crypto_Sign_Open
     (M  :    out Plain_Text;
      SM : in     Plain_Text;
      PK : in     Key)
     with
       Pre =>M'Length=SM'Length-SIGN_BYTES
          and then Is_Sign_Public_Key(PK)
          and then Is_Signed(SM) ;
   --  verifies the signature in SM using the signer's public key PK and
   --  returns the initial message M.


   procedure Crypto_Sign_Keypair (PK : out Key; SK : out Key64)
     with
       Post => Is_Sign_Public_Key(PK)
         and then Is_Sign_Secret_Key(SK);
   --  generates randomly a secret key SK and the corresponding public key PK
   --  to be used with Crypto_Sign and Crypto_Sign_Open.

   -- Building blocks of the 6 main programs

   procedure Randombytes (K: out Key) with
     Global => null;
   procedure Randombytes (N: out Nonce) with
     Post => Never_Used_Yet(N),
     Global => null;

   procedure Crypto_Box_Beforenm
     (K  :    out Key;
      PK : in     Key;
      SK : in     Key)
     with
       Pre => not Is_Box_Public_Key(PK)
         and then Is_Box_Secret_Key(SK),
       Post => Is_Box_After_Key(K);


   procedure Crypto_Box_Afternm
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then Is_Box_After_Key(K)
         and then Is_Signed(M)
         and then Never_Used_Yet(N) ;

   procedure Crypto_Box_Open_Afternm
     (M :    out Plain_Text;
      C : in     Cipher_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then Is_Box_After_Key(K),
       Post => Is_Signed(M);

   procedure Crypto_Core_Salsa20
     (ArgOut :    out Core_Out;
      ArgIn  : in     Core_In;
      K      : in     Key;
      Sigma  : in     Authenticator) ;

   procedure Crypto_Core_Hsalsa20
     (ArgOut :   out Core_Out;
      ArgIn  :in     Core_In;
      K      :in     Key;
      Sigma  :in     Authenticator) ;

   procedure Crypto_Hashblocks
     (X : in out Key64;
      M : in     Plain_Text) ;

   procedure Crypto_Hash
     (ArgOut :    out Key64;
      M      : in     Plain_Text) ;

   procedure Crypto_Onetimeauth
     (ArgOut :    out Authenticator;
      M      : in     Plain_Text;
      K      : in     Key)
     with Pre => Is_Signed(M);

   function Crypto_Onetimeauth_Verify
     (H : in Authenticator;
      M : in Plain_Text;
      K : in Key) return Int
     with Pre => Is_Signed(M);

   procedure Crypto_Scalarmult
     (Q :    out Key;
      N : in     Key;
      P : in     Key) ;

   procedure Crypto_Scalarmult_Base (Q : out Key; N : in Key) ;

   procedure Crypto_Secretbox
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then Is_Box_After_Key(K)
         and then Is_Signed(M);

   procedure Crypto_Secretbox_Open
     (M :    out Plain_Text;
      C : in     Cipher_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length+BOX_BYTES
         and then Is_Box_After_Key(K),
       Post => Is_Signed(M);

   procedure Crypto_Stream_Xsalsa20
     (C :    out Cipher_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => Is_Box_After_Key(K);

   procedure Crypto_Stream_Xsalsa20_Xor
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length
         and then Is_Box_After_Key(K)
         and then Is_Signed(M);


   procedure Crypto_Stream_Salsa20
     (C :    out Cipher_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => Is_Box_After_Key(K);


   procedure Crypto_Stream_Salsa20_Xor
     (C :    out Cipher_Text;
      M : in     Plain_Text;
      N : in     Nonce;
      K : in     Key)
     with
       Pre => C'Length=M'Length
         and then Is_Box_After_Key(K)
         and then Is_Signed(M);

   function Crypto_Verify_16 (X :in Authenticator; Y :in Authenticator) return Int;

   function Crypto_Verify_32 (X :in Key; Y :in Key) return Int;

   --  Properties defined as ghost functions

   function Is_Box_Public_Key (K : Key)      return Boolean with Ghost;
   function Is_Box_After_Key  (K :Key)       return Boolean with Ghost;
   function Is_Box_Secret_Key (K :Key)       return Boolean with Ghost;
   function Is_Sign_Public_Key(K :Key)       return Boolean with Ghost;
   function Is_Sign_Secret_Key(K :Key64)     return Boolean with Ghost;
   function Is_Signed         (M :Plain_Text)return Boolean with Ghost;
   function Never_Used_Yet    (N :Nonce)     return Boolean with Ghost;

private
   pragma SPARK_Mode (Off);

   --  Properties are intentionally hidden from SPARK analysis under SPARK_Mode
   --  Off. This ensures that proof considers them as black boxes.

   function Is_Box_Public_Key    (K : Key)      return Boolean is (True);
   function Is_Box_After_Key     (K :Key)       return Boolean is (True);
   function Is_Box_Secret_Key    (K :Key)       return Boolean is (True);
   function Is_Sign_Public_Key   (K :Key)       return Boolean is (True);
   function Is_Sign_Secret_Key   (K :Key64)     return Boolean is (True);
   function Is_Signed            (M :Plain_Text)return Boolean is (True);
   function Never_Used_Yet       (N :Nonce)     return Boolean is (True);


end TweetNaCl_Interface;
