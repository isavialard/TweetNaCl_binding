pragma SPARK_Mode;

with Ada.Text_IO;  use Ada.Text_IO;
with TweetNaCl_Binding; use TweetNaCl_Binding;
with TweetNaCl_Interface; use TweetNaCl_Interface;

-- Someone tampers with the cipher text
-- Test7 raises crypto_error at authentification

procedure Test5 is

   SK_Alice : Key;
   PK_Alice : Key;
   SK_Bob : Key;
   PK_Bob : Key;
   Sign_SK_Alice : Key64;
   Sign_PK_Alice : Key;
   N   : Nonce;
   M_Alice   : constant Plain_Text := (16#41#, 16#64#, 16#61#, 16#20#, 16#69#,
                                       16#73#, 16#20#, 16#74#, 16#68#, 16#65#,
                                       16#20#, 16#70#, 16#72#, 16#65#, 16#74#,
                                       16#74#, 16#69#, 16#65#, 16#73#, 16#74#,
                                       16#20#, 16#6f#, 16#66#, 16#20#, 16#61#,
                                       16#6c#, 16#6c#, 16#20#, 16#6c#, 16#61#,
                                       16#6e#, 16#67#, 16#75#, 16#61#, 16#67#,
                                       16#65#, 16#73#);
   SM_Alice  : Plain_Text (M_Alice'First .. M_Alice'Last + 64);
   C   : Cipher_Text (SM_Alice'First .. SM_Alice'Last + 32);
   SM_Bob : Plain_Text (C'First .. C'Last - 32);
   M_Bob  : Plain_Text (SM_Bob'First .. SM_Bob'Last - 64);

begin
   Put_Line (" Original message = ");
   for i in M_Alice'First .. M_Alice'Last loop
      Put (u8'Image (M_Alice (i)));
   end loop;
   Put_Line ("");
   -- Alice generate a keypair to sign her message
   -- Bob knows her signing public key and so does everyone

   Crypto_Sign_Keypair (Sign_PK_Alice, Sign_SK_Alice);

   -- Alice and Bob both generate keypairs for encryption and decryption
   -- They know each other public keys

   Crypto_Box_Keypair (PK_Alice, SK_Alice);
   Crypto_Box_Keypair (PK_Bob, SK_Bob);

   -- Alice signs her message using her signing secret key

   Crypto_Sign (SM_Alice, M_Alice, Sign_SK_Alice);
   Put (" Signed message = ");
   for i in SM_Alice'First .. SM_Alice'Last loop
      Put (u8'Image (SM_Alice (i)));
   end loop;
   Put_Line ("");

   -- Alice generates randomly a Nonce

   Randombytes (N);

   -- Alice computes a shared key with her secret key and Bob's public key
   -- Then she uses it to encrypt her signed message

   Crypto_Box (C, SM_Alice, N, PK_Bob, SK_Alice);
   Put (" Encrypted message sent to Bob = ");
   for i in C'First .. C'Last loop
      Put (u8'Image (C (i)));
   end loop;
   Put_Line ("");
   Put_Line (" Tampering with the cipher text ");
   C (17) := 0;

   -- Alice sends her encrypted and signed message to Bob with the Nonce
   -- Bob computes a shared key with his secret key and Alice's public key
   -- which is the same as the one Alice had used to encrypt
   -- Then he uses it to decrypt Alice's message

   Crypto_Box_Open (SM_Bob, C, N, PK_Alice, SK_Bob);
   Put (" Decrypted message = ");
   for i in SM_Bob'First .. SM_Bob'Last loop
      Put (u8'Image (SM_Bob (i)));
   end loop;
   Put_Line ("");

   -- Bob unsigns the message with Alice signing public key

   Crypto_Sign_Open (M_Bob, SM_Bob, Sign_PK_Alice);
   Put (" Final message = ");
   for i in M_Bob'First .. M_Bob'Last loop
      Put (u8'Image (M_Bob (i)));
   end loop;
   Put_Line ("");

end Test5;
