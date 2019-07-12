pragma SPARK_Mode;

with Ada.Text_IO;  use Ada.Text_IO;
with TweetNaCl_Binding; use TweetNaCl_Binding;
with TweetNaCl_Interface; use TweetNaCl_Interface;

procedure Test3 is

   SK_Alice : Key;
   PK_Alice : Key;
   SK_Bob : Key;
   PK_Bob : Key;
   N   : Nonce;
   M_Alice   : constant Plain_Text := (16#41#, 16#64#, 16#61#, 16#20#, 16#69#,
                                       16#73#, 16#20#, 16#74#, 16#68#, 16#65#,
                                       16#20#, 16#70#, 16#72#, 16#65#, 16#74#,
                                       16#74#, 16#69#, 16#65#, 16#73#, 16#74#,
                                       16#20#, 16#6f#, 16#66#, 16#20#, 16#61#,
                                       16#6c#, 16#6c#, 16#20#, 16#6c#, 16#61#,
                                       16#6e#, 16#67#, 16#75#, 16#61#, 16#67#,
                                       16#65#, 16#73#);
   C   : Cipher_Text (M_Alice'First .. M_Alice'Last + 32);
   M_Bob : Plain_Text (C'First .. C'Last - 32);

begin
   Put_Line (" Original message = ");
   for i in M_Alice'First .. M_Alice'Last loop
      Put (u8'Image (M_Alice (i)));
   end loop;
   Put_Line ("");

   -- Alice and Bob both generate keypairs for encryption and decryption
   -- They know each other public keys

   Crypto_Box_Keypair (PK_Alice, SK_Alice);
   Crypto_Box_Keypair (PK_Bob, SK_Bob);

   -- Alice generates randomly a Nonce

   Randombytes (N);

   -- Alice computes a shared key with her secret key and Bob's public key
   -- Then she uses it to encrypt her signed message

   Crypto_Box (C, M_Alice, N, PK_Bob, SK_Alice);
   Put (" Encrypted message sent to Bob = ");
   for i in C'First .. C'Last loop
      Put (u8'Image (C (i)));
   end loop;
   Put_Line ("");

   -- Alice sends her encrypted and signed message to Bob with the Nonce
   -- Bob computes a shared key with his secret key and Alice's public key
   -- which is the same as the one Alice had used to encrypt
   -- Then he uses it to decrypt Alice's message

   Crypto_Box_Open (M_Bob, C, N, PK_Alice, SK_Bob);
   Put (" Decrypted message = ");
   for i in M_Bob'First .. M_Bob'Last loop
      Put (u8'Image (M_Bob (i)));
   end loop;
   Put_Line ("");

end Test3;
