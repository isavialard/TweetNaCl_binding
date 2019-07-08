pragma SPARK_Mode;

with Ada.Text_IO;  use Ada.Text_IO;
with TweetNaCl_Binding; use TweetNaCl_Binding;
with TweetNaCl_Interface; use TweetNaCl_Interface;

procedure Test is

   csk : Key;
   cpk : Key;
   ssk : Key64;
   spk : Key;
   n   : Nonce;
   m   : constant Plain_Text := (16#41#, 16#64#, 16#61#, 16#20#, 16#69#,
                                 16#73#, 16#20#, 16#74#, 16#68#, 16#65#,
                                 16#20#, 16#70#, 16#72#, 16#65#, 16#74#,
                                 16#74#, 16#69#, 16#65#, 16#73#, 16#74#,
                                 16#20#, 16#6f#, 16#66#, 16#20#, 16#61#,
                                 16#6c#, 16#6c#, 16#20#, 16#6c#, 16#61#,
                                 16#6e#, 16#67#, 16#75#, 16#61#, 16#67#,
                                 16#65#, 16#73#);
   sm  : Plain_Text (m'First .. m'Last + 64);
   c   : Cipher_Text (sm'First .. sm'Last + 32);
   smu : Plain_Text (m'First .. m'Last + 64);
   mu  : Plain_Text (m'First .. m'Last);

begin
   Put_Line ("");
   Put (" m = ");
   for i in m'First .. m'Last loop
      Put (u8'Image (m (i)));
   end loop;
   Put_Line ("");
   Crypto_Box_Keypair (cpk, csk);
   Crypto_Sign_Keypair (spk, ssk);
   Put (" sign secret key = ");
   for i in ssk'First .. ssk'Last loop
      Put (u8'Image (ssk (i)));
   end loop;
   Put_Line ("");
   Put (" sign public key = ");
   for i in spk'First .. spk'Last loop
      Put (u8'Image (spk (i)));
   end loop;
   Put_Line ("");
   Put_Line ("Signing the message ...");
   Crypto_Sign (sm, m, ssk);
   Put (" signed m = ");
   for i in sm'First .. sm'Last loop
      Put (u8'Image (sm (i)));
   end loop;
   Put_Line ("");
   Randombytes (n);
   Put (" box secret key = ");
   for i in csk'First .. csk'Last loop
      Put (u8'Image (csk (i)));
   end loop;
   Put_Line ("");
   Put (" box public key = ");
   for i in cpk'First .. cpk'Last loop
      Put (u8'Image (cpk (i)));
   end loop;
   Put_Line ("");
   Put (" Nonce = ");
   Put_Line ("");
   Put_Line ("Encrypting ...");
   Crypto_Box (c, sm, n, cpk, csk);
   Put (" cipher text = ");
   for i in c'First .. c'Last loop
      Put (u8'Image (c (i)));
   end loop;
   Put_Line ("");
   Put_Line ("Decrypting ...");
   Crypto_Box_Open (smu, c, n, cpk, csk);
   if smu /= sm then
      Put_Line ("error new signed message different than initial message");
   else
      Put_Line ("Done !");
   end if;
   Put_Line ("Checking the sign ...");
   Crypto_Sign_Open (mu, smu, spk);
   if mu /= m then
         Put_Line ("error new message different than initial message");
   else
      Put_Line ("Done !");
   end if;

end Test;
