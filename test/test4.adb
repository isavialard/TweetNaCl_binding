pragma SPARK_Mode;

with Interfaces.C; use Interfaces.C;
with Ada.Text_IO;  use Ada.Text_IO;
with TweetNaCl_Binding; use TweetNaCl_Binding;
with TweetNaCl_Interface; use TweetNaCl_Interface;

-- Here the secret and public key are exchanged in Crypto_Box
-- This code can be compiled and executed, but fails at SPARK proof because of
-- the preconditions on Crypto_Box

procedure Test4 is

   csk : Key;
   cpk : Key;
   ssk : Key64;
   spk : Key;
   n   : Nonce;
   m   : PlainText :=(16#41#, 16#64#, 16#61#, 16#20#, 16#69#, 16#73#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#, 16#70#, 16#72#, 16#65#, 16#74#, 16#74#, 16#69#, 16#65#, 16#73#, 16#74#, 16#20#, 16#6f#, 16#66#, 16#20#, 16#61#, 16#6c#, 16#6c#, 16#20#, 16#6c#, 16#61#, 16#6e#, 16#67#, 16#75#, 16#61#, 16#67#, 16#65#, 16#73#);
   sm  : PlainText(m'First..m'Last+64);
   c   : CipherText(sm'First..sm'Last+32);
   smu : PlainText(m'First..m'Last+64);
   mu  : PlainText(m'First..m'Last);

begin

   Crypto_Box_Keypair(cpk,csk);
   Crypto_Sign_Keypair(spk,ssk);
   Crypto_Sign(sm,m,ssk);
   Randombytes(n);
   Crypto_Box(c,sm, n, csk, cpk);
   Crypto_Box_Open(smu,c,n,csk,cpk);
   if smu/=sm then
      Put_Line("error new signed message different than initial signed message");
   end if;
   Crypto_Sign_Open(mu, smu, spk);
   if mu/=m then
      Put_Line("error new message different than initial message");
   end if;

end Test4;
