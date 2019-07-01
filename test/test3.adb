pragma SPARK_Mode;

with Interfaces.C; use Interfaces.C;
with Ada.Text_IO;  use Ada.Text_IO;
with TweetNaCl_Binding; use TweetNaCl_Binding;
with TweetNaCl_Interface; use TweetNaCl_Interface;

-- Here we encrypt a plain text which has not be signed, which makes it
-- vulnerable to tampering
-- This code can be compiled and executed, but fails at SPARK proof because of
-- the preconditions on Crypto_Box

procedure Test3 is

   csk : Key;
   cpk : Key;
   n   : Nonce;
   m   : PlainText :=(16#41#, 16#64#, 16#61#, 16#20#, 16#69#, 16#73#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#, 16#70#, 16#72#, 16#65#, 16#74#, 16#74#, 16#69#, 16#65#, 16#73#, 16#74#, 16#20#, 16#6f#, 16#66#, 16#20#, 16#61#, 16#6c#, 16#6c#, 16#20#, 16#6c#, 16#61#, 16#6e#, 16#67#, 16#75#, 16#61#, 16#67#, 16#65#, 16#73#);
   c   : CipherText(m'First..m'Last+32);
   mu  : PlainText(m'First..m'Last);

begin

   Crypto_Box_Keypair(cpk,csk);
   Randombytes(n);
   Crypto_Box(c,m, n, cpk, csk);
   Crypto_Box_Open(mu,c,n,cpk,csk);
   if mu/=m then
      Put_Line("error new message different than initial message");
   end if;

end Test3;
