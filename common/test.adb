pragma SPARK_Mode;

with Interfaces.C; use Interfaces.C;
with Ada.Text_IO;  use Ada.Text_IO;
with tweetnaclhl; use tweetnaclhl;
with tweetnacl_h; use tweetnacl_h;

procedure Test is

   csk : Key;
   cpk : Key;
   ssk : Key64;
   spk : Key;
   n : Nonce;
   m : PlainText :=(16#41#, 16#64#, 16#61#, 16#20#, 16#69#, 16#73#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#, 16#70#, 16#72#, 16#65#, 16#74#, 16#74#, 16#69#, 16#65#, 16#73#, 16#74#, 16#20#, 16#6f#, 16#66#, 16#20#, 16#61#, 16#6c#, 16#6c#, 16#20#, 16#6c#, 16#61#, 16#6e#, 16#67#, 16#75#, 16#61#, 16#67#, 16#65#, 16#73#);
   sm : PlainText(m'First..m'Last+64);
   c : CipherText(sm'First..sm'Last+32);
   smu : PlainText(m'First..m'Last+64);
   mu : PlainText(m'First..m'Last);

begin

   crypto_box_keypair(cpk,csk);
   crypto_sign_keypair(spk,ssk);
   crypto_sign(sm,m,ssk);
   randombytes(n);
   crypto_box(c,sm, n, cpk, csk);
   crypto_box_open(smu,c,n,cpk,csk);
   for i in sm'First..sm'Last loop
      if smu(i)/=sm(i) then
         Put_Line("error new signed message different than initial signed message");
      end if;
   end loop;
   crypto_sign_open(mu, smu, spk);
   for i in m'First..m'Last loop
      if mu(i)/=m(i) then
         Put_Line("error new message different than initial message");
      end if;
   end loop;

end Test;
