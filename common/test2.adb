pragma SPARK_Mode;
-- enlever les pointeurs
-- faire un reproduceur
-- faire test ou on crypte et sign, et dans quel ordre ?
-- passer en spark
-- git


with Interfaces.C; use Interfaces.C;
with Ada.Text_IO;  use Ada.Text_IO;
with tweetnaclhl;       use tweetnaclhl;
with tweetnacl_h;
use tweetnacl_h;

procedure Test2 is
   procedure test_box is

      csk : tweetnacl_h.Key;
      cpk : tweetnacl_h.Key;
      ssk : tweetnacl_h.Key64;
      spk : tweetnacl_h.Key;
      n : tweetnacl_h.Nonce;
      m : tweetnacl_h.PlainText := (56,75,6,43,22,123,57,54,4,35,43,32,21,3,35,4,65,76,7,66,43,54,12,34,32,54,53,4,65);
      sm : tweetnacl_h.PlainText(m'First..m'Last+64);
      c : tweetnacl_h.CipherText(sm'First..sm'Last+32);
      smu : tweetnacl_h.PlainText(m'First..m'Last+64);
      mu : tweetnacl_h.PlainText(m'First..m'Last);

   begin

      crypto_box_keypair(cpk,csk);
      crypto_sign_keypair(spk,ssk);
      crypto_sign(sm,m,ssk);
      tweetnacl_h.randombytes(n,24);
      crypto_box(c,sm, n, cpk, csk);
      crypto_box_open(smu,c,n,cpk,csk);
      for i in sm'First..sm'Last loop
         if smu(i)/=sm(i) then
            Put_Line("Prblm 6");
         end if;
      end loop;
      crypto_sign_open(mu, smu, spk);
      for i in m'First..m'Last loop

         if mu(i)/=m(i) then
            Put_Line("Prblm 8");
         end if;
      end loop;

   end test_box;





begin
   test_box;
end Test2;
