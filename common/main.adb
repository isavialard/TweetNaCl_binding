with Interfaces.C; use Interfaces.C;
with Ada.Text_IO;  use Ada.Text_IO;
with tweetnacl_h;       use tweetnacl_h;

procedure Main is
   procedure test_box is

      sk : Key;
      pk : Key;
      n : Nonce;
      m : PlainText := new pt'(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,56,75,6,43,22,123,57,54,4,35,43,32,21,3,35,4,65,76,7,66,43,54,12,34,32,54,53,4,65);
      c : CipherText :=new ct(m'First..m'Last);
      md : PlainText :=new pt(m'First..m'Last);

   begin

      if crypto_box_curve25519xsalsa20poly1305_tweet_keypair(pk,sk)/=0 then
         Put_Line("Prblm 1");
      end if;
      randombytes(n,24);
      if crypto_box_curve25519xsalsa20poly1305_tweet(c, m, m'Length, n, pk, sk)/=0 then        --n ne change pas
         Put_Line("Prblm 2");
      end if;
      for i in c'First..c'Last loop
         Put(u8'Image(c(i)));
      end loop;
      if crypto_box_curve25519xsalsa20poly1305_tweet_open(md, c, m'Length, n, pk, sk)/=0 then
         Put_Line("Prblm 3");
      end if;
      for i in m'First..m'Last loop
         if md(i)/=m(i) then
            Put_Line("Prblm 4");
         end if;
      end loop;

   end test_box;


   procedure test_sign is

      sk : Key64;
      pk : Key;
      m : PlainText := new pt'(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,56,75,6,43,22,123,57,54,4,35,43,32,21,3,35,4,65,76,7,66,43,54,12,34,32,54,53,4,65);
      sm : CipherText :=new ct(m'First..m'Last+64);
      usm : PlainText :=new pt(m'First..m'Last+64);
      smlen : u64;
      mlen : u64;


   begin

      if crypto_sign_ed25519_tweet_keypair(pk,sk)/=0 then
         Put_Line("Prblm 1");
      end if;
      if crypto_sign_ed25519_tweet(sm,smlen,m,m'Length,sk)/=0 then        --n ne change pas
         Put_Line("Prblm 2");
      end if;
      if crypto_sign_ed25519_tweet_open(usm,mlen,sm,sm'Length,pk)/=0 then        --n ne change pas
         Put_Line("Prblm 2");
      end if;
      for i in m'First..m'Last loop
         if usm(i)/=m(i) then
            Put_Line("Prblm 4");
         end if;
      end loop;
   end test_sign;


begin
   test_box;
   test_sign;
end Main;
