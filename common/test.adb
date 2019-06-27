with Interfaces.C; use Interfaces.C;
with Ada.Text_IO;  use Ada.Text_IO;
with tweetnacl_h;       use tweetnacl_h;

procedure Test is
   --type u64 is mod 2 ** 64;

   procedure test_rfc7748_1 is
      

      r0: Key;
      r1: Key;
      s0: Key:=(16#a5#,16#46#,16#e3#,16#6b#,16#f0#,16#52#,16#7c#,16#9d#,16#3b#,16#16#,16#15#,16#4b#,16#82#,16#46#,16#5e#,16#dd#,16#62#,16#14#,16#4c#,16#0a#,16#c1#,16#fc#,16#5a#,16#18#,16#50#,16#6a#,16#22#,16#44#,16#ba#,16#44#,16#9a#,16#c4#);
      s1: Key:=(16#4b#,16#66#,16#e9#,16#d4#,16#d1#,16#b4#,16#67#,16#3c#,16#5a#,16#d2#,16#26#,16#91#,16#95#,16#7d#,16#6a#,16#f5#,16#c1#,16#1b#,16#64#,16#21#,16#e0#,16#ea#,16#01#,16#d4#,16#2c#,16#a4#,16#16#,16#9e#,16#79#,16#18#,16#ba#,16#0d#);
      u0: Key:=(16#e6#,16#db#,16#68#,16#67#,16#58#,16#30#,16#30#,16#db#,16#35#,16#94#,16#c1#,16#a4#,16#24#,16#b1#,16#5f#,16#7c#,16#72#,16#66#,16#24#,16#ec#,16#26#,16#b3#,16#35#,16#3b#,16#10#,16#a9#,16#03#,16#a6#,16#d0#,16#ab#,16#1c#,16#4c#);
      u1: Key:=(16#e5#,16#21#,16#0f#,16#12#,16#78#,16#68#,16#11#,16#d3#,16#f4#,16#b7#,16#95#,16#9d#,16#05#,16#38#,16#ae#,16#2c#,16#31#,16#db#,16#e7#,16#10#,16#6f#,16#c0#,16#3c#,16#3e#,16#fc#,16#4c#,16#d5#,16#49#,16#c7#,16#15#,16#a4#,16#93#);
      e0: Key:=(16#c3#,16#da#,16#55#,16#37#,16#9d#,16#e9#,16#c6#,16#90#,16#8e#,16#94#,16#ea#,16#4d#,16#f2#,16#8d#,16#08#,16#4f#,16#32#,16#ec#,16#cf#,16#03#,16#49#,16#1c#,16#71#,16#f7#,16#54#,16#b4#,16#07#,16#55#,16#77#,16#a2#,16#85#,16#52#);
      e1: Key:=(16#95#,16#cb#,16#de#,16#94#,16#76#,16#e8#,16#90#,16#7d#,16#7a#,16#ad#,16#e4#,16#5c#,16#b4#,16#b8#,16#73#,16#f8#,16#8b#,16#59#,16#5a#,16#68#,16#79#,16#9f#,16#a1#,16#52#,16#e6#,16#f8#,16#f7#,16#64#,16#7a#,16#ac#,16#79#,16#57#);

   begin
      if crypto_scalarmult_curve25519_tweet(r0,s0,u0) /= 0 then
        Put_Line ("prblm1.1");
      end if;
      if crypto_verify_32_tweet(r0,e0) /= 0 then
         Put_Line ("prblm1.2");
      end if;
      if crypto_scalarmult_curve25519_tweet(r1,s1,u1) /= 0 then
         Put_Line ("prblm1.3");
      end if;
      if crypto_verify_32_tweet(r1,e1) /= 0 then
         Put_Line ("prblm1.4");
      end if;
	Put_Line("Fin test 1");
   end test_rfc7748_1;
   
   procedure test_rfc7748_2 is
     
      type Index1000 is range 1 .. 1000;
      
      A1:Key:=(16#42#,16#2c#,16#8e#,16#7a#,16#62#,16#27#,16#d7#,16#bc#,16#a1#,16#35#,16#0b#,16#3e#,16#2b#,16#b7#,16#27#,16#9f#,16#78#,16#97#,16#b8#,16#7b#,16#b6#,16#85#,16#4b#,16#78#,16#3c#,16#60#,16#e8#,16#03#,16#11#,16#ae#,16#30#,16#79#);
      A1000:Key:=(16#68#,16#4c#,16#f5#,16#9b#,16#a8#,16#33#,16#09#,16#55#,16#28#,16#00#,16#ef#,16#56#,16#6f#,16#2f#,16#4d#,16#3c#,16#1c#,16#38#,16#87#,16#c4#,16#93#,16#60#,16#e3#,16#87#,16#5f#,16#2e#,16#b9#,16#4d#,16#99#,16#53#,16#2c#,16#51#);
      k:Key:=(9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
      u:Key:=(9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
      t:Key;
      v:Key; --v est là pour éviter un problème d'alias dans crypto_scalarmult_curve25519_tweet(k,k,u)
 
   begin
      for i in Index1000 loop
         if i=2 then
            if crypto_verify_32_tweet(k,A1)/=0 then
               Put_Line ("prblm2.1");
            end if;
         end if;
         for j in Index32 loop
            t(j):=k(j);
         end loop;
         if crypto_scalarmult_curve25519_tweet(v,k,u) /= 0 then --prblm erroneous memory access. Question d'alias ?
            Put_Line ("prblm2.2");
         end if;
         for j in Index32 loop
            u(j):=t(j);
            k(j):=v(j);
         end loop;
      end loop;
      if crypto_verify_32_tweet(k,A1000) /= 0 then
         Put_Line ("prblm2.3");
      end if;
      Put_Line("Fin test 2");
   end test_rfc7748_2;
   
   procedure test_rfc7748_3 is
      Ask :Key := (16#77#,16#07#,16#6d#,16#0a#,16#73#,16#18#,16#a5#,16#7d#,16#3c#,16#16#,16#c1#,16#72#,16#51#,16#b2#,16#66#,16#45#,16#df#,16#4c#,16#2f#,16#87#,16#eb#,16#c0#,16#99#,16#2a#,16#b1#,16#77#,16#fb#,16#a5#,16#1d#,16#b9#,16#2c#,16#2a#);
      Bsk :Key := (16#5d#,16#ab#,16#08#,16#7e#,16#62#,16#4a#,16#8a#,16#4b#,16#79#,16#e1#,16#7f#,16#8b#,16#83#,16#80#,16#0e#,16#e6#,16#6f#,16#3b#,16#b1#,16#29#,16#26#,16#18#,16#b6#,16#fd#,16#1c#,16#2f#,16#8b#,16#27#,16#ff#,16#88#,16#e0#,16#eb#);
      eApk :Key := (16#85#,16#20#,16#f0#,16#09#,16#89#,16#30#,16#a7#,16#54#,16#74#,16#8b#,16#7d#,16#dc#,16#b4#,16#3e#,16#f7#,16#5a#,16#0d#,16#bf#,16#3a#,16#0d#,16#26#,16#38#,16#1a#,16#f4#,16#eb#,16#a4#,16#a9#,16#8e#,16#aa#,16#9b#,16#4e#,16#6a#);
      eBpk:Key := (16#de#,16#9e#,16#db#,16#7d#,16#7b#,16#7d#,16#c1#,16#b4#,16#d3#,16#5b#,16#61#,16#c2#,16#ec#,16#e4#,16#35#,16#37#,16#3f#,16#83#,16#43#,16#c8#,16#5b#,16#78#,16#67#,16#4d#,16#ad#,16#fc#,16#7e#,16#14#,16#6f#,16#88#,16#2b#,16#4f#);
      ek:Key := (16#4a#,16#5d#,16#9d#,16#5b#,16#a4#,16#ce#,16#2d#,16#e1#,16#72#,16#8e#,16#3b#,16#f4#,16#80#,16#35#,16#0f#,16#25#,16#e0#,16#7e#,16#21#,16#c9#,16#47#,16#d1#,16#9e#,16#33#,16#76#,16#f0#,16#9b#,16#3c#,16#1e#,16#16#,16#17#,16#42#);
      Apk:Key;
      Bpk:Key;
      Ak: Key;
      Bk:Key;

      
   begin
      if crypto_scalarmult_curve25519_tweet_base(Apk,Ask) /= 0 then
        Put_Line ("prblm3.1");
      end if;
      if crypto_verify_32_tweet(Apk,eApk) /= 0 then
         Put_Line ("prblm3.2");
      end if;
      if crypto_scalarmult_curve25519_tweet_base(Bpk,Bsk) /= 0 then
        Put_Line ("prblm3.3");
      end if;
      if crypto_verify_32_tweet(Bpk,eBpk) /= 0 then
         Put_Line ("prblm3.4");
      end if;
      if crypto_scalarmult_curve25519_tweet(Ak,Ask,Bpk) /= 0 then
         Put_Line ("prblm3.5");
      end if;
      if crypto_verify_32_tweet(Ak,ek) /= 0 then
         Put_Line ("prblm3.6");
      end if;
      if crypto_scalarmult_curve25519_tweet(Bk,Bsk,Apk) /= 0 then
         Put_Line ("prblm3.7");
      end if;
      if crypto_verify_32_tweet(Bk,ek) /= 0 then
         Put_Line ("prblm3.8");
      end if;
	Put_Line("Fin test 3");
   end test_rfc7748_3;
   
begin
   test_rfc7748_1;
   test_rfc7748_2;
   test_rfc7748_3;
end Test;
