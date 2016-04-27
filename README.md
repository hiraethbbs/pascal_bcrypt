# Free Pascal BCrypt

Free Pascal [BCrypt](https://en.wikipedia.org/wiki/Bcrypt "BCrypt") implementation.

This started because I wanted something that would be compatible with PHP's $2y$ BCrypt hashing.  Ultimately there is no difference between the $2a$ algorithm and the $2y$ algorithm.  Just the a, and y.  But I didn't want to have a wrapper function that replaced the a with the y.

If you try to verify a $2a$ password with PHP it will verify, but if you run the needs rehash function it will always say it needs a rehash.  So I moved this to Free Pascal compatible class format.

Tested with :
  * Free Pascal
    * 2.6.4 
      * (Linux, Gentoo)
      * (Linux, Raspbian)
    * 3.0.0
      * (Linux, Gentoo)
      * (Win10, 64bit) 
  * PHP
    * 5.6.20-pl0-gentoo
    * 7.0.6_rc1-pl0-gentoo.

### Usage
```pascal
BCrypt.CreateHash(Password);
BCrypt.CreateHash(Password, HashType);
BCrypt.CreateHash(Password, HashType, Cost);
```
Where
  * Password is the password to be hashed
  * HashType is one of bcPHP, bcBSD, or bcDefault, bcPHP is the default $2y$
  * and Cost is a number between 10 and 30, default is 12.
```pascal
var
  BCrypt : TBCryptHash;
  Hash   : AnsiString;
begin
  BCrypt := TBCryptHash.Create;
  Hash := BCrypt.CreateHash('password'); // PHP $2y$ hash with a cost of 12
  // or
  Hash := BCrypt.CreateHash('password', bcBSD); // BSD $2a$ hash with a cost of 12
  // or
  Hash := BCrypt.CreateHash('password', bcPHP, 14); // PHP hash, with a cost of 14
  Writeln(Hash);
  BCrypt.Free;
end;
```

To verify
```pascal
var
  BCrypt : TBCryptHash;
  Hash : AnsiString;
  Verify : Boolean;
begin
  Hash := '$2y$12$GuC.Gk2YDsp8Yvga.IuSNOWM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq';
  BCrypt := TBCryptHash.Create;
  Verify := BCrypt.VerifyHash('password', Hash);
  BCrypt.Free;
end;
```

HashGetInfo - raises EHash exception if the hash is bad, ([too short](https://youtu.be/xT0Qb5ns7_A "too short"), too long);
```pascal
var
  BCrypt : TBCryptHash;
  Hash : AnsiString;
  PasswordInfo : RTPasswordInformation;
begin
  BCrypt := TBCryptHash.Create;
  Hash := '$2y$12$GuC.Gk2YDsp8Yvga.IuSNOWM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq';
  PasswordInfo := BCrypt.HashGetInfo(Hash);
  with PasswordInfo do
    begin
      WriteLn('Algo : ', Algo); // bcPHP  
      WriteLn('AlgoName : ', AlgoName); // bcrypt
      WriteLn('Cost : ', Cost); // 12
      WriteLn('Salt : ', BCryptSalt); // GuC.Gk2YDsp8Yvga.IuSNO
      WriteLn('Hash : ', BCryptHash); // WM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq
    end;

  Hash := '$2a$12$GuC.Gk2YDsp8Yvga.IuSNOWM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq';
  PasswordInfo := BCrypt.HashGetInfo(Hash);
  with PasswordInfo do
    begin
      WriteLn('Algo : ', Algo); // bcBSD  
      WriteLn('AlgoName : ', AlgoName); // bcrypt
      WriteLn('Cost : ', Cost); // 12
      WriteLn('Salt : ', BCryptSalt); // GuC.Gk2YDsp8Yvga.IuSNO
      WriteLn('Hash : ', BCryptHash); // WM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq
    end;
    BCrypt.Free;
end;  
```
NeedsRehash
```pascal
var
  BCrypt : TBCryptHash;
  Hash : AnsiString;
  Rehash : Boolean;
begin
  BCrypt := TBCryptHash.Create;
  Hash := '$2a$12$GuC.Gk2YDsp8Yvga.IuSNOWM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq';
  Rehash := BCrypt.NeedsRehash(Hash); // false
  Rehash := BCrypt.NeedsRehash(Hash, 14); // true
  Hash := '$2y$14$GuC.Gk2YDsp8Yvga.IuSNOWM0fxEIsAEaWC1hqEI14Wa.7Ps3iYFq';
  Rehash := BCrypt.NeedsRehash(Hash); // true
  Rehash := BCrypt.NeedsRehash(Hash, 14); // false
  BCrypt.Free;
end;
```
### Evolution
This has had quite the evolution.

[FreeBSD crypt.c](https://svnweb.freebsd.org/base/stable/10/lib/libcrypt/crypt.c?revision=273043&view=markup "FreeBSD crypt.c")

[BCrypt for Delphi](https://github.com/JoseJimeniz/bcrypt-for-delphi "BCrypt for Delphi")

[BCrypt for Delphi, Lazarus, FPC](https://github.com/PonyPC/BCrypt-for-delphi-lazarus-fpc "BCrypt for Delphi, Lazarus, FPC")

[PHP password.c](https://github.com/php/php-src/blob/master/ext/standard/password.c "PHP password.c") For the verify logic.

To here.
