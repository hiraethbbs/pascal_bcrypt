Program BCryptHashTest;
{$mode objfpc}{$H+}
{$ASSERTIONS ON}
{$UNITPATH ../}
{$CODEPAGE UTF-8}

uses BCrypt, Classes, SysUtils, Crt;
const
  HashToMatch1 = '$2y$14$6m54yWmpJRWWVkUz9p7feOlfQvafHGwsWt9pYupeLr8DU5wKMv.wW';
  HashToMatch2 = '$2y$16$d6eiNIIJPsVWtF.RCr.GUuCRs2hHFDB.0wPR.uK4kTi7KJvIO7k8e';
  BSDHashToMatch = '$2a$14$6m54yWmpJRWWVkUz9p7feOlfQvafHGwsWt9pYupeLr8DU5wKMv.wW';
  ShortHash = '$2y$14$6m54yWmpJRWWVkUz9p7feOlfQvafHGwsWt9pYupeLr8DU5wK';
  LongHash = '$2y$14$6m54yWmpJRWWVkUz9p7feOlfQvafHGwsWt9pYupeLr8DU5wKMv.wWwKMvwKMv';
  StaticPassword = 'password';

var
  TBCrypt : TBCryptHash;
  PasswordInfo : RTPasswordInformation;
  i, j,
  Assertions,
  FailedAssertions,
  PassedAssertions : Word;
  Passed : Boolean;

  UTF8TestString : UTF8String = 'Τη γλώσσα μου έδωσαν ελληνική';
  UTF8TestHash : AnsiString = '$2y$12$RSxqgCt5T4qPXLM3AzKMCueMBZo6cc9o/bN4wqcX6KA6lZnOkqzTG';
  UTF8PHPHash : AnsiString = '$2y$12$KrBUSn54WO5C/aw2H3imKurgsnrGq7PsrIZYXusaTNIO.27IGsmkG';

  PasswordHashes : array [1..14] of AnsiString = (
    '$2y$10$LCb3aOt8lAXSzNrEpQKDQO1zc2wCCQltrDwSEbb9JaUo4OKbphC3i',
    '$2y$11$H7TRTJZqQTzN5RCiwMOne.yjVxyKCd4GyLrBQzV91gK0T4XQeKTNa',
    '$2y$12$EL5tAZCoKb/kz4Q6WWCiw.DY1Ow/PcyE0w0Uo/SNjtnq7mePss/Yq',
    '$2y$13$ou4ZkaFPLILNkSLNINSw9uEARJOQQr8u02KbVuosBs3ULxpbEpjwS',
    '$2y$14$jvv79wTecdgfOjhefJL8B.ziJNvfqf.hR9IkUdEzgOVyqzgUDMnW.',
    '$2y$15$EdDG3DH94Yw5HWD8pHFpwuF6Bs/24cnf0c.H2UrhPeld4sl5.LPT.',
    '$2y$16$NjsYCIxFgM0KUfJ2N0tW1umTh4hUV696cEwVo8TM/grYdfbc4dwwu',
    // BSD
    '$2a$10$gd4l18fYW85l4he4zRD.seTuSA81Ku.Myqhdqp0LapOoGyHIe3okG',
    '$2a$11$sbCP6X5yYvjYe8EJt2H4wOGxiTT/JIXz.fCaVdLAXp58mEiXeQlrO',
    '$2a$12$hnT.LCI2PlLFDDI8lAi6G.Lmb5Q45pUIKk7Rabos9LNl8gqW4Z9gi',
    '$2a$13$UB99eDai2k5YrwAAbqxPreIStZiSszuRT0AZCP4hvavPSxUoC7DxW',
    '$2a$14$SDveEpfBff4N4FkpvQyxyu07EFhADHjk3lJkW3mV0/1x98xK28LKK',
    '$2a$15$7z9ZVYe16/s6NAXjWO2eyeCPR0tyUhI4PCj0LlJZ3XUR2NMrmO18y',
    '$2a$16$ZhJeznvMiClYg20vpSjPDOC79J5KKlaLmQAXuObWHl90G2D21NvKO');

  PHPPasswordHashes : array [1..7] of AnsiString = (
    '$2y$10$jRrQ51AeaJsJwNUw.QCDsOixDj.E0Vf2AG4tZdDmWqCSypmpFTr/q',
    '$2y$11$VEWaKBoOqoer/kjv3p/6SOa0SVTLRqH5huBsH7/6UlOvHI8f4zvvO',
    '$2y$12$hB6POF2QYZrkIx5a/CzB.OxvmJV9gy.93SPmOvwVySwukE1fJFgZm',
    '$2y$13$UWJNfSSzwYKeYyddhVYbNuyjYJx6ZZMGSLJnYcxiaFmYmPcTnJgxK',
    '$2y$14$FY/x2WRjTSB54IcSiRkz3u0mtyyNzeX/JQmxFxIyWrrc24JK3EuVK',
    '$2y$15$LE0.AEojI.2T6RadZVhc7eVsAkGsv0A2t0cKgWQBuAes86m.G036q',
    '$2y$16$yYy5GcoIgdd02DmUM3tfded5R5mv4K5QNG8QZDylGadokBdSL2WU6');

  PasswordHashFailures : array [1..7] of AnsiString = (
    '$2y$10$LCb3aOt8lAXSzNrEpQKDQO1zc2wCCQltrDwSEbb9JaUo4OKbph',
    '$2y$11$H7TRTJZqQTzN5RCiwMOne.yjVxyKCd4GyLrBQzV91gK0T4XQeKTNadr',
    '$2y$12$EL5tAZCoKb/kz4Q6WWCiw.DY1Ow/PcyE0w0Uo/SNjtnq7mePss/YQ',
    '$2y$13$ou4ZkaFPLILNkSLNINSw9uEARJOQQr8u02KbVuosBs3ULxpbEpjwt',
    '$2y$14$jvv79wTecdgfOjhefJL8B.ziJNvfqf.hR9IkUdEzgOVyqzgUDMn.W',
    '$2y$15$EdDG3DH94Yw5HWD8pHFpwuF6Bs/24cnf0c.H2UrhPeld4sl5.LP.',
    '$2y$16$NjsYCIxFgM0KUfJ2N0tW1umTh4hV696cEwVo8TM/gYdfbc4duwwd/');

begin

TBCrypt := TBCryptHash.Create;

Assertions := 0;
FailedAssertions := 0;
PassedAssertions := 0;

WriteLn(#10#13'Testing Pascal Hashes ...'#10#13);
for i := 1 to 14 do
  begin
      Write('Testing : ', PasswordHashes[i]);
      try
        Assert(TBCrypt.VerifyHash(StaticPassword, PasswordHashes[i]) = True, 'Should Be True');
        Inc(Assertions);
      except
        on e: EAssertionFailed do
          begin
            WriteLn(' - Fail');
            Inc(FailedAssertions);
            Continue;
          end;
      end;
      WriteLn(' - Pass');
      Inc(PassedAssertions);
      if i = 7 then
        begin
          Writeln(#10#13'Testing BSD Hashes ...'#10#13);
        end;
  end;
WriteLn(#10#13'Testing PHP Hashes ...'#10#13);
for i := 1 to 7 do
  begin
      Write('Testing : ', PHPPasswordHashes[i]);
      try
        Assert(TBCrypt.VerifyHash(StaticPassword, PHPPasswordHashes[i]) = True, 'Should Be True');
        Inc(Assertions);
      except
        on e: EAssertionFailed do
          begin
            WriteLn(' - Fail');
            Inc(FailedAssertions);
            Continue;
        end;
      end;
      WriteLn(' - Pass');
      Inc(PassedAssertions);
  end;
WriteLn(#10#13'Testing UTF8 with ', UTF8TestString, ' ... '#10#13);
  Write('Testing : ', UTF8TestHash);
  try
    Assert(TBCrypt.VerifyHash(UTF8TestString, UTF8TestHash) = True, 'Should Be True');
    Inc(Assertions);
    Inc(PassedAssertions);
    Writeln(' - Pass');
  except
    on e: EAssertionFailed do
    begin
      WriteLn(' - Fail');
      Inc(FailedAssertions);
      Dec(PassedAssertions);
    end;
    end;

  WriteLn(#10#13'Testing UTF8 PHP Hash with ', UTF8TestString, ' ... '#10#13);
  Write('Testing : ', UTF8PHPHash);
  try
    Assert(TBCrypt.VerifyHash(UTF8TestString, UTF8PHPHash) = True, 'Should Be True');
    Inc(Assertions);
    Inc(PassedAssertions);
    Writeln(' - Pass');
  except
  on e: EAssertionFailed do
  begin
    WriteLn(' - Fail');
    Inc(FailedAssertions);
    Dec(PassedAssertions);
  end;
  end;

    WriteLn(#10#13'Testing Failures ...'#10#13);
    for i := 1 to 7 do
    begin
      Write('Testing : ', PasswordHashFailures[i]);
      try
        Assert(TBCrypt.VerifyHash(StaticPassword, PasswordHashFailures[i]) = False, 'Should Be False');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        WriteLn(' - Fail');
        Inc(FailedAssertions);
        Continue;
      end;
      end;
      WriteLn(' - Pass');
      Inc(PassedAssertions);

    end;

    WriteLn(#10#13'Testing Rehash True ...'#10#13);
    for i := 1 to 7 do
    begin
      Write('Testing : ', PasswordHashes[i]);
      try
        Assert(TBCrypt.NeedsRehash(PasswordHashes[i], 17) = True, 'Should Be True');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        WriteLn(' - Fail');
        Inc(FailedAssertions);
        Continue;
      end;
      end;
      WriteLn(' - Pass');
      Inc(PassedAssertions);
    end;

    WriteLn(#10#13'Testing Rehash False ...'#10#13);
    j := 10;
    for i := 1 to 7 do
    begin
      Write('Testing : ', PasswordHashes[i]);
      try
        Assert(TBCrypt.NeedsRehash(PasswordHashes[i], j) = False, 'Should Be False');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        WriteLn(' - Fail');
        Inc(FailedAssertions);
        Inc(j);
        Continue;
      end;
      end;
      WriteLn(' - Pass');
      Inc(PassedAssertions);
      Inc(j);
    end;

    WriteLn(#10#13'Testing HashGetInfo on hash '#10#13, HashToMatch2, ' ...'#10#13);
    PasswordInfo := TBCrypt.HashGetInfo(HashToMatch2);
    Passed := True;
    With PasswordInfo do
    begin
      Writeln('Algo : ', Algo);
      try
        Assert(Algo = bcPHP);
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        Inc(FailedAssertions);
      end;
      end;
      WriteLn('AlgoName : ', AlgoName);
      WriteLn('Cost : ', Cost);
      Write('Salt : ', BCryptSalt);
      try
        Assert(Length(BCryptSalt) = 22, 'Should Be True');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        Passed := False;
      end;
      end;
      if Passed = False then
      begin
        Writeln(' Length - Fail');
        Inc(FailedAssertions);
      end else
      begin
        Writeln(' Length - Pass');
        Inc(PassedAssertions);
      end;
      Passed := True;
      Write('Hash : ', BCryptHash);
      try
        Assert(Length(BCryptHash) = 31, 'Should Be True');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        Passed := False;
      end;
      end;
      if Passed = False then
      begin
        Writeln(' Length - Fail');
        Inc(FailedAssertions);
      end else
      begin
        Writeln(' Length - Pass');
        Inc(PassedAssertions);
      end;

    end;

    WriteLn(#10#13'Testing HashGetInfo on bsd hash '#10#13, BSDHashToMatch, ' ...'#10#13);
    PasswordInfo := TBCrypt.HashGetInfo(BSDHashToMatch);
    Passed := True;
    With PasswordInfo do
    begin
      Writeln('Algo : ', Algo);
      try
        Assert(Algo = bcBSD);
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        Inc(FailedAssertions);
      end;
      end;
      WriteLn('AlgoName : ', AlgoName);
      WriteLn('Cost : ', Cost);
      Write('Salt : ', BCryptSalt);
      try
        Assert(Length(BCryptSalt) = 22, 'Should Be True');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        Passed := False;
      end;
      end;
      if Passed = False then
      begin
        Writeln(' Length - Fail');
        Inc(FailedAssertions);
      end else
      begin
        Writeln(' Length - Pass');
        Inc(PassedAssertions);
      end;
      Passed := True;
      Write('Hash : ', BCryptHash);
      try
        Assert(Length(BCryptHash) = 31, 'Should Be True');
        Inc(Assertions);
      except
      on e: EAssertionFailed do
      begin
        Passed := False;
      end;
      end;
      if Passed = False then
      begin
        Writeln(' Length - Fail');
        Inc(FailedAssertions);
      end else
      begin
        Writeln(' Length - Pass');
        Inc(PassedAssertions);
      end;

    end;

    Writeln(#10#13'Testing PasswordInfo with bad Hashes.'#10#13);
    Passed := False;
    try
      Write('Short Hash : ', ShortHash);
      PasswordInfo := TBCrypt.HashGetInfo(ShortHash);
      Inc(Assertions);
    except
    on e: EHash do
    begin
      Passed := True;
    end;
    end;
    if Passed = True then
    begin
      Writeln(' - Pass');
      Inc(PassedAssertions);
    end else
    begin
      Writeln(' - Fail');
      Inc(FailedAssertions);
    end;
    Passed := False;
    try
      Write('Long Hash  : ', LongHash);
      PasswordInfo := TBCrypt.HashGetInfo(LongHash);
      Inc(Assertions);
    except
    on e: EHash do
    begin
      Passed := True;
    end;
    end;
    if Passed = True then
    begin
      Writeln(' - Pass');
      Inc(PassedAssertions);
    end else
    begin
      Writeln(' - Fail');
      Inc(FailedAssertions);
    end;

    Writeln(#10#13'Testing hashing ...'#10#13);
    Writeln(TBCrypt.CreateHash(StaticPassword));
    Writeln(TBCrypt.CreateHash(StaticPassword, bcBSD));
    Writeln(TBCrypt.CreateHash(StaticPassword, bcDefault));
    Writeln(TBCrypt.CreateHash(StaticPassword, bcPHP));
    Writeln(TBCrypt.CreateHash(StaticPassword, bcBSD, 14));
    Writeln(TBCrypt.CreateHash(StaticPassword, bcDefault, 14));
    Writeln(TBCrypt.CreateHash(StaticPassword, bcPHP, 14));
    Writeln(#10#13);

    TBCrypt.Free;
    Writeln('Assertions        : ', Assertions);
    Writeln('Passed Assertions : ', PassedAssertions);
    Writeln('Failed Assertions : ', FailedAssertions);
    Writeln;
  end.
