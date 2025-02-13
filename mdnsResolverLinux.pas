unit mdnsResolverLinux;

{$IFDEF FPC}
  {$MODE DELPHI}{$H+}
{$ENDIF}

interface

uses
  Classes, SysUtils, IdUDPServer, IdGlobal, IdSocketHandle, mdnsCore;

type
  TMDNSConfig = record
    UserName: string;
    HostName: string;
    Port: Word;
    IPAddress: string;
  end;

  TMDNSHeader = packed record
    TransactionID: Word;   // 16-bit transaction ID
    Flags: Word;           // 16-bit flags (QR, Opcode, etc.)
    QDCount: Word;         // 16-bit question count
    ANCount: Word;         // 16-bit answer count
    NSCount: Word;         // 16-bit authority count
    ARCount: Word;         // 16-bit additional count
  end;

  TmdnsResolver = class(TComponent)
  private
    FUDPServer: TIdUDPServer;
    FServiceType: string;
    FOnResolved: TmdnsResolveEvent;
    FConfig: TMDNSConfig;

    // mDNS response generation functions
    function BuildMDNSResponse: TIdBytes;
    procedure EncodeDomainName(Stream: TMemoryStream; const DomainName: string);
    procedure WriteWordBE(Stream: TMemoryStream; Value: Word);
    procedure WriteLongWordBE(Stream: TMemoryStream; Value: Cardinal);

    procedure UDPServerUDPRead(AThread: TIdUDPListenerThread;
      const AData: TIdBytes; ABinding: TIdSocketHandle);
    procedure SendAdvertisement(ABinding: TIdSocketHandle);
  public
    procedure StartAdvertise(const AUserName, AHostName, AIP: string; APort: Word);
    procedure StopAdvertise;
    procedure StartResolve;
    procedure StopResolve;
    procedure DoStartBrowse(const AServiceType: string);
    procedure DoStopBrowse;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    property OnResolved: TmdnsResolveEvent read FOnResolved write FOnResolved;
    property ServiceType: string read FServiceType write FServiceType;
  end;

implementation

{ TmdnsResolver }

constructor TmdnsResolver.Create(AOwner: TComponent);
var
  LBinding: TIdSocketHandle;
begin
  inherited Create(AOwner);
  FUDPServer := TIdUDPServer.Create(Self);

  // Configure UDP Server
  with FUDPServer do begin
    // Configure IPv4 binding
    LBinding := Bindings.Add;
    LBinding.IP := '0.0.0.0';      // Listen on all interfaces
    LBinding.Port := 5353;
    LBinding.IPVersion := Id_IPv4;
    LBinding.ReuseSocket := rsTrue; // Enable port reuse

    // Activate the server FIRST to bind the socket
    Active := True;

    // Now join multicast group
    try
      LBinding.AddMulticastMembership('224.0.0.251');
      LBinding.SetLoopBack(False);  // Allow local testing
    except
      on E: Exception do
        raise Exception.Create('Multicast join failed: ' + E.Message);
    end;

    // Event setup
    OnUDPRead := UDPServerUDPRead;
    ThreadedEvent := True;
  end;
end;

destructor TmdnsResolver.Destroy;
begin
  FUDPServer.Free;
  inherited Destroy;
end;

procedure TmdnsResolver.EncodeDomainName(Stream: TMemoryStream; const DomainName: string);
var
  Labels: TStringList;
  i, L: Integer;
  tempByte: Byte;
begin
  Labels := TStringList.Create;
  try
    Labels.StrictDelimiter := True;
    Labels.Delimiter := '.';
    Labels.DelimitedText := DomainName;

    for i := 0 to Labels.Count - 1 do begin
      L := Length(Labels[i]);
      tempByte := L;
      Stream.Write(tempByte, 1);
      if L > 0 then
        Stream.Write(PChar(Labels[i])^, L);
    end;
    tempByte := 0;
    Stream.Write(tempByte, 1);
  finally
    Labels.Free;
  end;
end;

procedure TmdnsResolver.WriteWordBE(Stream: TMemoryStream; Value: Word);
var
  b: Byte;
begin
  b := (Value shr 8) and $FF;
  Stream.Write(b, 1);
  b := Value and $FF;
  Stream.Write(b, 1);
end;

procedure TmdnsResolver.WriteLongWordBE(Stream: TMemoryStream; Value: Cardinal);
var
  b: Byte;
begin
  b := (Value shr 24) and $FF;
  Stream.Write(b, 1);
  b := (Value shr 16) and $FF;
  Stream.Write(b, 1);
  b := (Value shr 8) and $FF;
  Stream.Write(b, 1);
  b := Value and $FF;
  Stream.Write(b, 1);
end;

function TmdnsResolver.BuildMDNSResponse: TIdBytes;
var
  ms: TMemoryStream;
  dataLenPos: Int64;
  startPos: Int64;
  dataLen: Integer;
  userService, txtLine: string;
  txtLenByte: Byte;
  ipParts: TStringList;
  i: Integer;
  b: Byte;
begin
  //userService := FConfig.UserName + '@' + FConfig.HostName + '._presence._tcp.local';
  userService := 'inky._presence._tcp.local';
  ms := TMemoryStream.Create;
  try
    // DNS Header
    WriteWordBE(ms, 0);       // Transaction ID
    WriteWordBE(ms, $8400);   // Flags: QR=1, AA=1
    WriteWordBE(ms, 0);       // QDCount=0
    WriteWordBE(ms, 3);       // ANCount=3
    WriteWordBE(ms, 0);       // NSCount=0
    WriteWordBE(ms, 1);       // ARCount=1

    // PTR Record
    EncodeDomainName(ms, '_presence._tcp.local');
    WriteWordBE(ms, $000C);   // TYPE=PTR
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 4500); // TTL=75 minutes (mdns standard)
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    EncodeDomainName(ms, userService);
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // SRV Record
    //EncodeDomainName(ms, userService);
    EncodeDomainName(ms, 'lovelace.local');
    WriteWordBE(ms, $0021);   // TYPE=SRV
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 4500);
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    WriteWordBE(ms, 0);       // Priority=0
    WriteWordBE(ms, 0);       // Weight=0
    WriteWordBE(ms, FConfig.Port);
    EncodeDomainName(ms, FConfig.HostName);
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // TXT Record
    EncodeDomainName(ms, userService);
    WriteWordBE(ms, $0010);   // TYPE=TXT
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 4500);
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);       // RDLENGTH placeholder
    startPos := ms.Position;
    //txtLine := 'txtvers=1';
    txtLine := 'txtvers=1'#13'status=avail'; // RFC 6121 compliance
    txtLenByte := Length(txtLine);
    ms.Write(txtLenByte, 1);
    ms.Write(PChar(txtLine)^, txtLenByte);
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);
    ms.Seek(0, soFromEnd);

    // A Record
    EncodeDomainName(ms, FConfig.HostName);
    WriteWordBE(ms, $0001);   // TYPE=A
    WriteWordBE(ms, $0001);   // CLASS=IN
    WriteLongWordBE(ms, 4500);
    dataLenPos := ms.Position;
    WriteWordBE(ms, 0);
    startPos := ms.Position;
    ipParts := TStringList.Create;
    try
      ipParts.Delimiter := '.';
      ipParts.DelimitedText := FConfig.IPAddress;
      for i := 0 to 3 do begin
        b := StrToInt(ipParts[i]);
        ms.Write(b, 1);
      end;
    finally
      ipParts.Free;
    end;
    dataLen := ms.Position - startPos;
    ms.Seek(dataLenPos, soFromBeginning);
    WriteWordBE(ms, dataLen);

    // Finalize
    SetLength(Result, ms.Size);
    ms.Position := 0;
    ms.Read(Result[0], ms.Size);
  finally
    ms.Free;
  end;
end;

procedure TmdnsResolver.SendAdvertisement(ABinding: TIdSocketHandle);
var
  Response: TIdBytes;
begin
  Response := BuildMDNSResponse;
  ABinding.SendTo('224.0.0.251', 5353, Response);
end;

procedure TmdnsResolver.UDPServerUDPRead(
  AThread: TIdUDPListenerThread;
  const AData: TIdBytes;
  ABinding: TIdSocketHandle
);
var
  Header: TMDNSHeader;
begin
  if Length(AData) >= SizeOf(TMDNSHeader) then begin
    // Extract DNS header to check if it's a query
    Move(AData[0], Header, SizeOf(TMDNSHeader));

    // Check if the QR bit is 0 (query)
    if (Header.Flags and $8000) = 0 then begin
      SendAdvertisement(ABinding);
    end;
  end;
end;

procedure TmdnsResolver.StartAdvertise(const AUserName, AHostName, AIP: string; APort: Word);
begin
  try
    FConfig.UserName := AUserName;
    FConfig.HostName := AHostName;
    FConfig.IPAddress := AIP;
    FConfig.Port := APort;
    FUDPServer.Active := True;
  except
    on E: Exception do
      raise Exception.Create('Failed to start mDNS: ' + E.Message);
  end;
end;


procedure TmdnsResolver.StopAdvertise;
begin
  FUDPServer.Active := False;
end;

procedure TmdnsResolver.StartResolve;
begin
  FUDPServer.Active := True;
end;

procedure TmdnsResolver.StopResolve;
begin
  FUDPServer.Active := False;
end;

procedure TmdnsResolver.DoStartBrowse(const AServiceType: string);
begin
  FServiceType := AServiceType;
  StartResolve;
end;

procedure TmdnsResolver.DoStopBrowse;
begin
  StopResolve;
end;

end.
