unit mdnsResolver;

{$IFDEF FPC}
  {$MODE DELPHI}{$H+}
{$ENDIF}

interface
{$DEFINE MDSN_UNIT_INCLUDE}

{$IF DEFINED(WIN32) OR DEFINED(WIN64)}
{$I mdnsResolverWindows.pas}
{$ENDIF}
{$IFDEF ANDROID}
{$I mdnsResolverDelphiAndroid.pas}
{$ENDIF}
{$IFDEF LINUX}
  {$DEFINE USE_MDNS_LINUX}
  uses mdnsResolverLinux;
{$ENDIF}
implementation

end.
