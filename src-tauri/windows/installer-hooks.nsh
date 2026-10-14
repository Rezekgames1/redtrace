!macro NSIS_HOOK_PREINSTALL
  StrCmp $INSTDIR "$PROGRAMFILES64\REDTRACE" allowed_install
  MessageBox MB_ICONSTOP "Install REDTRACE in Program Files\REDTRACE to enable protected audit operations."
  Abort
  allowed_install:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner *S-1-5-32-544 /T /C'
  Pop $0
  Pop $1
  StrCmp $0 "0" +3
  MessageBox MB_ICONSTOP "REDTRACE installation ownership could not be secured."
  Abort
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$INSTDIR" /reset'
  Pop $0
  Pop $1
  StrCmp $0 "0" +3
  MessageBox MB_ICONSTOP "REDTRACE installation permissions could not be reset."
  Abort
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"'
  Pop $0
  Pop $1
  StrCmp $0 "0" +3
  MessageBox MB_ICONSTOP "REDTRACE installation directory is not protected."
  Abort
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$INSTDIR\*" /reset /T /C'
  Pop $0
  Pop $1
  StrCmp $0 "0" +3
  MessageBox MB_ICONSTOP "REDTRACE installed files could not inherit protected permissions."
  Abort
!macroend
