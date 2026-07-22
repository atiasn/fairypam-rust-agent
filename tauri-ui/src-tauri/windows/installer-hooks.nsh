Var FairyPamFinalDir
Var FairyPamStageDir
Var FairyPamBackupDir
Var FairyPamStageHandle

!define FAIRYPAM_INSTALL_SDDL "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
!define ERROR_ALREADY_EXISTS 183
!define FILE_FLAG_OPEN_REPARSE_POINT 0x00200000
!define FAIRYPAM_STAGE_OPEN_FLAGS 0x02200000 ; FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT

!macro NSIS_HOOK_PREINSTALL
  StrCpy $FairyPamFinalDir "${FIXED_INSTALL_DIR}"
  StrCpy $FairyPamStageDir "${FIXED_INSTALL_DIR}.installing"
  StrCpy $FairyPamBackupDir "${FIXED_INSTALL_DIR}.previous"
  StrCpy $FairyPamStageHandle 0
  IfFileExists "$FairyPamBackupDir" fairypam_stale_backup 0
  IfFileExists "$FairyPamStageDir" fairypam_stale_stage 0

  ; NSIS is 32-bit, so SECURITY_ATTRIBUTES is 12 bytes here.
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${FAIRYPAM_INSTALL_SDDL}", i 1, *p .r8, p 0) i.r9 ?e'
  Pop $R5
  ${If} $R9 = 0
    Goto fairypam_stage_sddl_failed
  ${EndIf}
  System::Call '*(i 12, p r8, i 0) p.r7 ?e'
  Pop $R5
  ${If} $R7 = 0
    System::Call 'kernel32::LocalFree(p r8)'
    Goto fairypam_stage_attributes_failed
  ${EndIf}

  System::Call 'kernel32::CreateDirectoryW(w "$FairyPamStageDir", p r7) i.r9 ?e'
  Pop $R5
  ${If} $R9 = 0
    System::Free $R7
    System::Call 'kernel32::LocalFree(p r8)'
    ${If} $R5 = ${ERROR_ALREADY_EXISTS}
      Goto fairypam_stale_stage
    ${EndIf}
    Goto fairypam_stage_create_failed
  ${EndIf}
  System::Free $R7
  System::Call 'kernel32::LocalFree(p r8)'

  ; No share-delete keeps the protected, non-reparse stage pinned through verification.
  System::Call 'kernel32::CreateFileW(w "$FairyPamStageDir", i 0x80, i 3, p 0, i 3, i ${FAIRYPAM_STAGE_OPEN_FLAGS}, p 0) p.r6 ?e'
  Pop $R5
  IntCmp $R6 -1 fairypam_stage_pin_failed
  System::Call 'kernel32::GetFileAttributesW(w "$FairyPamStageDir") i.r9 ?e'
  Pop $R5
  IntCmp $R9 -1 fairypam_stage_verify_failed
  IntOp $R8 $R9 & 0x10 ; FILE_ATTRIBUTE_DIRECTORY
  ${If} $R8 = 0
    Goto fairypam_stage_not_directory
  ${EndIf}
  IntOp $R8 $R9 & 0x400 ; FILE_ATTRIBUTE_REPARSE_POINT
  ${If} $R8 != 0
    Goto fairypam_stage_reparse_detected
  ${EndIf}
  StrCpy $FairyPamStageHandle $R6
  StrCpy $INSTDIR "$FairyPamStageDir"
  SetOutPath $INSTDIR
  Goto fairypam_stage_ready

fairypam_stale_backup:
  SetErrorLevel ${ERROR_ALREADY_EXISTS}
  Abort "FairyPam found a preserved previous installation. Installation was stopped without changing the active runtime."
fairypam_stale_stage:
  SetErrorLevel ${ERROR_ALREADY_EXISTS}
  Abort "FairyPam found an unverified staging directory. Installation was stopped without following or deleting it."
fairypam_stage_sddl_failed:
  ${If} $R5 = 0
    SetErrorLevel 1
  ${Else}
    SetErrorLevel $R5
  ${EndIf}
  Abort "FairyPam could not prepare security for its protected installation staging directory (Win32 error $R5)."
fairypam_stage_attributes_failed:
  ${If} $R5 = 0
    SetErrorLevel 1
  ${Else}
    SetErrorLevel $R5
  ${EndIf}
  Abort "FairyPam could not allocate security attributes for its protected installation staging directory (Win32 error $R5)."
fairypam_stage_create_failed:
  ${If} $R5 = 0
    SetErrorLevel 1
  ${Else}
    SetErrorLevel $R5
  ${EndIf}
  Abort "FairyPam could not create its protected installation staging directory (Win32 error $R5)."
fairypam_stage_pin_failed:
  ${If} $R5 = 0
    SetErrorLevel 1
  ${Else}
    SetErrorLevel $R5
  ${EndIf}
  Abort "FairyPam could not pin its protected installation staging directory (Win32 error $R5)."
fairypam_stage_verify_failed:
  System::Call 'kernel32::CloseHandle(p r6)'
  ${If} $R5 = 0
    SetErrorLevel 1
  ${Else}
    SetErrorLevel $R5
  ${EndIf}
  Abort "FairyPam could not verify its protected installation staging directory (Win32 error $R5)."
fairypam_stage_not_directory:
  System::Call 'kernel32::CloseHandle(p r6)'
  SetErrorLevel 1
  Abort "FairyPam rejected a non-directory protected installation staging path."
fairypam_stage_reparse_detected:
  System::Call 'kernel32::CloseHandle(p r6)'
  SetErrorLevel 1
  Abort "FairyPam rejected a reparse point at its protected installation staging directory."
fairypam_stage_ready:
!macroend

!macro NSIS_HOOK_ACTIVATE
  IfFileExists "$FairyPamStageDir\resources\runtime\fairypam-agent-installer.exe" 0 fairypam_stage_failed
  ExecWait '"$FairyPamStageDir\resources\runtime\fairypam-agent-installer.exe" "$FairyPamStageDir" "$FairyPamFinalDir"' $0
  IfErrors fairypam_stage_failed 0
  ${If} $0 != 0
    Goto fairypam_stage_failed
  ${EndIf}
  IfFileExists "$FairyPamStageDir\fairypam-agent.exe" 0 fairypam_stage_failed
  IfFileExists "$FairyPamStageDir\fairypam-agent-guardian.exe" 0 fairypam_stage_failed
  IfFileExists "$FairyPamStageDir\profiles\*.*" 0 fairypam_stage_failed

  System::Call 'kernel32::CloseHandle(p $FairyPamStageHandle) i.r9'
  StrCpy $FairyPamStageHandle 0
  ${If} $R9 = 0
    Goto fairypam_stage_failed
  ${EndIf}
  IfFileExists "$FairyPamFinalDir" 0 fairypam_activate_fresh
  ClearErrors
  Rename "$FairyPamFinalDir" "$FairyPamBackupDir"
  IfErrors fairypam_activate_failed 0
  ClearErrors
  Rename "$FairyPamStageDir" "$FairyPamFinalDir"
  IfErrors fairypam_restore_previous 0
  Goto fairypam_activate_complete

fairypam_activate_fresh:
  ClearErrors
  Rename "$FairyPamStageDir" "$FairyPamFinalDir"
  IfErrors fairypam_activate_failed 0
fairypam_activate_complete:
  StrCpy $INSTDIR "$FairyPamFinalDir"
  SetOutPath $INSTDIR
  ClearErrors
  RMDir /r "$FairyPamBackupDir"
  IfErrors fairypam_backup_cleanup_failed 0
  IfFileExists "$FairyPamBackupDir" fairypam_backup_cleanup_failed 0
  Goto fairypam_install_complete
fairypam_restore_previous:
  ClearErrors
  Rename "$FairyPamBackupDir" "$FairyPamFinalDir"
  IfErrors fairypam_rollback_failed 0
fairypam_activate_failed:
  ClearErrors
  RMDir /r "$FairyPamStageDir"
  SetErrorLevel 1
  Abort "FairyPam could not activate the staged runtime. The previous installation remains active."
fairypam_stage_failed:
  ${If} $FairyPamStageHandle != 0
    System::Call 'kernel32::CloseHandle(p $FairyPamStageHandle)'
    StrCpy $FairyPamStageHandle 0
  ${EndIf}
  ClearErrors
  RMDir /r "$FairyPamStageDir"
  SetErrorLevel 1
  Abort "FairyPam could not validate the staged Agent runtime. The active installation was not changed."
fairypam_rollback_failed:
  SetErrorLevel 1
  Abort "FairyPam could not restore the preserved installation. The previous slot remains at the .previous path for recovery."
fairypam_backup_cleanup_failed:
  SetErrorLevel 1
  Abort "FairyPam could not remove the preserved previous installation. Installation was stopped without reporting success."
fairypam_install_complete:
!macroend
