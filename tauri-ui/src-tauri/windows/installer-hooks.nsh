Var FairyPamInstallDir
Var FairyPamInstallHandle
Var FairyPamBootstrapDir
Var FairyPamBootstrapPayloadDir

!define FAIRYPAM_INSTALL_DIRECTORY "FairyPam"
!define FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY ".fairypam-installer"
; Windows normalizes GRGX on a file-system object to FILE_GENERIC_READ |
; FILE_GENERIC_EXECUTE (0x1200a9). Use that canonical mask both when the
; protected root is created and when its DACL is verified.
!define FAIRYPAM_INSTALL_SDDL "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)S:(ML;OICI;NW;;;HI)"
!define FAIRYPAM_INSTALL_OWNER_SDDL "O:BA"
!define FAIRYPAM_INSTALL_DACL_SDDL "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
; Tauri 2.11 emits resource ancestors child-first. Older failed installers
; therefore left only this exact read/execute inherited DACL on intermediate
; directories created by the previous recursive directory API. It is accepted
; solely for one-way normalization to the protected DACL above.
!define FAIRYPAM_INSTALL_INHERITED_DACL_SDDL "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)"
!define FAIRYPAM_INSTALL_FILE_SDDL "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)S:(ML;;NW;;;HI)"
!define FAIRYPAM_INSTALL_FILE_DACL_SDDL "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
!define ERROR_ALREADY_EXISTS 183
!define ERROR_FILE_EXISTS 80
!define FAIRYPAM_INSTALL_SDDL_ERROR 65536
!define FAIRYPAM_INSTALL_SECURITY_ATTRIBUTES_ERROR 131072
!define FAIRYPAM_INSTALL_CREATE_DIRECTORY_ERROR 196608
!define FAIRYPAM_INSTALL_PIN_ERROR 262144
!define FAIRYPAM_INSTALL_VERIFY_ERROR 327680
!define FAIRYPAM_INSTALL_NOT_DIRECTORY_ERROR 393216
!define FAIRYPAM_INSTALL_REPARSE_ERROR 458752
!define FAIRYPAM_INSTALL_VALIDATION_ERROR 524288
!define FAIRYPAM_INSTALL_RELEASE_ERROR 589824
!define FAIRYPAM_INSTALL_DETAIL_FILE_CREATE 0x1000
!define FAIRYPAM_INSTALL_DETAIL_FILE_ATTRIBUTES 0x2000
!define FAIRYPAM_INSTALL_DETAIL_FILE_TYPE 0x3000
!define FAIRYPAM_INSTALL_DETAIL_OWNER 0x4000
!define FAIRYPAM_INSTALL_DETAIL_DACL 0x5000
!define FAIRYPAM_INSTALL_OPEN_FLAGS 0x02200000 ; FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
!define FAIRYPAM_INSTALL_OWNER_SECURITY_INFORMATION 0x00000001
!define FAIRYPAM_INSTALL_DACL_SECURITY_INFORMATION 0x00000004
!define FAIRYPAM_INSTALL_PROTECTED_DACL_SECURITY_INFORMATION 0x80000004
!define FAIRYPAM_INSTALL_SECURITY_INFORMATION 0x00000005 ; owner + DACL; protection is encoded in D: P

!macro FAIRYPAM_SET_INSTALL_ERROR stage_base detail
  IntOp $R4 ${detail} & 0xFFFF
  ${If} $R4 = 0
    StrCpy $R4 1
  ${EndIf}
  IntOp $R4 $R4 + ${stage_base}
  SetErrorLevel $R4
!macroend

!macro FAIRYPAM_VERIFY_PROTECTED_OBJECT object failure_label
  ; A pre-existing root is safe to update only when it was created with the
  ; product's protected owner/DACL. Verify this before NSIS writes or executes
  ; anything inside it; a root with a user-writable DACL may contain junctions.
  System::Call 'advapi32::GetNamedSecurityInfoW(w "${object}", i 1, i ${FAIRYPAM_INSTALL_SECURITY_INFORMATION}, p 0, p 0, p 0, p 0, *p .R7) i.R9'
  ${If} $R9 != 0
    StrCpy $R5 $R9
    Goto ${failure_label}
  ${EndIf}
  ; Convert and compare each component independently. The Win32 conversion
  ; returns an API-owned UTF-16 pointer; compare it in place so verification
  ; does not depend on NSIS string-buffer marshaling.
  System::Call 'advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW(p R7, i 1, i ${FAIRYPAM_INSTALL_OWNER_SECURITY_INFORMATION}, *p .R8, p 0) i.R9 ?e'
  Pop $R5
  ${If} $R9 = 0
    System::Call 'kernel32::LocalFree(p R7)'
    Goto ${failure_label}
  ${EndIf}
  System::Call 'kernel32::lstrcmpW(p R8, w "${FAIRYPAM_INSTALL_OWNER_SDDL}") i.R9'
  System::Call 'kernel32::LocalFree(p R8)'
  ${If} $R9 != 0
    StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_OWNER}
    IntOp $R5 $R5 | 1
    System::Call 'kernel32::LocalFree(p R7)'
    Goto ${failure_label}
  ${EndIf}

  System::Call 'advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW(p R7, i 1, i ${FAIRYPAM_INSTALL_DACL_SECURITY_INFORMATION}, *p .R8, p 0) i.R9 ?e'
  Pop $R5
  ${If} $R9 = 0
    System::Call 'kernel32::LocalFree(p R7)'
    Goto ${failure_label}
  ${EndIf}
  System::Call 'kernel32::lstrcmpW(p R8, w R4) i.R9'
  ${If} $R9 != 0
    ; R3 is empty for roots/files. Directory callers may provide only the
    ; single inherited form produced by the previous broken creation order.
    ${If} $R3 == ""
      System::Call 'kernel32::LocalFree(p R8)'
      StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_DACL}
      IntOp $R5 $R5 | 1
      System::Call 'kernel32::LocalFree(p R7)'
      Goto ${failure_label}
    ${EndIf}
    System::Call 'kernel32::lstrcmpW(p R8, w R3) i.R9'
    System::Call 'kernel32::LocalFree(p R8)'
    ${If} $R9 != 0
      StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_DACL}
      IntOp $R5 $R5 | 1
      System::Call 'kernel32::LocalFree(p R7)'
      Goto ${failure_label}
    ${EndIf}

    ; The inherited descriptor has the exact trusted ACE set and no untrusted
    ; write right. Make it protected before any payload file is written.
    System::Call 'kernel32::LocalFree(p R7)'
    System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w R4, i 1, *p .R8, p 0) i.R9 ?e'
    Pop $R5
    ${If} $R9 = 0
      Goto ${failure_label}
    ${EndIf}
    System::Call 'advapi32::GetSecurityDescriptorDacl(p R8, *i .R9, *p .R0, *i .R1) i.R2'
    ${If} $R2 = 0
      System::Call 'kernel32::LocalFree(p R8)'
      StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_DACL}
      IntOp $R5 $R5 | 2
      Goto ${failure_label}
    ${EndIf}
    System::Call 'advapi32::SetNamedSecurityInfoW(w "${object}", i 1, i ${FAIRYPAM_INSTALL_PROTECTED_DACL_SECURITY_INFORMATION}, p 0, p 0, p R0, p 0) i.R9'
    System::Call 'kernel32::LocalFree(p R8)'
    ${If} $R9 != 0
      StrCpy $R5 $R9
      Goto ${failure_label}
    ${EndIf}

    ; Re-read after normalization. A successful setter call alone is not the
    ; verification boundary.
    System::Call 'advapi32::GetNamedSecurityInfoW(w "${object}", i 1, i ${FAIRYPAM_INSTALL_DACL_SECURITY_INFORMATION}, p 0, p 0, p 0, p 0, *p .R7) i.R9'
    ${If} $R9 != 0
      StrCpy $R5 $R9
      Goto ${failure_label}
    ${EndIf}
    System::Call 'advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW(p R7, i 1, i ${FAIRYPAM_INSTALL_DACL_SECURITY_INFORMATION}, *p .R8, p 0) i.R9 ?e'
    Pop $R5
    ${If} $R9 = 0
      System::Call 'kernel32::LocalFree(p R7)'
      Goto ${failure_label}
    ${EndIf}
    System::Call 'kernel32::lstrcmpW(p R8, w R4) i.R9'
    System::Call 'kernel32::LocalFree(p R8)'
    System::Call 'kernel32::LocalFree(p R7)'
    ${If} $R9 != 0
      StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_DACL}
      IntOp $R5 $R5 | 3
      Goto ${failure_label}
    ${EndIf}
  ${Else}
    System::Call 'kernel32::LocalFree(p R8)'
    System::Call 'kernel32::LocalFree(p R7)'
  ${EndIf}
!macroend

!macro FAIRYPAM_VERIFY_PROTECTED_DIRECTORY_PATH directory failure_label
  System::Call 'kernel32::GetFileAttributesW(w "${directory}") i.R9 ?e'
  Pop $R5
  IntCmp $R9 -1 ${failure_label}
  IntOp $R8 $R9 & 0x10 ; FILE_ATTRIBUTE_DIRECTORY
  ${If} $R8 = 0
    Goto ${failure_label}
  ${EndIf}
  IntOp $R8 $R9 & 0x400 ; FILE_ATTRIBUTE_REPARSE_POINT
  ${If} $R8 != 0
    Goto ${failure_label}
  ${EndIf}
  StrCpy $R4 "${FAIRYPAM_INSTALL_DACL_SDDL}"
  !insertmacro FAIRYPAM_VERIFY_PROTECTED_OBJECT "${directory}" ${failure_label}
!macroend

!macro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_DIRECTORY directory failure_label
  ; The bootstrap is created with the same explicit descriptor as the product
  ; root. On a later install, check it before any executable is copied there.
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${FAIRYPAM_INSTALL_SDDL}", i 1, *p .R8, p 0) i.R9 ?e'
  Pop $R5
  ${If} $R9 = 0
    Goto ${failure_label}
  ${EndIf}
  System::Call '*(i 12, p R8, i 0) p.R7 ?e'
  Pop $R5
  ${If} $R7 = 0
    System::Call 'kernel32::LocalFree(p R8)'
    Goto ${failure_label}
  ${EndIf}
  ; Never recurse here: a recursive API can create intermediate directories
  ; with inherited security. Missing parents now fail closed.
  System::Call 'kernel32::CreateDirectoryW(w "${directory}", p R7) i.R9 ?e'
  Pop $R5
  System::Free $R7
  System::Call 'kernel32::LocalFree(p R8)'
  ${If} $R9 = 0
    ${If} $R5 != ${ERROR_ALREADY_EXISTS}
      ${If} $R5 != ${ERROR_FILE_EXISTS}
        Goto ${failure_label}
      ${EndIf}
    ${EndIf}
  ${EndIf}
  StrCpy $R3 "${FAIRYPAM_INSTALL_INHERITED_DACL_SDDL}"
  !insertmacro FAIRYPAM_VERIFY_PROTECTED_DIRECTORY_PATH "${directory}" ${failure_label}
!macroend

!macro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_FILE file failure_label
  ; Establish owner and DACL before File/WriteUninstaller overwrites an
  ; existing leaf. Without this, a user-owned read-only-looking file can later
  ; restore its own write permission between extraction and ExecWait.
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${FAIRYPAM_INSTALL_FILE_SDDL}", i 1, *p .R8, p 0) i.R9 ?e'
  Pop $R5
  ${If} $R9 = 0
    Goto ${failure_label}
  ${EndIf}
  System::Call '*(i 12, p R8, i 0) p.R7 ?e'
  Pop $R5
  ${If} $R7 = 0
    System::Call 'kernel32::LocalFree(p R8)'
    Goto ${failure_label}
  ${EndIf}
  System::Call 'kernel32::CreateFileW(w "${file}", i 0x40000000, i 0, p R7, i 1, i 0x00200000, p 0) p.R0 ?e'
  Pop $R5
  System::Free $R7
  System::Call 'kernel32::LocalFree(p R8)'
  ${If} $R0 = -1
    ${If} $R5 != ${ERROR_FILE_EXISTS}
      IntOp $R5 $R5 & 0x0FFF
      IntOp $R5 $R5 | ${FAIRYPAM_INSTALL_DETAIL_FILE_CREATE}
      Goto ${failure_label}
    ${EndIf}
  ${Else}
    System::Call 'kernel32::CloseHandle(p R0)'
  ${EndIf}
  System::Call 'kernel32::GetFileAttributesW(w "${file}") i.R9 ?e'
  Pop $R5
  ${If} $R9 = -1
    IntOp $R5 $R5 & 0x0FFF
    IntOp $R5 $R5 | ${FAIRYPAM_INSTALL_DETAIL_FILE_ATTRIBUTES}
    Goto ${failure_label}
  ${EndIf}
  IntOp $R8 $R9 & 0x10 ; FILE_ATTRIBUTE_DIRECTORY
  ${If} $R8 != 0
    StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_FILE_TYPE}
    IntOp $R5 $R5 | 1
    Goto ${failure_label}
  ${EndIf}
  IntOp $R8 $R9 & 0x400 ; FILE_ATTRIBUTE_REPARSE_POINT
  ${If} $R8 != 0
    StrCpy $R5 ${FAIRYPAM_INSTALL_DETAIL_FILE_TYPE}
    IntOp $R5 $R5 | 2
    Goto ${failure_label}
  ${EndIf}
  StrCpy $R4 "${FAIRYPAM_INSTALL_FILE_DACL_SDDL}"
  StrCpy $R3 ""
  !insertmacro FAIRYPAM_VERIFY_PROTECTED_OBJECT "${file}" ${failure_label}
!macroend

!macro NSIS_HOOK_PREINSTALL
  StrCpy $FairyPamInstallDir "${FAIRYPAM_INSTALL_ROOT}"
  StrCpy $FairyPamInstallHandle 0
  IfFileExists "$FairyPamInstallDir" fairypam_open_existing_install 0

  ; First install creates the only product directory with its final ACL before
  ; any payload is extracted. Reinstallations overwrite the same fixed files.
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${FAIRYPAM_INSTALL_SDDL}", i 1, *p .R8, p 0) i.R9 ?e'
  Pop $R5
  ${If} $R9 = 0
    Goto fairypam_install_sddl_failed
  ${EndIf}
  System::Call '*(i 12, p R8, i 0) p.R7 ?e'
  Pop $R5
  ${If} $R7 = 0
    System::Call 'kernel32::LocalFree(p R8)'
    Goto fairypam_install_attributes_failed
  ${EndIf}
  System::Call 'kernel32::CreateDirectoryW(w "$FairyPamInstallDir", p R7) i.R9 ?e'
  Pop $R5
  System::Free $R7
  System::Call 'kernel32::LocalFree(p R8)'
  ${If} $R9 = 0
    ${If} $R5 = ${ERROR_ALREADY_EXISTS}
      Goto fairypam_open_existing_install
    ${EndIf}
    Goto fairypam_install_create_failed
  ${EndIf}

fairypam_open_existing_install:
  ; Pin and inspect the exact fixed root. There is intentionally no recursive
  ; cleanup: the installer overwrites only declared payload files.
  System::Call 'kernel32::CreateFileW(w "$FairyPamInstallDir", i 0x80, i 3, p 0, i 3, i ${FAIRYPAM_INSTALL_OPEN_FLAGS}, p 0) p.R6 ?e'
  Pop $R5
  IntCmp $R6 -1 fairypam_install_pin_failed
  System::Call 'kernel32::GetFileAttributesW(w "$FairyPamInstallDir") i.R9 ?e'
  Pop $R5
  IntCmp $R9 -1 fairypam_install_verify_failed
  IntOp $R8 $R9 & 0x10 ; FILE_ATTRIBUTE_DIRECTORY
  ${If} $R8 = 0
    Goto fairypam_install_not_directory
  ${EndIf}
  IntOp $R8 $R9 & 0x400 ; FILE_ATTRIBUTE_REPARSE_POINT
  ${If} $R8 != 0
    Goto fairypam_install_reparse_detected
  ${EndIf}
  StrCpy $R4 "${FAIRYPAM_INSTALL_DACL_SDDL}"
  StrCpy $R3 ""
  !insertmacro FAIRYPAM_VERIFY_PROTECTED_OBJECT "$FairyPamInstallDir" fairypam_install_untrusted_security
  StrCpy $FairyPamBootstrapDir "$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}"
  StrCpy $FairyPamBootstrapPayloadDir "$FairyPamBootstrapDir\payload"
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_DIRECTORY "$FairyPamBootstrapDir" fairypam_install_untrusted_security
  !insertmacro FAIRYPAM_CREATE_OR_VERIFY_PROTECTED_DIRECTORY "$FairyPamBootstrapPayloadDir" fairypam_install_untrusted_security
  StrCpy $FairyPamInstallHandle $R6
  StrCpy $INSTDIR "$FairyPamInstallDir"
  SetOutPath $INSTDIR
!macroend

!macro NSIS_HOOK_PREPAYLOAD
  ; This verifier was copied into the protected bootstrap subtree before any
  ; existing product payload is touched. It refuses reparse points and
  ; user-writable entries throughout the current tree before replacement.
  ExecWait '"$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime\fairypam-agent-installer.exe" --preflight "$FairyPamInstallDir"' $0
  IfErrors fairypam_install_validation_failed 0
  ${If} $0 != 0
    StrCpy $R3 $0
    Goto fairypam_install_helper_failed
  ${EndIf}
  ExecWait '"$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime\fairypam-agent-installer.exe" --prepare-install "$FairyPamInstallDir"' $0
  IfErrors fairypam_install_validation_failed 0
  ${If} $0 != 0
    StrCpy $R3 $0
    Goto fairypam_install_helper_failed
  ${EndIf}
  SetOutPath "$FairyPamInstallDir"
!macroend

!macro NSIS_HOOK_ACTIVATE
  IfFileExists "$FairyPamInstallDir\resources\runtime\fairypam-agent-installer.exe" 0 fairypam_install_validation_failed
  IfFileExists "$FairyPamInstallDir\fairypam-agent.exe" 0 fairypam_install_validation_failed
  IfFileExists "$FairyPamInstallDir\fairypam-agent-guardian.exe" 0 fairypam_install_validation_failed
  IfFileExists "$FairyPamInstallDir\profiles\*.*" 0 fairypam_install_validation_failed
  IfFileExists "$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime\fairypam-agent-installer.exe" 0 fairypam_install_validation_failed
  ExecWait '"$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\payload\resources\runtime\fairypam-agent-installer.exe" --provision "$FairyPamInstallDir"' $0
  IfErrors fairypam_install_validation_failed 0
  ${If} $0 != 0
    StrCpy $R3 $0
    Goto fairypam_install_helper_failed
  ${EndIf}
  IfFileExists "$FairyPamInstallDir\current.json" 0 fairypam_install_validation_failed
  IfFileExists "$FairyPamInstallDir\versions\*.*" 0 fairypam_install_validation_failed
  RMDir /r "$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}"
  IfFileExists "$FairyPamInstallDir\${FAIRYPAM_INSTALL_BOOTSTRAP_DIRECTORY}\*.*" fairypam_install_validation_failed 0

  ; Leave the product directory before releasing its pinned handle. The final
  ; versioned layout and current pointer are already active.
  SetOutPath "$PROGRAMFILES64"
  StrCpy $R6 $FairyPamInstallHandle
  System::Call 'kernel32::CloseHandle(p R6) i.R9 ?e'
  Pop $R5
  ${If} $R9 = 0
    !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_RELEASE_ERROR} $R5
    Abort "FairyPam could not release its protected installation directory (Win32 error $R5)."
  ${EndIf}
  StrCpy $FairyPamInstallHandle 0
  StrCpy $INSTDIR "$FairyPamInstallDir"
  SetOutPath $INSTDIR
  Goto fairypam_install_complete

fairypam_install_sddl_failed:
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_SDDL_ERROR} $R5
  Abort "FairyPam could not prepare security for its protected installation directory (Win32 error $R5)."
fairypam_install_attributes_failed:
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_SECURITY_ATTRIBUTES_ERROR} $R5
  Abort "FairyPam could not allocate security attributes for its protected installation directory (Win32 error $R5)."
fairypam_install_create_failed:
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_CREATE_DIRECTORY_ERROR} $R5
  Abort "FairyPam could not create its protected installation directory (Win32 error $R5)."
fairypam_install_pin_failed:
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_PIN_ERROR} $R5
  Abort "FairyPam could not pin its protected installation directory (Win32 error $R5)."
fairypam_install_verify_failed:
  System::Call 'kernel32::CloseHandle(p R6)'
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_VERIFY_ERROR} $R5
  Abort "FairyPam could not verify its protected installation directory (Win32 error $R5)."
fairypam_install_not_directory:
  System::Call 'kernel32::CloseHandle(p R6)'
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_NOT_DIRECTORY_ERROR} 1
  Abort "FairyPam rejected a non-directory protected installation path."
fairypam_install_reparse_detected:
  System::Call 'kernel32::CloseHandle(p R6)'
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_REPARSE_ERROR} 1
  Abort "FairyPam rejected a reparse point at its protected installation path."
fairypam_install_untrusted_security:
  System::Call 'kernel32::CloseHandle(p R6)'
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_VERIFY_ERROR} $R5
  Abort "FairyPam rejected an untrusted protected installation directory."
fairypam_install_validation_failed:
  ${If} $FairyPamInstallHandle != 0
    StrCpy $R6 $FairyPamInstallHandle
    System::Call 'kernel32::CloseHandle(p R6)'
    StrCpy $FairyPamInstallHandle 0
  ${EndIf}
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_VALIDATION_ERROR} 1
  Abort "FairyPam could not validate the installed Agent runtime."
fairypam_install_helper_failed:
  ${If} $FairyPamInstallHandle != 0
    StrCpy $R6 $FairyPamInstallHandle
    System::Call 'kernel32::CloseHandle(p R6)'
    StrCpy $FairyPamInstallHandle 0
  ${EndIf}
  !insertmacro FAIRYPAM_SET_INSTALL_ERROR ${FAIRYPAM_INSTALL_VALIDATION_ERROR} $R3
  Abort "FairyPam could not validate the installed Agent runtime."
fairypam_install_complete:
!macroend
